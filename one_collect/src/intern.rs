use std::hash::{Hash, Hasher};
use twox_hash::XxHash64;

#[derive(Default, Clone, Copy, PartialEq)]
pub struct InternedSpan {
    start: usize,
    end: usize,
}

impl InternedSpan {
    pub fn len(&self) -> usize {
        self.end - self.start
    }
}

struct InternedBucket {
    hash: u64,
    len: usize,
    index: usize,
}

pub struct InternedSlices<T> {
    buckets: Vec<Vec<InternedBucket>>,
    mask: u64,
    slices: Vec<T>,
    spans: Vec<InternedSpan>,
}

impl<T: Copy + std::cmp::Eq + std::hash::Hash> InternedSlices<T> {
    pub fn new(
        bucket_count: usize) -> Self {
        let mut bucket_count = bucket_count;

        if !bucket_count.is_power_of_two() {
            bucket_count = bucket_count.next_power_of_two();
        }

        let mut buckets: Vec<Vec<InternedBucket>> = Vec::new();

        for _ in 0..bucket_count {
            buckets.push(Vec::new());
        }

        Self {
            buckets,
            mask: (bucket_count - 1) as u64,
            slices: Vec::new(),
            spans: Vec::new(),
        }
    }

    pub fn to_id(
        &mut self,
        slice: &[T]) -> usize {
        let mut hasher = XxHash64::default();
        Hash::hash_slice(slice, &mut hasher);
        let hash = hasher.finish();

        let bucket_index = (hash & self.mask) as usize;
        let chain = &self.buckets[bucket_index];
        let len = slice.len();

        for bucket in chain {
            if bucket.hash == hash && bucket.len == len {
                let span = &self.spans[bucket.index];
                let items = &self.slices[span.start..span.end];
                if items == slice {
                    return bucket.index;
                }
            }
        }

        let start = self.slices.len();
        let span_index = self.spans.len();

        let span = InternedSpan {
            start,
            end: start + len,
        };

        self.spans.push(span);

        self.buckets[bucket_index].push(
            InternedBucket {
                hash,
                len,
                index: span_index,
            });

        for i in slice {
            self.slices.push(*i);
        }

        span_index
    }

    pub fn from_id(
        &self,
        id: usize) -> Option<&[T]> {
        if id <= self.spans.len() {
            let span = &self.spans[id];
            return Some(&self.slices[span.start..span.end]);
        }

        None
    }

    pub fn for_each(
        &self,
        mut f: impl FnMut(usize, &[T])) {
        for (i, span) in self.spans.iter().enumerate() {
            f(i, &self.slices[span.start..span.end]);
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq)]
pub struct CallstackId {
    ip: u64,
    id: usize,
}

impl CallstackId {
    pub fn ip(&self) -> u64 {
        self.ip
    }

    pub fn id(&self) -> usize {
        self.id
    }
}

pub struct InternedCallstacks {
    interned_frames: InternedSlices<u64>,
}

impl InternedCallstacks {
    pub fn new(bucket_count: usize) -> Self {
        Self {
            interned_frames: InternedSlices::new(bucket_count),
        }
    }

    pub fn to_id(
        &mut self,
        frames: &[u64]) -> CallstackId {
        CallstackId {
            ip: frames[0],
            id: self.interned_frames.to_id(&frames[1..]),
        }
    }

    pub fn from_id(
        &self,
        id: CallstackId,
        frames: &mut Vec<u64>) -> anyhow::Result<()> {
        frames.clear();
        frames.push(id.ip());

        if let Some(found) = self.interned_frames.from_id(id.id()) {
            for frame in found {
                frames.push(*frame);
            }
        } else {
            return Err(anyhow::Error::msg("ID not found."));
        }

        Ok(())
    }
}

pub struct InternedStrings {
    strings: InternedSlices<u8>,
}

impl InternedStrings {
    pub fn new(bucket_count: usize) -> Self {
        Self {
            strings: InternedSlices::new(bucket_count),
        }
    }

    pub fn to_id(
        &mut self,
        string: &str) -> usize {
        self.strings.to_id(string.as_bytes())
    }

    pub fn from_id(
        &self,
        id: usize) -> anyhow::Result<&str> {
        if let Some(bytes) = self.strings.from_id(id) {
            Ok(std::str::from_utf8(bytes)?)
        } else {
            Err(anyhow::Error::msg("ID not found."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices() {
        let mut slices: InternedSlices<u64> = InternedSlices::new(8);

        let id1 = slices.to_id(&[1, 2, 3]);
        let id2 = slices.to_id(&[3, 2, 1]);
        let id3 = slices.to_id(&[1, 2, 3]);
        let id4 = slices.to_id(&[3, 2, 1]);

        assert!(id1 != id2);
        assert!(id1 == id3);
        assert!(id2 == id4);

        assert!(slices.from_id(id1) == Some(&[1, 2, 3]));
        assert!(slices.from_id(id2) == Some(&[3, 2, 1]));
        assert!(slices.from_id(id3) == Some(&[1, 2, 3]));
        assert!(slices.from_id(id4) == Some(&[3, 2, 1]));

        let mut current_index: usize = 0;

        slices.for_each(|index,span| {
            assert_eq!(current_index, index);
            current_index += 1;

            if index == 0 {
                assert!(span == &[1, 2, 3]);
            } else if index == 1 {
                assert!(span == &[3, 2, 1]);
            } else {
                /* Too many items */
                assert!(false);
            }
        });

        assert_eq!(2, current_index);
    }

    #[test]
    fn strings() {
        let mut strings = InternedStrings::new(8);

        let id1 = strings.to_id("1 2 3");
        let id2 = strings.to_id("3 2 1");
        let id3 = strings.to_id("1 2 3");
        let id4 = strings.to_id("3 2 1");

        assert!(id1 != id2);
        assert!(id1 == id3);
        assert!(id2 == id4);

        assert!(strings.from_id(id1).unwrap() == "1 2 3");
        assert!(strings.from_id(id2).unwrap() == "3 2 1");
        assert!(strings.from_id(id3).unwrap() == "1 2 3");
        assert!(strings.from_id(id4).unwrap() == "3 2 1");
    }

    #[test]
    fn callstacks() {
        let mut callstacks = InternedCallstacks::new(8);

        let id1 = callstacks.to_id(&[1, 2, 3]);
        let id2 = callstacks.to_id(&[3, 2, 1]);
        let id3 = callstacks.to_id(&[1, 2, 3]);
        let id4 = callstacks.to_id(&[3, 2, 1]);

        assert!(id1 != id2);
        assert!(id1 == id3);
        assert!(id2 == id4);

        let mut frames: Vec<u64> = Vec::new();
        callstacks.from_id(id1, &mut frames).unwrap();
        assert!(frames == &[1, 2, 3]);
        callstacks.from_id(id2, &mut frames).unwrap();
        assert!(frames == &[3, 2, 1]);
        callstacks.from_id(id3, &mut frames).unwrap();
        assert!(frames == &[1, 2, 3]);
        callstacks.from_id(id4, &mut frames).unwrap();
        assert!(frames == &[3, 2, 1]);
    }
}
