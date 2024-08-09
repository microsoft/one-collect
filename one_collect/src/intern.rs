use std::hash::{Hash, Hasher};
use twox_hash::XxHash64;

/// `InternedSpan` represents a span of interned data in memory.
///
/// This struct is used to keep track of the start and end indices of interned data,
/// effectively representing a slice of the data without owning it.
#[derive(Default, Clone, Copy, PartialEq)]
pub struct InternedSpan {
    start: usize,
    end: usize,
}

impl InternedSpan {
    /// Returns the length of the interned span.
    ///
    /// This is calculated as the difference between the end and start indices.
    ///
    /// # Returns
    /// * `usize`: The length of the interned span.
    pub fn len(&self) -> usize {
        self.end - self.start
    }
}

struct InternedBucket {
    hash: u64,
    len: usize,
    index: usize,
}

/// `InternedSlices` represents a collection of interned slices of type `T`.
///
/// Interning is a method of storing only one copy of each distinct slice value, which must be immutable.
/// This struct is used to keep track of all the interned slices, their individual spans,
/// and a hash map for quick access to these slices.
pub struct InternedSlices<T> {
    buckets: Vec<Vec<InternedBucket>>,
    mask: u64,
    slices: Vec<T>,
    spans: Vec<InternedSpan>,
}

impl<T: Copy + std::cmp::Eq + std::hash::Hash> InternedSlices<T> {
    /// Creates a new collection of interned slices.
    ///
    /// # Parameters
    /// * `bucket_count`: The initial capacity of the hash map in number of buckets.
    ///
    /// # Returns
    /// * `Self`: A new `InternedSlices` instance.
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

    /// Interns a slice and returns its ID.
    ///
    /// # Parameters
    /// * `slice`: The slice of type `T` to be interned.
    ///
    /// # Returns
    /// * `usize`: The ID (index) of the interned slice.
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

    /// Returns the slice corresponding to the given ID returned by to_id().
    ///
    /// # Parameters
    /// * `id`: The ID (index) of the interned slice to retrieve.
    ///
    /// # Returns
    /// * `Option<&[T]>`: The interned slice if found, or `None` otherwise.
    pub fn from_id(
        &self,
        id: usize) -> Option<&[T]> {
        if id < self.spans.len() {
            let span = &self.spans[id];
            return Some(&self.slices[span.start..span.end]);
        }

        None
    }

    /// Executes a function for each interned slice.
    ///
    /// # Parameters
    /// * `f`: A closure that takes an index and a slice, and returns nothing. This closure is executed for each interned slice.
    pub fn for_each(
        &self,
        mut f: impl FnMut(usize, &[T])) {
        for (i, span) in self.spans.iter().enumerate() {
            f(i, &self.slices[span.start..span.end]);
        }
    }
}

/// `InternedCallstacks` represents a collection of interned call stacks.
///
/// Each call stack is a sequence of frame addresses, and this struct provides methods
/// to intern these call stacks and retrieve them by ID.
///
/// Interning is a method of storing only one copy of each distinct call stack,
/// which must be immutable. This helps in efficient memory utilization and faster comparisons.
pub struct InternedCallstacks {
    frames: InternedSlices<u64>,
}

impl InternedCallstacks {
    /// Creates a new collection of interned call stacks.
    ///
    /// # Parameters
    /// * `bucket_count`: The initial capacity of the hash map in number of buckets.
    ///
    /// # Returns
    /// * `Self`: A new `InternedCallstacks` instance.
    pub fn new(bucket_count: usize) -> Self {
        Self {
            frames: InternedSlices::new(bucket_count),
        }
    }

    /// Interns a call stack and returns its ID.
    ///
    /// # Parameters
    /// * `frames`: The call stack to be interned, represented as a slice of frame addresses.
    ///
    /// # Returns
    /// * `usize`: The ID (index) of the interned call stack.
    pub fn to_id(
        &mut self,
        frames: &[u64]) -> usize {
        self.frames.to_id(frames)
    }

    /// Retrieves a call stack by its ID returned by to_id().
    ///
    /// # Parameters
    /// * `id`: The ID (index) of the interned call stack to retrieve.
    /// * `frames`: A mutable reference to a `Vec<u64>` where the retrieved call stack will be stored.
    ///
    /// # Returns
    /// * `anyhow::Result<()>`: `Ok(())` if the call stack was successfully retrieved, or an `Err` with a description of what went wrong.
    pub fn from_id(
        &self,
        id: usize,
        frames: &mut Vec<u64>) -> anyhow::Result<()> {
        frames.clear();

        if let Some(found) = self.frames.from_id(id) {
            for frame in found {
                frames.push(*frame);
            }
        } else {
            return Err(anyhow::Error::msg("ID not found."));
        }

        Ok(())
    }

    /// Executes a function for each interned call stack.
    ///
    /// # Parameters
    /// * `f`: A closure that takes an index and a call stack (slice of frame addresses), and returns nothing.
    ///         This closure is executed for each interned call stack.
    ///
    /// # Example
    /// ```
    /// use one_collect::intern::InternedCallstacks;
    ///
    /// let mut interned_callstacks = InternedCallstacks::new(16);
    /// interned_callstacks.to_id(&[0x12345678, 0x9abcdef0]);
    /// interned_callstacks.to_id(&[0xdeadbeef, 0xcafebabe]);
    /// interned_callstacks.for_each(|id, callstack| {
    ///     println!("ID: {}, Callstack: {:?}", id, callstack);
    /// });
    /// ```
    /// The above example will print:
    /// ID: 0, Callstack: [305419896, 2638827904]
    /// ID: 1, Callstack: [3735928559, 3405691582]
    pub fn for_each(
        &self,
        f: impl FnMut(usize, &[u64])) {
        self.frames.for_each(f);
    }
}

/// `InternedStrings` represents a collection of interned strings.
///
/// Each string is converted to bytes and interned as a slice of bytes.
/// This struct provides methods to intern these strings and retrieve them by ID.
///
/// Interning is a method of storing only one copy of each distinct string,
/// which must be immutable. This helps in efficient memory utilization and faster comparisons.
pub struct InternedStrings {
    strings: InternedSlices<u8>,
}

impl InternedStrings {
    /// Creates a new collection of interned strings.
    ///
    /// # Parameters
    /// * `bucket_count`: The initial capacity of the hash map in number of buckets.
    ///     In general the more buckets the faster the query performance will be.
    ///
    /// # Returns
    /// * `Self`: A new `InternedStrings` instance.
    pub fn new(bucket_count: usize) -> Self {
        Self {
            strings: InternedSlices::new(bucket_count),
        }
    }

    /// Interns a string and returns its ID.
    ///
    /// # Parameters
    /// * `string`: The string to be interned.
    ///
    /// # Returns
    /// * `usize`: The ID (index) of the interned string.
    pub fn to_id(
        &mut self,
        string: &str) -> usize {
        self.strings.to_id(string.as_bytes())
    }

    /// Returns the string corresponding to the given ID returned by to_id().
    ///
    /// # Parameters
    /// * `id`: The ID (index) of the interned string to retrieve.
    ///
    /// # Returns
    /// * `anyhow::Result<&str>`: The interned string if found, or an `Err` with a description of what went wrong.
    pub fn from_id(
        &self,
        id: usize) -> anyhow::Result<&str> {
        if let Some(bytes) = self.strings.from_id(id) {
            /* Safety: Bytes are pre-checked during adds */
            unsafe {
                Ok(std::str::from_utf8_unchecked(bytes))
            }
        } else {
            Err(anyhow::Error::msg("ID not found."))
        }
    }

    /// Executes a function for each interned string.
    ///
    /// # Parameters
    /// * `f`: A closure that takes an index and a string, and returns nothing.
    ///         This closure is executed for each interned string.
    ///
    /// # Example
    /// ```
    /// use one_collect::intern::InternedStrings;
    ///
    /// let mut interned_strings = InternedStrings::new(16);
    /// interned_strings.to_id("hello");
    /// interned_strings.to_id("world");
    /// interned_strings.for_each(|id, string| {
    ///     println!("ID: {}, String: {}", id, string);
    /// });
    /// ```
    /// The above example will print:
    /// ID: 0, String: hello
    /// ID: 1, String: world
    pub fn for_each(
        &self,
        mut f: impl FnMut(usize, &str)) {
        self.strings.for_each(|id,bytes| {
            /* Safety: Bytes are pre-checked during adds */
            unsafe {
                f(id, std::str::from_utf8_unchecked(bytes));
            }
        });
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

        let mut count = 0;

        strings.for_each(|_i, _string| {
            count += 1;
        });

        assert_eq!(2, count);
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

        let mut count = 0;

        callstacks.for_each(|_i, _calstack| {
            count += 1;
        });

        assert_eq!(2, count);
    }
}
