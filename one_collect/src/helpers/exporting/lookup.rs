// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::HashMap;

pub(crate) struct AddressLookupItem {
    address: u64,
    index: u32,
    valid: bool,
}

impl AddressLookupItem {
    pub(crate) fn new(
        address: u64,
        index: u32,
        valid: bool) -> Self {
        Self {
            address,
            index,
            valid,
        }
    }
}

#[derive(Default)]
pub(crate) struct AddressLookup {
    lookup: Vec<AddressLookupNode>,
    index: Vec<u32>,
}

struct AddressInterval {
    start: u64,
    end: u64,
    index: u32,
}

struct AddressLookupNode {
    center: u64,
    by_start: Vec<(u64, u32)>,
    by_end: Vec<(u64, u32)>,
    left: Option<usize>,
    right: Option<usize>,
}

impl AddressLookup {
    pub(crate) fn is_empty(&self) -> bool { self.lookup.is_empty() }

    pub(crate) fn clear(&mut self) {
        self.lookup.clear();
        self.index.clear();
    }

    pub(crate) fn find(
        &mut self,
        address: u64) -> &[u32] {
        self.index.clear();
        let mut next = if self.lookup.is_empty() { None } else { Some(0) };
        while let Some(node_index) = next {
            let node = &self.lookup[node_index];
            if address <= node.center {
                for &(start, index) in &node.by_start {
                    if start > address { break; }
                    self.index.push(index);
                }
                next = node.left;
            } else {
                for &(end, index) in &node.by_end {
                    if end < address { break; }
                    self.index.push(index);
                }
                next = node.right;
            }
        }
        &self.index
    }

    pub(crate) fn update(
        &mut self,
        items: &mut Vec<AddressLookupItem>) {
        self.clear();
        items.sort_by(|a,b| a.address.cmp(&b.address));

        let mut active = HashMap::new();
        let mut intervals = Vec::new();
        for item in items.iter() {
            if item.valid {
                active.entry(item.index).or_insert(item.address);
            } else if let Some(start) = active.remove(&item.index) {
                if start < item.address {
                    intervals.push(AddressInterval {
                        start,
                        end: item.address - 1,
                        index: item.index,
                    });
                }
            }
        }
        for (index, start) in active {
            intervals.push(AddressInterval { start, end: u64::MAX, index });
        }

        intervals.sort_by_key(|interval| interval.start);
        self.build_node(intervals);
    }

    // Intervals arrive sorted by start; the median start balances the tree.
    // Each interval belongs to one node, with lists sorted by start and end.
    fn build_node(&mut self, intervals: Vec<AddressInterval>) -> Option<usize> {
        if intervals.is_empty() {
            return None;
        }
        let center = intervals[intervals.len() / 2].start;
        let mut left = Vec::new();
        let mut right = Vec::new();
        let mut by_start = Vec::new();
        let mut by_end = Vec::new();
        for interval in intervals {
            if interval.end < center {
                left.push(interval);
            } else if interval.start > center {
                right.push(interval);
            } else {
                by_start.push((interval.start, interval.index));
                by_end.push((interval.end, interval.index));
            }
        }
        by_end.sort_unstable_by(|a, b| b.0.cmp(&a.0));

        let index = self.lookup.len();
        self.lookup.push(AddressLookupNode {
            center, by_start, by_end, left: None, right: None,
        });
        let left = self.build_node(left);
        let right = self.build_node(right);
        self.lookup[index].left = left;
        self.lookup[index].right = right;
        Some(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::mappings::{ExportMapping, ExportMappingLookup};
    use crate::ruwind::UnwindType;

    #[test]
    fn reused_ranges_store_each_interval_once() {
        let mut items = vec![AddressLookupItem::new(0, 0, true)];
        for index in 1..=5000 {
            items.push(AddressLookupItem::new(100, index, true));
            items.push(AddressLookupItem::new(200, index, false));
        }
        items.push(AddressLookupItem::new(200, 5001, true));
        let mut lookup = AddressLookup::default();
        lookup.update(&mut items);

        assert_eq!(5002, lookup.lookup.iter().map(|node| node.by_start.len()).sum::<usize>());
        let mut inside = lookup.find(100).to_vec();
        inside.sort_unstable();
        assert_eq!((0..=5000).collect::<Vec<_>>(), inside);
        let mut after = lookup.find(200).to_vec();
        after.sort_unstable();
        assert_eq!(vec![0, 5001], after);
        assert_eq!(vec![0], lookup.find(99));
    }

    #[test]
    fn shared_start_distinct_ends_use_linear_storage() {
        const COUNT: u32 = 5000;
        let mut items = Vec::new();
        for index in 0..COUNT {
            items.push(AddressLookupItem::new(100, index, true));
            items.push(AddressLookupItem::new(101 + u64::from(index), index, false));
        }
        items.push(AddressLookupItem::new(u64::MAX - 1, COUNT, true));

        let mut lookup = AddressLookup::default();
        lookup.update(&mut items);
        assert_eq!(COUNT as usize + 1,
            lookup.lookup.iter().map(|node| node.by_start.len()).sum::<usize>());
        assert_eq!(COUNT as usize + 1,
            lookup.lookup.iter().map(|node| node.by_end.len()).sum::<usize>());
        assert!(lookup.lookup.len() <= COUNT as usize + 1);

        for address in [0, 99, 100, 101, 2600, 5099, 5100, u64::MAX - 2, u64::MAX - 1, u64::MAX] {
            let mut actual = lookup.find(address).to_vec();
            actual.sort_unstable();
            let mut expected = (0..COUNT)
                .filter(|&index| 100 <= address && address <= 100 + u64::from(index))
                .collect::<Vec<_>>();
            if address >= u64::MAX - 1 {
                expected.push(COUNT);
            }
            assert_eq!(expected, actual, "address {address}");
        }

        lookup.clear();
        assert!(lookup.is_empty());
        assert!(lookup.find(100).is_empty());
    }

    #[test]
    fn interval_tree_matches_ranges_and_boundary_updates() {
        let mut items = Vec::new();
        let mut ranges = Vec::new();
        for index in 0..300u32 {
            let start = u64::from((index * 47) % 181);
            let end = start + u64::from((index * 37) % 91);
            items.push(AddressLookupItem::new(start, index, true));
            items.push(AddressLookupItem::new(end + 1, index, false));
            ranges.push((start, end, index));
        }
        // The same index may be removed and re-added at the same boundary.
        items.extend([
            AddressLookupItem::new(10, 300, true),
            AddressLookupItem::new(20, 300, false),
            AddressLookupItem::new(20, 300, true),
            AddressLookupItem::new(30, 300, false),
            AddressLookupItem::new(10, 301, true),
            AddressLookupItem::new(20, 301, true),
            AddressLookupItem::new(20, 301, false),
            AddressLookupItem::new(20, 302, true),
            AddressLookupItem::new(20, 302, false),
        ]);
        ranges.push((10, 29, 300));
        ranges.push((10, 19, 301));
        let mut lookup = AddressLookup::default();
        lookup.update(&mut items);
        for address in 0..=275 {
            let mut actual = lookup.find(address).to_vec();
            actual.sort_unstable();
            let mut expected = ranges.iter()
                .filter(|&&(start, end, _)| start <= address && address <= end)
                .map(|&(_, _, index)| index)
                .collect::<Vec<_>>();
            expected.sort_unstable();
            assert_eq!(expected, actual, "address {address}");
        }
        assert!(lookup.find(u64::MAX).is_empty());
    }

    #[test]
    fn distinct_end_mappings_match_linear_time_and_filter_selection() {
        let mut lookup = ExportMappingLookup::default();
        for index in 0..5000usize {
            lookup.mappings_mut().push(ExportMapping::new(
                index as u64, 0, 100, 100 + index as u64, 0, false, index + 1,
                UnwindType::Prolog));
        }
        lookup.mappings_mut().push(ExportMapping::new(
            0, 0, u64::MAX - 1, u64::MAX, 0, false, 5001, UnwindType::Prolog));

        for address in [99, 100, 101, 2600, 5099, 5100, u64::MAX - 1, u64::MAX] {
            for time in [Some(0), Some(2500), Some(4999), None] {
                lookup.set_lookup_min_size(usize::MAX);
                let expected = lookup.find_index_where(address, time, |map| map.id() % 3 != 0);
                lookup.set_lookup_min_size(0);
                assert_eq!(expected, lookup.find_index_where(address, time, |map| map.id() % 3 != 0),
                    "address {address}, time {time:?}");
            }
        }
    }
}
