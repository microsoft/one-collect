// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::cmp::Ordering;

use tracing::{info, trace};

use ruwind::{CodeSection, ModuleKey, UnwindType};

use super::*;
use super::lookup::*;

#[derive(Clone)]
pub struct ExportMapping {
    time: u64,
    filename_id: usize,
    start: u64,
    end: u64,
    file_offset: u64,
    anon: bool,
    id: usize,
    unwind_type: UnwindType,
    node: Option<ExportDevNode>,
    symbols: Vec<ExportSymbol>,
}

impl Ord for ExportMapping {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start.cmp(&other.start)
    }
}

impl PartialOrd for ExportMapping {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ExportMapping {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}

impl Eq for ExportMapping {}

impl CodeSection for ExportMapping {
    fn anon(&self) -> bool { self.anon }

    fn unwind_type(&self) -> UnwindType {
        self.unwind_type
    }

    fn rva(
        &self,
        ip: u64) -> u64 {
        (ip - self.start) + self.file_offset
    }

    fn key(&self) -> ModuleKey {
        match &self.node {
            Some(node) => {
                ModuleKey::new(
                    node.dev(),
                    node.ino())
            },
            None => {
                ModuleKey::new(
                    0,
                    0)
            }
        }
    }
}

impl ExportMapping {
    pub fn new(
        time: u64,
        filename_id: usize,
        start: u64,
        end: u64,
        file_offset: u64,
        anon: bool,
        id: usize,
        unwind_type: UnwindType) -> Self {
        Self {
            time,
            filename_id,
            start,
            end,
            file_offset,
            anon,
            id,
            unwind_type,
            node: None,
            symbols: Vec::new(),
        }
    }

    pub fn set_node(
        &mut self,
        node: ExportDevNode) {
        self.node = Some(node);
    }

    pub fn time(&self) -> u64 { self.time }

    pub fn time_mut(&mut self) -> &mut u64 { &mut self.time }

    pub fn filename_id(&self) -> usize { self.filename_id }

    pub fn start(&self) -> u64 { self.start }

    pub fn end(&self) -> u64 { self.end }

    pub fn end_mut(&mut self) -> &mut u64 { &mut self.end }

    pub fn len(&self) -> u64 { self.end - self.start }

    pub fn file_offset(&self) -> u64 { self.file_offset }

    pub fn anon(&self) -> bool { self.anon }

    pub fn node(&self) -> &Option<ExportDevNode> { &self.node }

    pub fn id(&self) -> usize { self.id }

    pub fn symbols(&self) -> &Vec<ExportSymbol> { &self.symbols }

    pub fn symbols_mut(&mut self) -> &mut Vec<ExportSymbol> { &mut self.symbols }

    pub fn add_symbol(
        &mut self,
        symbol: ExportSymbol) {
        self.symbols.push(symbol);
    }

    pub fn contains_ip(
        &self,
        ip: u64) -> bool {
        ip >= self.start && ip <= self.end
    }

    pub fn file_to_va_range(
        &self,
        mut file_start: u64,
        mut file_end: u64) -> Option<(u64, u64)> {
        let map_file_start = self.file_offset();
        let map_file_end = map_file_start + self.len();

        // If the map is anonymous or kernel the input addresses are already a va range.
        if self.anon() || self.start() >= KERNEL_START {
            return Some((file_start, file_end))
        }

        // Bail fast if file start/end are not within mapping at all.
        if file_end < map_file_start || file_start > map_file_end {
            return None
        }

        // Ensure start is within mapping.
        if file_start < map_file_start {
            file_start = map_file_start;
        }

        // Ensure end is within mapping.
        if file_end > map_file_end {
            file_end = map_file_end;
        }

        // Calc length of target file range within mapping.
        let file_len = file_end - file_start;

        // Calc offset within mapping by file range.
        let file_offset = file_start - map_file_start;

        // VA start is the file offset in addition to va start.
        let va_offset_start = file_offset + self.start();

        // VA end is the VA start in addition to the file range length.
        let va_offset_end = va_offset_start + file_len;

        Some((va_offset_start, va_offset_end))
    }

    pub fn add_matching_symbols(
        &mut self,
        unique_ips: &mut Vec<u64>,
        sym_reader: &mut impl ExportSymbolReader,
        strings: &mut InternedStrings) {
        let initial_symbol_count = self.symbols.len();
        unique_ips.sort();
        sym_reader.reset();

        loop {
            if !sym_reader.next() {
                break;
            }

            let mut add_sym = false;

            if let Some((start_ip, end_ip)) = self.file_to_va_range(
                sym_reader.start(), sym_reader.end()) {

                match unique_ips.binary_search(&start_ip) {
                    Ok(_) => {
                        add_sym = true;
                    },
                    Err(i) => {
                        let addr = *unique_ips.get(i).unwrap_or(&0u64);
                        if unique_ips.len() > i && addr < end_ip {
                            add_sym = true;
                        }
                    }
                }

                if add_sym {
                    let demangled_name = sym_reader.demangle();
                    let demangled_name = match &demangled_name {
                        Some(n) => n.as_str(),
                        None => sym_reader.name()
                    };

                    // Add the symbol.
                    let symbol = ExportSymbol::new(
                        strings.to_id(demangled_name),
                        start_ip,
                        end_ip);

                    trace!("Adding symbol to mapping: mapping_id={}, name={}, start={:#x}, end={:#x}", 
                        self.id, demangled_name, start_ip, end_ip);
                    self.add_symbol(symbol);
                }
            }
        }
        
        let added_symbols = self.symbols.len() - initial_symbol_count;
        if added_symbols > 0 {
            info!("Added symbols to mapping: mapping_id={}, start={:#x}, added_count={}", 
                self.id, self.start, added_symbols);
        }
    }
}

pub struct ExportMappingLookup {
    lookup: Writable<AddressLookup>,
    mappings: Vec<ExportMapping>,
    min_lookup: usize,
}

impl Default for ExportMappingLookup {
    fn default() -> Self {
        Self {
            lookup: Writable::new(AddressLookup::default()),
            mappings: Vec::new(),
            min_lookup: 16,
        }
    }
}

impl Clone for ExportMappingLookup {
    fn clone(&self) -> Self {
        Self {
            lookup: Writable::new(AddressLookup::default()),
            mappings: self.mappings.clone(),
            min_lookup: self.min_lookup,
        }
    }
}

impl ExportMappingLookup {
    pub fn set_lookup_min_size(
        &mut self,
        min_lookup: usize) {
        self.min_lookup = min_lookup;
    }

    pub fn mappings_mut(&mut self) -> &mut Vec<ExportMapping> {
        /* Mutations must clear lookup */
        self.lookup.borrow_mut().clear();

        &mut self.mappings
    }

    pub fn sort_mappings_by_time(&mut self) {
        self.mappings_mut().sort_by(|a, b| a.time.cmp(&b.time));
    }

    pub fn mappings(&self) -> &Vec<ExportMapping> { &self.mappings }

    fn build_lookup(&self) {
        let mut items = Vec::new();

        for (i, mapping) in self.mappings.iter().enumerate() {
            let index = i as u32;

            items.push(
                AddressLookupItem::new(
                    mapping.start(),
                    index,
                    true));

            items.push(
                AddressLookupItem::new(
                    mapping.end(),
                    index,
                    false));
        }

        self.lookup.borrow_mut().update(&mut items);
    }

    pub fn find_index(
        &self,
        address: u64,
        time: Option<u64>) -> Option<usize> {
        let time = match time {
            Some(time) => { time },
            None => { u64::MAX },
        };

        let mut best: Option<&ExportMapping> = None;
        let mut best_index: usize = 0;

        if self.mappings.len() >= self.min_lookup {
            /* Many items, ensure a lookup and use it */
            if self.lookup.borrow().is_empty() {
                /* Refresh lookup */
                self.build_lookup();
            }

            for index in self.lookup.borrow_mut().find(address) {
                let map = &self.mappings[*index as usize];

                if map.contains_ip(address) && map.time() <= time {
                    match best {
                        Some(existing) => {
                            if map.time() > existing.time() {
                                best = Some(map);
                                best_index = *index as usize;
                            }
                        },
                        None => {
                            best = Some(map);
                            best_index = *index as usize;
                        },
                    }
                }
            }
        } else {
            /* Minimal items, no lookup, scan range */
            for (index, map) in self.mappings.iter().enumerate() {
                if map.contains_ip(address) && map.time() <= time {
                    match best {
                        Some(existing) => {
                            if map.time() > existing.time() {
                                best = Some(map);
                                best_index = index;
                            }
                        },
                        None => {
                            best = Some(map);
                            best_index = index;
                        },
                    }
                }
            }
        }

        match best {
            Some(_) => { Some(best_index) },
            None => { None },
        }
    }

    pub fn find(
        &self,
        address: u64,
        time: Option<u64>) -> Option<&ExportMapping> {
        match self.find_index(address, time) {
            Some(index) => { Some(&self.mappings[index]) },
            None => { None },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_map(
        time: u64,
        start: u64,
        end: u64,
        id: usize) -> ExportMapping {
        ExportMapping::new(time, 0, start, end, 0, false, id, UnwindType::Prolog)
    }

    // Mock implementation of ExportSymbolReader for testing
    struct MockSymbolReader {
        symbols: Vec<(u64, u64, String)>, // (start, end, name)
        current_idx: usize,
        reset_called: bool,
    }

    impl MockSymbolReader {
        fn new(symbols: Vec<(u64, u64, String)>) -> Self {
            Self {
                symbols,
                current_idx: 0,
                reset_called: false,
            }
        }
    }

    impl ExportSymbolReader for MockSymbolReader {
        fn reset(&mut self) {
            self.current_idx = 0;
            self.reset_called = true;
        }

        fn next(&mut self) -> bool {
            if self.current_idx < self.symbols.len() {
                self.current_idx += 1;
                true
            } else {
                false
            }
        }

        fn start(&self) -> u64 {
            if self.current_idx > 0 && self.current_idx <= self.symbols.len() {
                self.symbols[self.current_idx - 1].0
            } else {
                0
            }
        }

        fn end(&self) -> u64 {
            if self.current_idx > 0 && self.current_idx <= self.symbols.len() {
                self.symbols[self.current_idx - 1].1
            } else {
                0
            }
        }

        fn name(&self) -> &str {
            if self.current_idx > 0 && self.current_idx <= self.symbols.len() {
                &self.symbols[self.current_idx - 1].2
            } else {
                ""
            }
        }

        fn demangle(&mut self) -> Option<String> {
            // No demangling in the mock implementation
            None
        }
    }



    #[test]
    fn add_matching_symbols_test() {
        let start = 4096;
        let end = start + 4096;
        let file_offset = 1024;

        let mut mapping = ExportMapping::new(0, 0, start, end, file_offset, false, 0, UnwindType::Prolog);

        // Create test symbols (file offsets and names)
        // File offsets will be converted to VAs: VA = file_offset - 1024 + 4096
        let symbols = vec![
            // Symbol 1: file 1024-1100 -> VA 4096-4172
            (1024, 1100, "symbol_at_start".to_string()),
            
            // Symbol 2: file 1150-1250 -> VA 4222-4322  
            (1150, 1250, "symbol_middle_1".to_string()),
            
            // Symbol 3: file 1300-1400 -> VA 4372-4472
            (1300, 1400, "symbol_middle_2".to_string()),
            
            // Symbol 4: file 1500-1600 -> VA 4572-4672
            (1500, 1600, "symbol_middle_3".to_string()),
            
            // Symbol 5: file 1700-1800 -> VA 4772-4872
            (1700, 1800, "symbol_middle_4".to_string()),
            
            // Symbol 6: file 4900-5020 -> VA 7972-8092 (near end of mapping)
            (4900, 5020, "symbol_near_end".to_string()),
            
            // Symbol that shouldn't match (outside mapping range)
            (6000, 6100, "symbol_out_of_range".to_string()),
        ];

        let mut sym_reader = MockSymbolReader::new(symbols);
        let mut strings = InternedStrings::new(32);
        
        // Create 20 unique IPs for comprehensive testing
        let mut unique_ips = vec![
            // Test beginning of symbols
            4096,  // Start of symbol_at_start
            4222,  // Start of symbol_middle_1
            4372,  // Start of symbol_middle_2
            
            // Test end of symbols  
            4172,  // End of symbol_at_start
            4322,  // End of symbol_middle_1
            4472,  // End of symbol_middle_2
            
            // Test middle of symbols
            4136,  // Middle of symbol_at_start (4096-4172)
            4272,  // Middle of symbol_middle_1 (4222-4322)
            4422,  // Middle of symbol_middle_2 (4372-4472)
            4622,  // Middle of symbol_middle_3 (4572-4672)
            4822,  // Middle of symbol_middle_4 (4772-4872)
            8032,  // Middle of symbol_near_end (7972-8092)
            
            // Test boundaries
            4572,  // Start of symbol_middle_3
            4672,  // End of symbol_middle_3
            4772,  // Start of symbol_middle_4
            4872,  // End of symbol_middle_4
            7972,  // Start of symbol_near_end
            8092,  // End of symbol_near_end
            
            // Test non-matching IPs
            4200,  // Between symbols
            8500,  // Beyond all symbols
        ];

        // Call the function being tested
        mapping.add_matching_symbols(&mut unique_ips, &mut sym_reader, &mut strings);

        // Verify results - should have 6 matching symbols
        assert_eq!(6, mapping.symbols().len(), "Should have added 6 symbols");
        
        // Verify that reset was called on the reader
        assert!(sym_reader.reset_called, "Expected reset() to be called");

        // Check that unique_ips was sorted
        assert!(unique_ips.windows(2).all(|w| w[0] <= w[1]), "Expected unique_ips to be sorted");

        // Verify the symbols are in the expected order (should be sorted by start address)
        let expected_symbols = vec![
            ("symbol_at_start", 4096, 4172),
            ("symbol_middle_1", 4222, 4322),
            ("symbol_middle_2", 4372, 4472),
            ("symbol_middle_3", 4572, 4672),
            ("symbol_middle_4", 4772, 4872),
            ("symbol_near_end", 7972, 8092),
        ];

        for (i, (expected_name, expected_start, expected_end)) in expected_symbols.iter().enumerate() {
            assert_eq!(*expected_start, mapping.symbols()[i].start(), 
                "Symbol {} should start at {}", i, expected_start);
            assert_eq!(*expected_end, mapping.symbols()[i].end(), 
                "Symbol {} should end at {}", i, expected_end);
            assert_eq!(*expected_name, strings.from_id(mapping.symbols()[i].name_id()).unwrap(), 
                "Symbol {} should be '{}'", i, expected_name);
        }
    }

    #[test]
    fn lookup() {
        let mappings = vec!(
            new_map(0, 0, 1023, 1),
            new_map(0, 2048, 3071, 3),
            new_map(0, 1024, 2047, 2),
            new_map(100, 128, 255, 4),
        );

        let mut lookup = ExportMappingLookup::default();

        for mapping in mappings {
            lookup.mappings_mut().push(mapping);
        }

        /* No Time: Linear */
        lookup.set_lookup_min_size(usize::MAX);
        assert_eq!(1, lookup.find(0, None).unwrap().id());
        assert_eq!(2, lookup.find(1024, None).unwrap().id());
        assert_eq!(3, lookup.find(2048, None).unwrap().id());
        assert_eq!(4, lookup.find(128, None).unwrap().id());

        /* No Time: Lookup */
        lookup.set_lookup_min_size(0);
        assert_eq!(1, lookup.find(0, None).unwrap().id());
        assert_eq!(2, lookup.find(1024, None).unwrap().id());
        assert_eq!(3, lookup.find(2048, None).unwrap().id());
        assert_eq!(4, lookup.find(128, None).unwrap().id());

        /* Time: Linear */
        lookup.set_lookup_min_size(usize::MAX);
        assert_eq!(1, lookup.find(0, Some(0)).unwrap().id());
        assert_eq!(2, lookup.find(1024, Some(0)).unwrap().id());
        assert_eq!(3, lookup.find(2048, Some(0)).unwrap().id());
        assert_eq!(1, lookup.find(128, Some(0)).unwrap().id());
        assert_eq!(4, lookup.find(128, Some(100)).unwrap().id());

        /* Time: Lookup */
        lookup.set_lookup_min_size(0);
        assert_eq!(1, lookup.find(0, Some(0)).unwrap().id());
        assert_eq!(2, lookup.find(1024, Some(0)).unwrap().id());
        assert_eq!(3, lookup.find(2048, Some(0)).unwrap().id());
        assert_eq!(1, lookup.find(128, Some(0)).unwrap().id());
        assert_eq!(4, lookup.find(128, Some(100)).unwrap().id());

        lookup.mappings_mut().push(new_map(200, 0, 3071, 5));

        lookup.set_lookup_min_size(usize::MAX);

        /* No Time: Large span Linear */
        assert_eq!(5, lookup.find(0, None).unwrap().id());
        assert_eq!(5, lookup.find(1024, None).unwrap().id());
        assert_eq!(5, lookup.find(2048, None).unwrap().id());
        assert_eq!(5, lookup.find(128, None).unwrap().id());

        /* Time: Large span Linear */
        assert_eq!(1, lookup.find(0, Some(0)).unwrap().id());
        assert_eq!(2, lookup.find(1024, Some(0)).unwrap().id());
        assert_eq!(3, lookup.find(2048, Some(0)).unwrap().id());
        assert_eq!(1, lookup.find(128, Some(0)).unwrap().id());
        assert_eq!(4, lookup.find(128, Some(100)).unwrap().id());

        assert_eq!(5, lookup.find(0, Some(200)).unwrap().id());
        assert_eq!(5, lookup.find(1024, Some(200)).unwrap().id());
        assert_eq!(5, lookup.find(2048, Some(200)).unwrap().id());
        assert_eq!(5, lookup.find(128, Some(200)).unwrap().id());
        assert_eq!(5, lookup.find(128, Some(200)).unwrap().id());

        lookup.set_lookup_min_size(0);

        /* No Time: Large span Lookup */
        assert_eq!(5, lookup.find(0, None).unwrap().id());
        assert_eq!(5, lookup.find(1024, None).unwrap().id());
        assert_eq!(5, lookup.find(2048, None).unwrap().id());
        assert_eq!(5, lookup.find(128, None).unwrap().id());

        /* Time: Large span Lookup */
        assert_eq!(1, lookup.find(0, Some(0)).unwrap().id());
        assert_eq!(2, lookup.find(1024, Some(0)).unwrap().id());
        assert_eq!(3, lookup.find(2048, Some(0)).unwrap().id());
        assert_eq!(1, lookup.find(128, Some(0)).unwrap().id());
        assert_eq!(4, lookup.find(128, Some(100)).unwrap().id());

        assert_eq!(5, lookup.find(0, Some(200)).unwrap().id());
        assert_eq!(5, lookup.find(1024, Some(200)).unwrap().id());
        assert_eq!(5, lookup.find(2048, Some(200)).unwrap().id());
        assert_eq!(5, lookup.find(128, Some(200)).unwrap().id());
        assert_eq!(5, lookup.find(128, Some(200)).unwrap().id());
    }

    #[test]
    fn file_to_va() {
        let start = 4096;
        let end = start + 4096;
        let file_offset = 1024;

        let mapping = ExportMapping::new(0, 0, start, end, file_offset, false, 0, UnwindType::Prolog);

        /* Simple in range case: start */
        let va_range = mapping.file_to_va_range(1024, 1096).unwrap();
        assert_eq!((start, start + 72), va_range);

        /* Simple in range case: middle */
        let va_range = mapping.file_to_va_range(1096, 2048).unwrap();
        assert_eq!((start + 72, start + 72 + 952), va_range);

        /* Entirely out of range cases */
        assert!(mapping.file_to_va_range(end, end+1).is_none());
        assert!(mapping.file_to_va_range(0, 1023).is_none());

        /* Partial start case */
        let va_range = mapping.file_to_va_range(956, 1096).unwrap();
        assert_eq!((start, start + 72), va_range);

        /* Partial end case */
        let va_range = mapping.file_to_va_range(1096, 9216).unwrap();
        assert_eq!((start + 72, end), va_range);
    }
}
