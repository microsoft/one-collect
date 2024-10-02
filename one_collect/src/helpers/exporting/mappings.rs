use std::cmp::Ordering;

use ruwind::{CodeSection, ModuleKey};

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
        id: usize) -> Self {
        Self {
            time,
            filename_id,
            start,
            end,
            file_offset,
            anon,
            id,
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

    pub fn filename_id(&self) -> usize { self.filename_id }

    pub fn start(&self) -> u64 { self.start }

    pub fn end(&self) -> u64 { self.end }

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

                    self.add_symbol(symbol);
                    if sym_reader.start() == 0x338050 {
                        println!("Added symbol.");
                    }
                }
            }
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

    pub fn find(
        &self,
        address: u64,
        time: Option<u64>) -> Option<&ExportMapping> {
        let time = match time {
            Some(time) => { time },
            None => { u64::MAX },
        };

        let mut best: Option<&ExportMapping> = None;

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
                            }
                        },
                        None => { best = Some(map); },
                    }
                }
            }
        } else {
            /* Minimal items, no lookup, scan range */
            for map in &self.mappings {
                if map.contains_ip(address) && map.time() <= time {
                    match best {
                        Some(existing) => {
                            if map.time() > existing.time() {
                                best = Some(map);
                            }
                        },
                        None => { best = Some(map); },
                    }
                }
            }
        }

        best
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
        ExportMapping::new(time, 0, start, end, 0, false, id)
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

        let mapping = ExportMapping::new(0, 0, start, end, file_offset, false, 0);

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
