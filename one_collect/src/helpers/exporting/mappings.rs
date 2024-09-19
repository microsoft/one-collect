use std::cmp::Ordering;
use std::path::Path;

use ruwind::{CodeSection, ModuleKey};

use super::*;

#[derive(Clone)]
pub struct ExportMapping {
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
        filename_id: usize,
        start: u64,
        end: u64,
        file_offset: u64,
        anon: bool,
        id: usize) -> Self {
        Self {
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

    pub fn filename_id(&self) -> usize { self.filename_id }

    pub fn start(&self) -> u64 { self.start }

    pub fn end(&self) -> u64 { self.end }

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

    pub fn add_matching_symbols(
        &mut self,
        unique_ips: &mut Vec<u64>,
        sym_reader: &mut impl ExportSymbolReader,
        strings: &mut InternedStrings) {
        unique_ips.sort();
        sym_reader.reset();

        // Anonymous and kernel symbols use a raw ip.
        let mut offset = 0u64;
        if !self.anon() && self.start() < KERNEL_START {
            offset = self.start();
        }

        loop {
            if !sym_reader.next() {
                break;
            }

            let mut add_sym = false;
            let start_addr = sym_reader.start() + offset;
            let end_addr = sym_reader.end() + offset;

            // Find the start address for the current symbol in unique_ips.
            let mut start_index = 0;
            match unique_ips.binary_search(&start_addr) {
                Ok(i) => { 
                    start_index = i;
                    add_sym = true;
                },
                Err(i) => {
                    let addr = *unique_ips.get(i).unwrap_or(&0u64);
                    if unique_ips.len() > i && addr < end_addr {
                        start_index = i;
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
                    start_addr,
                    end_addr);

                self.add_symbol(symbol);

                // Remove ips from unique_ips if the symbol we just added includes them.
                let mut end_index = start_index;
                for ip in &unique_ips[start_index..] {
                    end_index += 1;
                    if ip >= &end_addr {
                        break;
                    }
                }

                unique_ips.drain(start_index..end_index);
            }
        }
    }
}
