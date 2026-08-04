// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::ruwind::elf::{symbol_rva, ElfLoadHeader, ElfSymbol, ElfSymbolIterator};
use crate::ruwind::go_pclntab::{GoPclnTab, GoPclnTabFileReader};
use std::collections::HashSet;
use std::{
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
};
use tracing::{info, trace, warn};

use crate::helpers::exporting::ExportMachine;

pub const SYM_FLAG_MUST_MATCH: u8 = 1 << 0;

pub struct SymbolPageMap {
    pages: HashSet<u64>,
    page_size: u64,
    page_mask: u64,
}

impl SymbolPageMap {
    pub fn new(page_size: u64) -> Self {
        Self {
            pages: HashSet::new(),
            page_size,

            /* Mask out lower page bits */
            page_mask: !(page_size.next_power_of_two() - 1),
        }
    }

    pub fn mark_ip(
        &mut self,
        ip: u64) {
        /* Find page high bit */
        let page = ip & self.page_mask;

        /* Insert high bit */
        self.pages.insert(page);
    }

    pub fn seen_range(
        &self,
        start: u64,
        end: u64) -> bool {
        /* Find any page high bits */
        let mut page = start & self.page_mask;
        let end_page = end & self.page_mask;

        while page <= end_page {
            if self.pages.contains(&page) {
                return true;
            }

            page += self.page_size;
        }

        false
    }
}

pub struct DynamicSymbol<'a> {
    time: u64,
    pid: u32,
    start: u64,
    end: u64,
    name: &'a str,
    flags: u8,
}

impl<'a> DynamicSymbol<'a> {
    pub fn new(
        time: u64,
        pid: u32,
        start: u64,
        end: u64,
        name: &'a str) -> Self {
        Self {
            time,
            pid,
            start,
            end,
            name,
            flags: 0,
        }
    }

    pub fn time(&self) -> u64 { self.time }

    pub fn pid(&self) -> u32 { self.pid }

    pub fn start(&self) -> u64 { self.start }

    pub fn end(&self) -> u64 { self.end }

    pub fn name(&self) -> &str { self.name }

    pub fn flags(&self) -> u8 { self.flags }

    pub fn set_flag(
        &mut self,
        flag: u8) {
        self.flags |= flag;
    }

    pub fn has_flag(
        &self,
        flag: u8) -> bool {
        self.flags & flag == flag
    }

    pub fn to_export_time_symbol(
        &self,
        machine: &mut ExportMachine) -> ExportTimeSymbol {
        ExportTimeSymbol::new(
            self.time,
            ExportSymbol {
                name_id: machine.strings.to_id(self.name),
                start: self.start,
                end: self.end,
            })
    }
}

#[derive(Clone)]
pub struct ExportSymbol {
    name_id: usize,
    start: u64,
    end: u64,
}

impl ExportSymbol {
    pub fn new(
        name_id: usize,
        start: u64,
        end: u64) -> Self {
        Self {
            name_id,
            start,
            end,
        }
    }

    pub fn name_id(&self) -> usize { self.name_id }

    pub fn start(&self) -> u64 { self.start }

    pub fn end(&self) -> u64 { self.end }
}

#[derive(Clone)]
pub struct ExportTimeSymbol {
    time: u64,
    symbol: ExportSymbol,
}

impl ExportTimeSymbol {
    pub fn new(
        time: u64,
        symbol: ExportSymbol) -> Self {
        Self  {
            time,
            symbol,
        }
    }

    pub fn time(&self) -> u64 { self.time }

    pub fn symbol(&self) -> ExportSymbol { self.symbol.clone() }
}

pub trait ExportSymbolReader {
    fn reset(&mut self);

    fn next(&mut self) -> bool;

    fn start(&self) -> u64;

    fn end(&self) -> u64;

    fn name(&self) -> &str;

    fn demangle(&mut self) -> Option<String>;
}

pub struct KernelSymbolReader {
    reader: Option<BufReader<File>>,
    buffer: String,
    current_ip: u64,
    current_end: Option<u64>,
    current_name: String,
    next_ip: Option<u64>,
    next_name: String,
    done: bool,
}

impl KernelSymbolReader {
    pub fn new() -> Self {
        Self {
            reader: None,
            buffer: String::with_capacity(64),
            current_name: String::with_capacity(64),
            current_ip: 0,
            current_end: None,
            next_ip: None,
            next_name: String::with_capacity(64),
            done: true,
        }
    }

    pub fn set_file(
        &mut self,
        file: File) {
        self.reader = Some(BufReader::new(file));
        self.reset()
    }

    fn load_next(&mut self) {
        /* Swap next with current */
        if let Some(ip) = self.next_ip {
            self.current_ip = ip;
            self.current_end = None;
            self.current_name.clear();
            self.current_name.push_str(&self.next_name);

            self.next_ip = None;
            self.next_name.clear();
        }

        /* Load in new next */
        if let Some(reader) = &mut self.reader {
            loop {
                self.buffer.clear();

                if let Ok(len) = reader.read_line(&mut self.buffer) {
                    if len == 0 {
                        break;
                    }
                } else {
                    break;
                }

                let mut addr: u64 = 0;
                let mut symtype: &str = "";
                let mut method: &str = "";
                let mut module: Option<&str> = None;

                for (index, part) in self.buffer.split_whitespace().enumerate() {
                    match index {
                        0 => {
                            addr = u64::from_str_radix(part, 16).unwrap();
                        },
                        1 => {
                            symtype = part;
                        },
                        2 => {
                            method = part;
                        },
                        3 => {
                            module = Some(part);
                        },
                        _ => {},
                    }
                }

                if self.current_end.is_none() && self.current_ip != 0 {
                    self.current_end = Some(addr - 1);
                }

                /* Skip non-method symbols */
                if !symtype.starts_with('t') && !symtype.starts_with('T') {
                    continue;
                }

                self.next_ip = Some(addr);
                if let Some(module) = module {
                    self.next_name.push_str(module);
                    self.next_name.push_str(" ");
                }
                self.next_name.push_str(method);
                self.done = false;

                return;
            }
        }

        self.done = true;
    }
}

impl ExportSymbolReader for KernelSymbolReader {
    fn reset(&mut self) {
        self.current_ip = 0;
        self.current_end = None;
        self.next_ip = None;
        self.done = true;

        if let Some(reader) = &mut self.reader {
            if reader.seek(SeekFrom::Start(0)).is_ok() {
                self.done = false;
                self.load_next();
                return;
            }
        }

        if let Ok(file) = File::open("/proc/kallsyms") {
            self.reader = Some(BufReader::new(file));
            self.done = false;
            self.load_next();
            info!("Kernel symbol reader initialized from /proc/kallsyms");
        } else {
            warn!("Failed to open /proc/kallsyms");
        }
    }

    fn next(&mut self) -> bool {
        if self.done {
            return false;
        }

        self.load_next();

        true
    }

    fn start(&self) -> u64 {
        self.current_ip
    }

    fn end(&self) -> u64 {
        match self.current_end {
            Some(end) => { end },
            None => { 0xFFFFFFFFFFFFFFFF },
        }
    }

    fn name(&self) -> &str {
        &self.current_name
    }

    fn demangle(&mut self) -> Option<String> {
        None
    }
}

pub struct ElfSymbolReader<'a> {
    iterator: ElfSymbolIterator<'a>,
    current_sym: ElfSymbol,
    current_sym_valid: bool,
}

impl<'a> ElfSymbolReader<'a> {
    pub fn new(file: File, load_header: ElfLoadHeader, system_page_size: u64) -> Self {
        Self {
            iterator: ElfSymbolIterator::new(file, load_header, system_page_size),
            current_sym: ElfSymbol::new(),
            current_sym_valid: false,
        }
    }
}

impl<'a> ExportSymbolReader for ElfSymbolReader<'a> {
    fn reset(&mut self) {
        self.iterator.reset();
        self.current_sym_valid = false;
    }

    fn next(&mut self) -> bool {
        self.current_sym_valid = self.iterator.next(&mut self.current_sym);
        self.current_sym_valid
    }

    fn start(&self) -> u64 {
        let mut start = 0u64;
        if self.current_sym_valid {
            start = self.current_sym.start();
        }
        start
    }

    fn end(&self) -> u64 {
        let mut end = 0u64;
        if self.current_sym_valid {
            end = self.current_sym.end();
        }
        end
    }

    fn name(&self) -> &str {
        let mut name = "";
        if self.current_sym_valid {
            name = self.current_sym.name();
        }
        name
    }

    fn demangle(&mut self) -> Option<String> {
        let mut demangled_name = None;
        if self.current_sym_valid {
            demangled_name = self.current_sym.demangle();
        }
        demangled_name
    }
}

pub struct PerfMapSymbolReader {
    reader: BufReader<File>,
    buffer: String,
    start_ip: u64,
    end_ip: u64,
    name: String,
    done: bool,
}

/// Symbol reader backed by a Go `gopclntab` line table.
///
/// Recovers Go function names from the `.gopclntab` section for binaries whose
/// ELF symbol table has been stripped (e.g. `go build -ldflags "-s"`, as used
/// by Kubernetes). Function virtual addresses from the table are translated to
/// file RVAs via [`symbol_rva`], identical to [`ElfSymbolReader`], so the two
/// can be layered (unioned) for the same mapping.
#[doc(hidden)]
pub struct GoPclnTabSymbolReader {
    tab: GoPclnTab<GoPclnTabFileReader>,
    load_header: ElfLoadHeader,
    page_mask: u64,
    current_start: u64,
    current_end: u64,
    valid: bool,
}

impl GoPclnTabSymbolReader {
    /// Attempts to build a reader from `file`. Returns `None` if the file has no
    /// usable `.gopclntab` section or the table cannot be parsed (e.g. an
    /// unsupported/older Go layout), so callers fall back to ELF symbols.
    pub fn new(mut file: File, load_header: ElfLoadHeader, system_page_size: u64) -> Option<Self> {
        // Prefer the .gopclntab section; fall back to scanning for a stripped
        // (section-header-removed) line table.
        let location = crate::ruwind::elf::read_go_pclntab(&mut file)
            .or_else(|| crate::ruwind::elf::recover_go_pclntab(&mut file))?;
        let tab = GoPclnTab::open(
            GoPclnTabFileReader::new(file, location.file_offset()),
            location,
        )?;

        Some(Self {
            tab,
            load_header,
            page_mask: crate::page_size_to_mask(system_page_size),
            current_start: 0,
            current_end: 0,
            valid: false,
        })
    }
}

impl ExportSymbolReader for GoPclnTabSymbolReader {
    fn reset(&mut self) {
        self.tab.reset();
        self.valid = false;
    }

    fn next(&mut self) -> bool {
        let p_vaddr = self.load_header.p_vaddr();

        while self.tab.next() {
            let start_va = self.tab.start();
            let end_va = self.tab.end();

            // Guard against entries below the loaded segment (would
            // underflow the RVA translation).
            if start_va < p_vaddr {
                continue;
            }

            let start = symbol_rva(start_va, &self.load_header, self.page_mask);

            // pclntab end is the next function's entry (exclusive); make it
            // inclusive to match ElfSymbol semantics and avoid overlapping
            // the following function's start.
            let end_exclusive = if end_va > start_va {
                end_va
            } else {
                start_va + 1
            };
            let end = symbol_rva(end_exclusive, &self.load_header, self.page_mask)
                .saturating_sub(1)
                .max(start);

            self.current_start = start;
            self.current_end = end;
            self.valid = true;
            return true;
        }

        self.valid = false;
        false
    }

    fn start(&self) -> u64 {
        if self.valid {
            self.current_start
        } else {
            0
        }
    }

    fn end(&self) -> u64 {
        if self.valid {
            self.current_end
        } else {
            0
        }
    }

    fn name(&self) -> &str {
        if self.valid {
            self.tab.name()
        } else {
            ""
        }
    }

    fn demangle(&mut self) -> Option<String> {
        // Go pclntab names are already in final, human-readable form and must
        // never be passed through a C++/Rust demangler.
        None
    }
}


impl PerfMapSymbolReader {
    pub fn new(file: File) -> Self {
        Self {
            reader: BufReader::new(file),
            buffer: String::with_capacity(256),
            name: String::with_capacity(256),
            start_ip: 0,
            end_ip: 0,
            done: true,
        }
    }

    fn load_next(&mut self) {
        loop {
            self.buffer.clear();

            self.start_ip = 0;
            self.end_ip = 0;
            self.name.clear();

            if let Ok(len) = self.reader.read_line(&mut self.buffer) {
                if len == 0 {
                    trace!("PerfMap load_next: end of file");
                    break;
                }
            } else {
                trace!("PerfMap load_next: read error");
                break;
            }

            trace!("PerfMap load_next: parsing line={}", self.buffer.trim());

            let mut parts = self.buffer.splitn(3, ' ');

            let Some(start_str) = parts.next() else {
                continue;
            };

            let start_str = if start_str.starts_with("0x") || start_str.starts_with("0X") {
                &start_str[2..]
            } else {
                start_str
            };

            self.start_ip = match u64::from_str_radix(start_str, 16) {
                Ok(start_ip) => start_ip,
                Err(_) => {
                    warn!("PerfMap load_next: skipping malformed line={}", self.buffer.trim());
                    continue;
                }
            };

            let Some(size_str) = parts.next() else {
                continue;
            };

            let Ok(size) = u64::from_str_radix(size_str, 16) else {
                warn!("PerfMap load_next: skipping malformed line={}", self.buffer.trim());
                continue;
            };

            self.end_ip = self.start_ip + size;

            if let Some(name_part) = parts.next() {
                /*
                 * Symbols sometimes have nulls in them. When we see
                 * this we'll just use up to the null as the name.
                 */
                let name_part = name_part.split('\0').next().unwrap();

                self.name.push_str(name_part);
                if self.name.ends_with("\n") {
                    self.name.pop();
                }
                if self.name.ends_with("\r") {
                    self.name.pop();
                }
            }

            self.done = false;

            trace!("PerfMap load_next: parsed symbol start_ip={:#x}, end_ip={:#x}, name={}", self.start_ip, self.end_ip, self.name);
            return;
        }

        self.done = true;
    }
}

impl ExportSymbolReader for PerfMapSymbolReader {
    fn reset(&mut self) {
        if self.reader.seek(SeekFrom::Start(0)).is_ok() {
            self.done = false;
            return;
        }
        else {
            // If we fail to seek to the start of the file,
            // set the values to their defaults and set
            // done = true to prevent further reading.
            self.start_ip = 0;
            self.end_ip = 0;
            self.name.clear();
            self.done = true;
        }
    }

    fn next(&mut self) -> bool {
        if self.done {
            return false;
        }

        self.load_next();

        if self.done {
            return false;
        }

        true
    }

    fn start(&self) -> u64 {
        self.start_ip
    }

    fn end(&self) -> u64 {
        self.end_ip
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn demangle(&mut self) -> Option<String> {
        None
    }
}

pub struct R2RMapSymbolReader {
    reader: BufReader<File>,
    buffer: String,
    start_ip: u64,
    end_ip: u64,
    name: String,
    done: bool,
    signature: [u8; 16],
}

impl R2RMapSymbolReader {
    pub fn new(file: File) -> Self {
        Self {
            reader: BufReader::new(file),
            buffer: String::with_capacity(256),
            name: String::with_capacity(256),
            start_ip: 0,
            end_ip: 0,
            done: true,
            signature: [0; 16],
        }
    }

    pub fn signature(&self) -> &[u8; 16] {
        &self.signature
    }

    fn initialize(&mut self) {
        loop {
            self.load_next();

            if self.done {
                break;
            }

            // The pseudo RVA 0xFFFFFFFF contains the perfmap signature.
            // It is part of the perfmap header that is composed of a few pseudo RVAs at the beginning of the file.
            if self.start_ip == 0xFFFFFFFF {
                if Self::read_signature(self.name.as_str(), &mut self.signature).is_err() {
                    // If there was a failure reading the signature, reset to zero.
                    self.signature = [0; 16];
                }
                break;
            }
        }
    }

    fn read_signature(
        name: &str,
        buf: &mut [u8; 16]) -> anyhow::Result<()> {
        // Don't set the signature if it's not the right length (16 bytes).
        if name.len() != 32 {
            return Ok(());
        }

        for i in 0..16 {
            let byte_str = &name[(2*i)..(2*i)+2];
            buf[i] = u8::from_str_radix(byte_str, 16)?;
        }

        Ok(())
    }

    fn load_next(&mut self) {
        'load: {
            self.buffer.clear();

            self.start_ip = 0;
            self.end_ip = 0;
            self.name.clear();

            if let Ok(len) = self.reader.read_line(&mut self.buffer) {
                if len == 0 {
                    break 'load;
                }
            } else {
                break 'load;
            }

            for (index, part) in self.buffer.splitn(3, ' ').enumerate() {
                match index {
                    0 => {
                        if part.starts_with("0x") || part.starts_with("0X") {
                            self.start_ip = u64::from_str_radix(&part[2..], 16).unwrap();
                        } else {
                            self.start_ip = u64::from_str_radix(part, 16).unwrap();
                        }
                    },
                    1 => {
                        let size = u64::from_str_radix(part, 16).unwrap();
                        self.end_ip = self.start_ip + size;
                    },
                    _ => {
                        /*
                         * Symbols sometimes have nulls in them. When we see
                         * this we'll just use up to the null as the name.
                         */
                        let part = part.split('\0').next().unwrap();

                        self.name.push_str(part);
                        if self.name.ends_with("\n") {
                            self.name.pop();
                        }
                        if self.name.ends_with("\r") {
                            self.name.pop();
                        }
                    },
                }
            }

            self.done = false;

            return;
        }

        self.done = true;
    }
}

impl ExportSymbolReader for R2RMapSymbolReader {
    fn reset(&mut self) {
        if self.reader.seek(SeekFrom::Start(0)).is_ok() {
            self.done = false;
            self.initialize();
            return;
        }
        else {
            // If we fail to seek to the start of the file,
            // set the values to their defaults and set
            // done = true to prevent further reading.
            self.start_ip = 0;
            self.end_ip = 0;
            self.name.clear();
            self.done = true;
        }
    }

    fn next(&mut self) -> bool {
        loop {
            if self.done {
                return false;
            }

            self.load_next();

            if self.done {
                return false;
            }

            // Skip perfmap metadata.
            if self.start_ip <= 0xFFFFFFF0 {
                break;
            }
        }

        true
    }

    fn start(&self) -> u64 {
        self.start_ip
    }

    fn end(&self) -> u64 {
        self.end_ip
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn demangle(&mut self) -> Option<String> {
        None
    }
}

// This transformer is responsible for reconciling the difference between the expectations in the crossgen2 tool
// and the representation of the PE image loaded layout as implemented by CoreCLR and seen from the Linux kernel.
//
// When a ready to run PE image is loaded by CoreCLR, it loads it via multiple mmap calls, which results in multiple
// mmap events and multiple ExportMapping objects.  The Linux kernel reports this as:
//
// 1. The base mapping that contains the DOS and NT image headers.  This mapping represents the beginning of the PE image,
//    and its start address represents the base address of the loaded layout.
// 2. One mapping per section.  For example, there will be one mapping for the .text section.
//
// When it's time to calculate RVAs from captured IPs, crossgen2 has generated the symbol file with the assumption that RVAs
// are calculated by taking the IP and subtracting the base address - the start address of the base mapping, and NOT the start
// address of the current (e.g. .text section) mapping.  R2RLoadedLayoutSymbolTransformer takes as a parameter, the difference
// between the current mapping's start address and the base mapping's start address, and uses that offset to compute RVAs that
// will match crossgen2's view of the world when generating the symbol file.
pub struct R2RLoadedLayoutSymbolTransformer {
    sym_reader: R2RMapSymbolReader,
    offset: u64,
}

impl R2RLoadedLayoutSymbolTransformer {
    pub fn new(
        sym_reader: R2RMapSymbolReader,
        offset: u64) -> Self {
        Self {
            sym_reader,
            offset,
        }
    }
}

impl ExportSymbolReader for R2RLoadedLayoutSymbolTransformer {
    fn reset(&mut self) {
        self.sym_reader.reset()
    }

    fn next(&mut self) -> bool {
        self.sym_reader.next()
    }

    fn start(&self) -> u64 {
        self.sym_reader.start() - self.offset
    }

    fn end(&self) -> u64 {
        self.sym_reader.end() - self.offset
    }

    fn name(&self) -> &str {
        self.sym_reader.name()
    }

    fn demangle(&mut self) -> Option<String> {
        self.sym_reader.demangle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::os::system_page_size;
    #[cfg(target_os = "linux")]
    use std::path::Path;

    #[test]
    fn kernel_symbol_reader() {
        let kern_syms_path = std::env::current_dir().unwrap().join(
            "../test/assets/kernel/symbols.map");

        let mut reader = KernelSymbolReader::new();

        reader.set_file(File::open(kern_syms_path).unwrap());

        for _ in 0..4 {
            /* method1 */
            assert!(reader.next());
            assert_eq!(0x0A, reader.start());
            assert_eq!(0xA9, reader.end());
            assert_eq!("method1", reader.name());

            /* method2 */
            assert!(reader.next());
            assert_eq!(0xAC, reader.start());
            assert_eq!(0xBA, reader.end());
            assert_eq!("[module] method2", reader.name());

            /* method3 */
            assert!(reader.next());
            assert_eq!(0xBB, reader.start());
            assert_eq!(0xFFFFFFFFFFFFFFFF, reader.end());
            assert_eq!("method3", reader.name());

            /* End */
            assert!(!reader.next());

            /* Reset */
            reader.reset();
        }
    }

    #[test]
    fn perf_map_symbol_reader() {
        let expected_count = 2435;
        let perf_map_path = std::env::current_dir().unwrap().join(
            "../test/assets/perfmap/dotnet-info.map");

        if let Ok(file) = File::open(perf_map_path.clone()) {
            let mut reader = PerfMapSymbolReader::new(file);
            reader.reset();

            let mut actual_count = 0;
            loop {
                if !reader.next() {
                    break;
                }

                actual_count+=1;
                assert!(reader.start() < reader.end(), "Start must be less than end - start: {}, end: {}", reader.start(), reader.end());
                assert!(reader.name().len() > 0);

                // Check for a few known symbols.
                match reader.start() {
                    0x00007F148458E6A0 => {
                        assert_eq!(0x00007F148458E6A0 + 0x1B0, reader.end());
                        assert_eq!(reader.name(), "int32 [System.Private.CoreLib] System.SpanHelpers::IndexOf(char&,char,int32)[OptimizedTier1]");
                    },
                    0x00007F1484597400 => {
                        assert_eq!(0x00007F1484597400 + 0x121, reader.end());
                        assert_eq!(reader.name(), "native uint [System.Private.CoreLib] System.Text.ASCIIUtility::NarrowUtf16ToAscii(char*,uint8*,native uint)[Optimized]");
                    },
                    0x00007F1484F65380 => {
                        assert_eq!(0x00007F1484F65380 + 0x17e, reader.end());
                        assert_eq!(reader.name(), "instance bool [System.Linq] System.Linq.Enumerable+SelectListIterator`2[Microsoft.Extensions.DependencyModel.DependencyContextJsonReader+TargetLibrary,System.__Canon]::MoveNext()[QuickJitted]")
                    },
                    _ => {},
                }
            }

            assert_eq!(actual_count, expected_count);
        }
        else {
            assert!(false, "Unable to open file {}", perf_map_path.display());
        }
    }

    #[test]
    fn r2r_map_symbol_reader() {
        let expected_count = 45433;
        let r2r_map_path = std::env::current_dir().unwrap().join(
            "../test/assets/r2rmap/System.Private.CoreLib.ni.r2rmap");

        if let Ok(file) = File::open(r2r_map_path.clone()) {
            let mut reader = R2RMapSymbolReader::new(file);
            reader.reset();

            let expected_signature: [u8; 16] = [
                0x7B, 0x8E, 0x67, 0x11, 0xBF, 0xD1, 0xA8, 0x79,
                0x11, 0x84, 0xF7, 0xDB, 0x99, 0xCD, 0xB3, 0xA5
            ];
            assert_eq!(&expected_signature, reader.signature());

            let mut actual_count = 0;
            let mut s1 = false;
            let mut s2 = false;
            let mut s3 = false;
            loop {
                if !reader.next() {
                    break;
                }

                actual_count+=1;
                assert!(reader.start() < reader.end(), "Start must be less than end - start: {}, end: {}", reader.start(), reader.end());
                assert!(reader.name().len() > 0);

                // Check for a few known symbols.
                match reader.start() {
                    0x0011D1D0 => {
                        assert_eq!(0x0011D1D0 + 0x23, reader.end());
                        assert_eq!(reader.name(), "Interop::CheckIo(Interop+Error, System.String, System.Boolean)");
                        s1 = true;
                    },
                    0x0011E880 => {
                        assert_eq!(0x0011E880 + 0xA5, reader.end());
                        assert_eq!(reader.name(), "System.Int32 Interop+Globalization::WindowsIdToIanaId(System.String, System.IntPtr, System.Char*, System.Int32)");
                        s2 = true;
                    },
                    0x0011FB00 => {
                        assert_eq!(0x0011FB00 + 0x54, reader.end());
                        assert_eq!(reader.name(), "System.Int32 Interop+ErrorInfo::get_RawErrno()");
                        s3 = true;
                    },
                    _ => {},
                }
            }

            assert_eq!(s1, true);
            assert_eq!(s2, true);
            assert_eq!(s3, true);
            assert_eq!(actual_count, expected_count);
        }
        else {
            assert!(false, "Unable to open file {}", r2r_map_path.display());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn elf_symbol_reader() {
        #[cfg(all(target_arch = "x86_64", target_env = "gnu"))]
        let possible_paths = [
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/libc.so.6"
        ];

        #[cfg(all(target_arch = "x86_64", target_env = "musl"))]
        let possible_paths = [
            "/lib/ld-musl-x86_64.so.1",
            "/lib/libc.musl-x86_64.so.1",
            "/usr/lib/libc.musl-x86_64.so.1"
        ];

        #[cfg(all(target_arch = "aarch64", target_env = "gnu"))]
        let possible_paths = [
            "/usr/lib/aarch64-linux-gnu/libc.so.6",
            "/usr/lib/libc.so.6"
        ];

        #[cfg(all(target_arch = "aarch64", target_env = "musl"))]
        let possible_paths = [
            "/lib/ld-musl-aarch64.so.1",
            "/lib/libc.musl-aarch64.so.1",
            "/usr/lib/libc.musl-aarch64.so.1"
        ];

        let path = possible_paths
            .iter()
            .find(|&p| Path::new(p).exists())
            .expect("Could not find libc in any expected location");

        if let Ok(file) = File::open(path) {
            let load_header = ElfLoadHeader::new(0, 0);
            let system_page_size = system_page_size();
            let mut reader = ElfSymbolReader::new(file, load_header, system_page_size);
            reader.reset();

            let mut actual_count = 0;
            loop {
                if !reader.next() {
                    break;
                }

                actual_count+=1;
                assert!(reader.start() <= reader.end(), "Start must be less than or equal to end - start: {}, end: {}", reader.start(), reader.end());
                assert!(reader.name().len() > 0);
            }

            assert!(actual_count > 0);
        }
        else {
            assert!(false, "Unable to open file {}", path);
        }
    }

    /// Cross-checks the Go pclntab reader against the ELF symbol reader on a
    /// binary that has both. For every function name present in both sources,
    /// the start address must match exactly — proving coordinate consistency so
    /// the two can be unioned. Ignored by default; run with:
    ///   GO_PCLNTAB_BIN=/path/to/go-binary \
    ///     cargo test --lib go_pclntab_matches_elf -- --ignored --nocapture
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn go_pclntab_matches_elf() {
        use std::collections::HashMap;

        let path = std::env::var("GO_PCLNTAB_BIN").expect("set GO_PCLNTAB_BIN");
        let page = system_page_size();

        // Collect ELF symtab/dynsym function starts by name.
        let mut elf_starts: HashMap<String, u64> = HashMap::new();
        {
            let file = File::open(&path).expect("open binary");
            let mut reader = ElfSymbolReader::new(file, ElfLoadHeader::new(0, 0), page);
            reader.reset();
            while reader.next() {
                elf_starts.insert(reader.name().to_string(), reader.start());
            }
        }
        assert!(!elf_starts.is_empty(), "binary should have ELF symbols for this test");

        // Walk the Go pclntab reader and compare overlapping names.
        let file = File::open(&path).expect("open binary");
        let mut go = GoPclnTabSymbolReader::new(file, ElfLoadHeader::new(0, 0), page)
            .expect("binary should have a .gopclntab");
        go.reset();

        let mut compared = 0usize;
        let mut matched = 0usize;
        let mut mismatched = 0usize;
        let mut go_count = 0usize;
        let mut examples: Vec<String> = Vec::new();
        while go.next() {
            go_count += 1;
            if let Some(&elf_start) = elf_starts.get(go.name()) {
                compared += 1;
                assert!(go.start() <= go.end());
                if elf_start == go.start() {
                    matched += 1;
                } else {
                    mismatched += 1;
                    if examples.len() < 5 {
                        examples.push(format!(
                            "{}: elf={:#x} go={:#x}", go.name(), elf_start, go.start()));
                    }
                }
            }
        }

        println!(
            "{}: elf_funcs={} go_funcs={} overlap={} matched={} mismatched={}",
            path, elf_starts.len(), go_count, compared, matched, mismatched);
        for e in &examples {
            println!("  mismatch (expected for ABI wrappers): {}", e);
        }

        // The vast majority of shared names must agree exactly. A small number
        // legitimately differ because the ELF symtab and pclntab record distinct
        // addresses for ABI wrappers that share a name; the union dedups by start
        // so those become separate, correct entries. A coordinate bug would make
        // essentially everything mismatch, which this guards against.
        assert!(compared > 1000, "expected a large overlap, got {}", compared);
        assert!(
            matched * 100 >= compared * 95,
            "expected >=95% start agreement, got {}/{}", matched, compared);
    }

    /// Exercises the full GoPclnTabSymbolReader over committed fixtures, for both
    /// the section path and the recovery (renamed-section) path. No network.
    #[test]
    #[cfg(target_os = "linux")]
    fn go_pclntab_symbol_reader_fixtures() {
        let page = system_page_size();
        for name in ["pclntab_stripped_symbols", "pclntab_section_stripped"] {
            let path = std::env::current_dir().unwrap()
                .join("../test/assets/go").join(name);
            let file = File::open(&path).unwrap_or_else(|_| panic!("open fixture {}", name));

            let mut reader = GoPclnTabSymbolReader::new(file, ElfLoadHeader::new(0, 0), page)
                .unwrap_or_else(|| panic!("reader should build for {}", name));
            reader.reset();

            let mut count = 0usize;
            let mut found_main = false;
            while reader.next() {
                count += 1;
                assert!(reader.start() <= reader.end());
                assert!(!reader.name().is_empty());
                assert!(
                    reader.demangle().is_none(),
                    "Go names must not be demangled"
                );
                if reader.name() == "main.main" {
                    found_main = true;
                }
            }
            assert!(
                count > 100,
                "{}: expected many symbols, got {}",
                name,
                count
            );
            assert!(found_main, "{}: main.main should resolve", name);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn symbol_benchmark_fixtures_match() {
        use std::collections::HashMap;

        let fixture_dir = std::env::current_dir().unwrap().join("../test/assets/go");
        let elf_path = fixture_dir.join("symbol_benchmark_elf");
        let go_path = fixture_dir.join("symbol_benchmark_go");
        let page = system_page_size();

        let mut elf_symbols = HashMap::new();
        let mut elf = ElfSymbolReader::new(
            File::open(&elf_path).expect("open ELF benchmark fixture"),
            ElfLoadHeader::new(0, 0x400000),
            page,
        );
        elf.reset();
        while elf.next() {
            elf_symbols.insert(elf.name().to_string(), elf.start());
        }

        let mut go = GoPclnTabSymbolReader::new(
            File::open(&go_path).expect("open Go benchmark fixture"),
            ElfLoadHeader::new(0, 0x400000),
            page,
        )
        .expect("parse Go benchmark fixture");
        go.reset();

        let mut go_count = 0;
        let mut shared_count = 0;
        let mut found_target = false;
        while go.next() {
            go_count += 1;
            if elf_symbols.get(go.name()) == Some(&go.start()) {
                shared_count += 1;
            }
            if go.name() == "main.benchmarkTarget" {
                found_target = true;
            }
        }

        assert!(
            elf_symbols.len() >= 1000,
            "expected at least 1000 ELF symbols"
        );
        assert!(go_count >= 1000, "expected at least 1000 Go symbols");
        assert!(
            shared_count >= 1000,
            "expected at least 1000 shared symbols"
        );
        assert!(found_target, "benchmark target should be present");
    }

    #[test]
    fn symbol_page_map() {
        let mut map = SymbolPageMap::new(256);
        map.mark_ip(0);
        map.mark_ip(257);
        map.mark_ip(1024);

        assert!(map.seen_range(0, 256));
        assert!(map.seen_range(257, 257));
        assert!(map.seen_range(511, 511));
        assert!(!map.seen_range(512, 1023));
        assert!(map.seen_range(1024, 4096));
        assert!(map.seen_range(1279, 1279));
        assert!(!map.seen_range(1280, 4096));
    }

    #[test]
    fn perf_map_skips_malformed_lines() {
        let perf_map_path = std::env::current_dir().unwrap().join(
            "../test/assets/perfmap/malformed-lines.map");

        let file = File::open(perf_map_path).expect("Unable to open test file");
        let mut reader = PerfMapSymbolReader::new(file);
        reader.reset();

        // 0x-prefixed .NET symbol
        assert!(reader.next());
        assert_eq!(0x7a231c4c0020, reader.start());
        assert_eq!(0x7a231c4c0020 + 0xc49, reader.end());
        assert_eq!(reader.name(), "instance bool [System.Private.CoreLib] System.IO.Enumeration.FileSystemEnumerator`1[System.__Canon]::MoveNext()[OptimizedTier1]");

        // 0x-prefixed .NET symbol
        assert!(reader.next());
        assert_eq!(0x7a231c4c0cb0, reader.start());
        assert_eq!(0x7a231c4c0cb0 + 0x4, reader.end());

        // Malformed line "rs.HeaderDescriptor,string)..." is skipped

        // Plain hex JS symbol
        assert!(reader.next());
        assert_eq!(0x7402ec4bb340, reader.start());
        assert_eq!(0x7402ec4bb340 + 0x1668, reader.end());
        assert_eq!(reader.name(), "JS:*'parserOnIncoming node:_http_server:1084:26");

        // Malformed line "del.Protocols.OpenIdConnect..." is skipped

        // Plain hex JS symbol
        assert!(reader.next());
        assert_eq!(0x7402ec4bca40, reader.start());
        assert_eq!(0x7402ec4bca40 + 0x11e0, reader.end());
        assert_eq!(reader.name(), "JS:*'write_ node:_http_outgoing:887:16");

        // 0X-prefixed (uppercase) JS symbol
        assert!(reader.next());
        assert_eq!(0x7402EC2F8640, reader.start());
        assert_eq!(0x7402EC2F8640 + 0x250, reader.end());
        assert_eq!(reader.name(), "JS:+ node:internal/deps/undici/undici:3179:40");

        // End of file
        assert!(!reader.next());
    }
}
