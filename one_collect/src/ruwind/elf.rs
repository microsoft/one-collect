// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::io::{BufReader, Error, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::mem::{zeroed, size_of};
use std::slice;
use cpp_demangle::{DemangleOptions, Symbol};
use rustc_demangle::try_demangle;
use tracing::{warn, info, debug, trace};

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

pub const SHT_PROGBITS: ElfWord = 1;
pub const SHT_SYMTAB: ElfWord = 2;
const SHT_RELA: ElfWord = 4;
pub const SHT_NOTE: ElfWord = 7;
pub const SHT_NOBITS: ElfWord = 8;
pub const SHT_DYNSYM: ElfWord = 11;

// Relative relocation types (used to recover Go runtime.text on PIE binaries).
const R_X86_64_RELATIVE: u32 = 8;
const R_AARCH64_RELATIVE: u32 = 1027;

// Symbol type flags that can be or'd together to keep track of
// which types of symbols are present in a binary.
pub const SYMBOL_TYPE_ELF_SYMTAB: u32 = 1;
pub const SYMBOL_TYPE_ELF_DYNSYM: u32 = 2;
pub(crate) const SYMBOL_TYPE_GO_PCLNTAB: u32 = 4;

pub struct ElfSymbol {
    start: u64,
    end: u64,
    name_buf: [u8; 1024],
    name_len: usize,
}

impl ElfSymbol {
    pub fn new() -> Self {
        ElfSymbol {
            start: 0,
            end: 0,
            name_buf: [0; 1024],
            name_len: 0,
        }
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    pub fn name(&self) -> &str {
        get_str(&self.name_buf[0..self.name_len])
    }

    pub fn demangle(&self) -> Option<String> {
        demangle_symbol(self.name())
    }
}

pub struct SectionMetadata {
    pub sec_type: u32,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub entry_size: u64,
    pub name_offset: u64,
    pub link: u32,
    pub class: u8,
}

impl SectionMetadata {
    pub fn name_equals(
        &self,
        reader: &mut (impl Read + Seek),
        name: &str,
        buf: &mut Vec<u8>) -> Result<bool, Error> {
        reader.seek(SeekFrom::Start(self.name_offset))?;
        buf.resize(name.len() + 1, 0);
        reader.read_exact(buf)?;

        /* Ensure what we read ends with a null */
        if buf[name.len()] != 0 {
            return Ok(false);
        }

        /* Only compare up to name len */
        let buf = &buf[..name.len()];
        Ok(buf == name.as_bytes())
    }
}

pub struct ElfLoadHeader {
    p_offset: u64,
    p_vaddr: u64,
}

impl ElfLoadHeader {
    pub fn new (
        p_offset: u64,
        p_vaddr: u64) -> Self {
        Self {
            p_offset,
            p_vaddr,
        }
    }

    pub fn default() -> Self {
        Self::new(0, 0)
    }

    pub fn p_offset(&self) -> u64 {
        self.p_offset
    }

    pub fn p_vaddr(&self) -> u64 {
        self.p_vaddr
    }

}

pub struct ElfSymbolIterator<'a> {
    phantom: PhantomData<&'a ()>,
    reader: BufReader<File>,
    
    sections: Vec<SectionMetadata>,
    section_index: usize,
    section_offsets: Vec<u64>,
    section_str_offset: u64,

    load_header: ElfLoadHeader,
    system_page_mask: u64,

    entry_count: u64,
    entry_index: u64,

    reset: bool,
}

impl<'a> ElfSymbolIterator<'a> {
    pub fn new(file: File, load_header: ElfLoadHeader, system_page_size: u64) -> Self {
        Self {
            phantom: std::marker::PhantomData,
            reader: BufReader::new(file),
            sections: Vec::new(),
            section_index: 0,
            section_offsets: Vec::new(),
            section_str_offset: 0,
            load_header: load_header,
            system_page_mask: crate::page_size_to_mask(system_page_size),
            entry_count: 0,
            entry_index: 0,
            reset: true,
        }
    }

    pub fn reset(&mut self) {
        let clear = |iterator: &mut ElfSymbolIterator| {
            iterator.sections.clear();
            iterator.section_index = 0;
            iterator.section_offsets.clear();
            iterator.section_str_offset = 0;
            iterator.entry_count = 0;
            iterator.entry_index = 0;
            iterator.reset = true;
        };
        
        // Clear prior to the call to initialize.
        clear(self);

        // Initialize and re-clear if initialization fails.
        if self.initialize().is_err() {
            warn!("ElfSymbolIterator initialization failed during reset");
            clear(self);
        }
    }

    fn initialize(&mut self) -> Result<(), Error> {
        // Seek to the beginning of the file in-case this is not the first call to initialize.
        self.reader.seek(SeekFrom::Start(0))?;

        // Read the section metadata and store it.
        get_section_metadata(&mut self.reader, None, SHT_SYMTAB, &mut self.sections)?;
        get_section_metadata(&mut self.reader, None, SHT_DYNSYM, &mut self.sections)?;
        get_section_offsets(&mut self.reader, None, &mut self.section_offsets)?;

        debug!("ElfSymbolIterator initialized: section_count={}", self.sections.len());
        Ok(())
    }

    pub fn next(
        &mut self,
        symbol: &mut ElfSymbol) -> bool {
        if self.section_index >= self.sections.len() {
            return false;
        }

        let mut section = &self.sections[self.section_index];

        loop {
            // Load the next section if necessary.
            if self.entry_index >= self.entry_count {
                // Load the next section.
                if self.reset {
                    // Don't increment the section_index the first time through after a reset.
                    self.reset = false;
                }
                else {
                    self.section_index+=1;
                }

                if self.section_index >= self.sections.len() {
                    return false;
                }

                section = &self.sections[self.section_index];
                if section.link < self.section_offsets.len() as u32 {
                    self.section_str_offset = self.section_offsets[section.link as usize];
                }
                else {
                    self.section_str_offset = 0;
                }

                self.entry_count = section.size / section.entry_size;
                self.entry_index = 0;

                // If the new section doesn't contain any symbols, skip it.
                if self.entry_index >= self.entry_count {
                    continue;
                }
            }

            // If we get here, we have at least one entry in the current section.
            let result = get_symbol(
                &mut self.reader,
                section,
                self.entry_index,
                self.section_str_offset,
                &self.load_header,
                self.system_page_mask,
                symbol);

            self.entry_index+=1;

            if result.is_ok() {
                return true;
            }
        }
    }
}

pub fn is_elf_file(
    reader: &mut (impl Read + Seek)) -> std::io::Result<bool> {
    let mut buf: [u8; 4] = [0; 4];
    reader.seek(SeekFrom::Start(0))?;
    reader.read_exact(&mut buf)?;
    Ok(buf == ELF_MAGIC)
}

pub fn get_str(
    buffer: &[u8]) -> &str {
    let mut i = 0;

    for b in buffer {
        if *b == 0 {
            break;
        }

        i += 1;
    }

    match std::str::from_utf8(&buffer[0..i]) {
        Ok(val) => { val },
        _ => { "" },
    }
}

fn get_symbols32(
    reader: &mut (impl Read + Seek),
    load_header: &ElfLoadHeader,
    system_page_mask : u64,
    metadata: &SectionMetadata,
    count: u64,
    str_offset: u64,
    mut callback: impl FnMut(&ElfSymbol)) -> Result<(), Error> {
    let mut symbol = ElfSymbol::new();

    for i in 0..count {
        if get_symbol32(
            reader,
            metadata,
            i,
            str_offset,
            load_header,
            system_page_mask,
            &mut symbol).is_err() {
                continue;
        }

        callback(&symbol);
    }

    Ok(())
}

pub(crate) fn symbol_rva(
    value: u64,
    load_header: &ElfLoadHeader,
    system_page_mask: u64) -> u64 {

    // The load header values must be page aligned.
    assert!(load_header.p_vaddr() & system_page_mask == load_header.p_vaddr());
    assert!(load_header.p_offset() & system_page_mask == load_header.p_offset());
    (value - load_header.p_vaddr()) + load_header.p_offset()
}

fn get_symbol32(
    reader: &mut (impl Read + Seek),
    metadata: &SectionMetadata,
    sym_index: u64,
    str_offset: u64,
    load_header: &ElfLoadHeader,
    system_page_mask: u64,
    symbol: &mut ElfSymbol) -> Result<(), Error> {
    let mut sym = ElfSymbol32::default();
    let pos = metadata.offset + (sym_index * metadata.entry_size);
    debug!("Reading symbol32: sym_index={}, offset={:#x}", sym_index, pos);
    reader.seek(SeekFrom::Start(pos))?;
    read_symbol32(reader, &mut sym)?;

    if !sym.is_function() || sym.st_value == 0 || sym.st_size == 0 {
        trace!(
            "Skipping invalid symbol32: sym_index={}, is_function={}, st_value={:#x}, st_size={}", 
            sym_index, sym.is_function(), sym.st_value, sym.st_size
        );
        return Err(Error::new(std::io::ErrorKind::InvalidData, "Invalid symbol"));
    }

    symbol.start = symbol_rva(sym.st_value as u64, load_header, system_page_mask);
    symbol.end = symbol.start + (sym.st_size as u64 - 1);
    let str_pos = sym.st_name as u64 + str_offset;

    debug!("Reading symbol32 name: str_pos={:#x}", str_pos);
    reader.seek(SeekFrom::Start(str_pos))?;
    symbol.name_len = reader.read(&mut symbol.name_buf[..])?;

    Ok(())
}

fn get_symbols64(
    reader: &mut (impl Read + Seek),
    load_header: &ElfLoadHeader,
    system_page_mask: u64,
    metadata: &SectionMetadata,
    count: u64,
    str_offset: u64,
    mut callback: impl FnMut(&ElfSymbol)) -> Result<(), Error> {
    let mut symbol = ElfSymbol::new();

    for i in 0..count {
        if get_symbol64(
            reader,
            metadata,
            i,
            str_offset,
            load_header,
            system_page_mask,
            &mut symbol).is_err() {
                continue;
        }

        callback(&symbol);
    }

    Ok(())
}

fn get_symbol64(
    reader: &mut (impl Read + Seek),
    metadata: &SectionMetadata,
    sym_index: u64,
    str_offset: u64,
    load_header: &ElfLoadHeader,
    system_page_mask: u64,
    symbol: &mut ElfSymbol) -> Result<(), Error> {
    let mut sym = ElfSymbol64::default();
    let pos = metadata.offset + (sym_index * metadata.entry_size);
    debug!("Reading symbol64: sym_index={}, offset={:#x}", sym_index, pos);
    reader.seek(SeekFrom::Start(pos))?;
    read_symbol64(reader, &mut sym)?;

    if !sym.is_function() || sym.st_value == 0 || sym.st_size == 0 {
        trace!(
            "Skipping invalid symbol64: sym_index={}, is_function={}, st_value={:#x}, st_size={}", 
            sym_index, sym.is_function(), sym.st_value, sym.st_size
        );
        return Err(Error::new(std::io::ErrorKind::InvalidData, "Invalid symbol"));
    }

    symbol.start = symbol_rva(sym.st_value as u64, load_header, system_page_mask);
    symbol.end = symbol.start + (sym.st_size - 1);
    let str_pos = sym.st_name as u64 + str_offset;

    debug!("Reading symbol64 name: str_pos={:#x}", str_pos);
    reader.seek(SeekFrom::Start(str_pos))?;
    symbol.name_len = reader.read(&mut symbol.name_buf)?;

    Ok(())
}


fn demangle_symbol(
    mangled_name: &str) -> Option<String> {
    let mut result = None;

    if mangled_name.len() > 2 && &mangled_name[0..2] == "_Z" {
        // C++ mangled name.  Demangle using cpp_demangle crate.
        if let Ok(symbol) = Symbol::new(mangled_name) {
            let options = DemangleOptions::new();
            if let Ok(demangled_name) = symbol.demangle(&options) {
                result = Some(demangled_name);
            }
        }
    }
    else if mangled_name.len() > 2  && &mangled_name[0..2] == "_R" {
        // Rust mangled name.  Demangle using rustc-demangle crate.
        match try_demangle(mangled_name) {
            Ok(demangler) => {
                // Remove the hash from the demangled symbol.
                result = Some(format!("{:#}", demangler));
            }
            Err(_) => {
                result = None;
            }
        }
    }

    result
}

pub fn get_symbols(
    reader: &mut (impl Read + Seek),
    load_header: &ElfLoadHeader,
    system_page_mask: u64,
    metadata: &Vec<SectionMetadata>,
    mut callback: impl FnMut(&ElfSymbol)) -> Result<(), Error> {
    let mut offsets: Vec<u64> = Vec::new();
    let mut sections: Vec<SectionMetadata> = Vec::new();

    /* We need all sections to find the correct address */
    enum_section_metadata(reader, None, None, &mut sections)?;

    get_section_offsets(reader, None, &mut offsets)?;

    for m in metadata {
        let count = m.size / m.entry_size;
        let mut str_offset = 0u64;

        if m.link < offsets.len() as u32 {
            str_offset = offsets[m.link as usize];
        }

        debug!("Processing section: type={}, offset={:#x}, size={}, entry_count={}", m.sec_type, m.offset, m.size, count);

        match m.class {
            ELFCLASS32 => {
                get_symbols32(reader, load_header, system_page_mask, m, count, str_offset, &mut callback)?;
            },
            ELFCLASS64 => {
                get_symbols64(reader, load_header, system_page_mask, m, count, str_offset, &mut callback)?;
            },
            _ => {
                warn!("Unknown ELF class: class={}", m.class);
            },
        }
    }

    Ok(())
}

pub fn get_symbol(
    reader: &mut (impl Read + Seek),
    metadata: &SectionMetadata,
    sym_index: u64,
    str_offset: u64,
    load_header: &ElfLoadHeader,
    system_page_mask : u64,
    symbol: &mut ElfSymbol) -> Result<(), Error> {
    match metadata.class {
        ELFCLASS32 => {
            return get_symbol32(reader, metadata, sym_index, str_offset, load_header, system_page_mask, symbol);
        },
        ELFCLASS64 => {
            return get_symbol64(reader, metadata, sym_index, str_offset, load_header, system_page_mask, symbol);
        }
        _ => {
            warn!("Unknown ELF class for symbol: class={}", metadata.class);
        },
    }
    Ok(())
}

pub fn get_section_offsets(
    reader: &mut (impl Read + Seek),
    ident: Option<&[u8]>,
    offsets: &mut Vec<u64>) -> Result<(), Error> {
    let class: u8;

    match ident {
        Some(slice) => {
            class = slice[EI_CLASS];
            reader.seek(SeekFrom::Start(16))?;
        },
        None => {
            reader.seek(SeekFrom::Start(0))?;
            let slice = get_ident(reader)?;
            class = slice[EI_CLASS];
        },
    }

    match class {
        ELFCLASS32 => {
            get_section_offsets32(reader, offsets)
        },
        ELFCLASS64 => {
            get_section_offsets64(reader, offsets)
        },
        _ => {
            warn!("Unknown ELF class for section offsets: class={}", class);
            Ok(())
        },
    }
}

pub fn get_section_metadata(
    reader: &mut (impl Read + Seek),
    ident: Option<&[u8]>,
    sec_type: u32,
    metadata: &mut Vec<SectionMetadata>) -> Result<(), Error> {
    enum_section_metadata(
        reader,
        ident,
        Some(sec_type),
        metadata)
}

pub fn enum_section_metadata(
    reader: &mut (impl Read + Seek),
    ident: Option<&[u8]>,
    sec_type: Option<u32>,
    metadata: &mut Vec<SectionMetadata>) -> Result<(), Error> {
    let class: u8;

    match ident {
        Some(slice) => {
            class = slice[EI_CLASS];
            reader.seek(SeekFrom::Start(16))?;
        },
        None => {
            reader.seek(SeekFrom::Start(0))?;
            let slice = get_ident(reader)?;
            class = slice[EI_CLASS];
        },
    }

    match class {
        ELFCLASS32 => {
            get_section_metadata32(
                reader, sec_type, metadata)
        },
        ELFCLASS64 => {
            get_section_metadata64(
                reader, sec_type, metadata)
        },
        _ => {
            warn!("Unknown ELF class for section metadata: class={}", class);
            Ok(())
        },
    }
}

pub fn read_section_name<'a>(
    reader: &mut (impl Read + Seek),
    section: &SectionMetadata,
    section_offsets: &[u64],
    buf: &'a mut [u8]) -> Result<&'a str, Error> {
    let mut str_offset = 0u64;

    if section.link < section_offsets.len() as u32 {
        str_offset = section_offsets[section.link as usize];
    }

    let str_pos = section.name_offset + str_offset;
    debug!("Reading section name: str_pos={:#x}", str_pos);
    reader.seek(SeekFrom::Start(str_pos))?;

    let mut name = "";
    if let Ok(bytes_read) = reader.read(buf) {
        name = get_str(&buf[0..bytes_read]);
    }

    Ok(name)
}

pub fn get_build_id<'a>(
    reader: &mut (impl Read + Seek),
    buf: &'a mut [u8; 20]) -> Result<Option<&'a [u8; 20]>, Error> {
    let mut sections = Vec::new();
    let mut section_offsets = Vec::new();

    get_section_offsets(reader, None, &mut section_offsets)?;
    get_section_metadata(reader, None, SHT_NOTE, &mut sections)?;

    read_build_id(reader, &sections, &section_offsets, buf)
}

fn seek_to_note_data(
    reader: &mut (impl Read + Seek),
    section: &SectionMetadata) -> Result<usize, Error> {
    reader.seek(SeekFrom::Start(section.offset))?;

    let mut buf: [u8; 4] = [0; 4];
    reader.read_exact(&mut buf[0..])?;
    let name_len = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
    reader.read_exact(&mut buf[0..])?;
    let desc_len = u32::from_ne_bytes(buf[0..4].try_into().unwrap());

    /* Align to 4 bytes */
    let name_len = (name_len + 3) & !3;

    /* Skip over n_type field (4 bytes) and name */
    reader.seek(SeekFrom::Current((4 + name_len).into()))?;

    Ok(desc_len as usize)
}

pub fn read_build_id<'a>(
    reader: &mut (impl Read + Seek),
    sections: &Vec<SectionMetadata>,
    section_offsets: &Vec<u64>,
    buf: &'a mut [u8; 20]) -> Result<Option<&'a [u8; 20]>, Error> {
    for section in sections {
        let mut name_buf: [u8; 1024] = [0; 1024];
        if let Ok(name) = read_section_name(reader, section, section_offsets, &mut name_buf) {
            if name == ".note.gnu.build-id" {
                debug!("Found build-id section: offset={:#x}, size={}", section.offset, section.size);
                let _len = seek_to_note_data(reader, section)?;
                reader.read_exact(&mut buf[0..])?;
                info!("Build-id retrieved successfully");
                return Ok(Some(buf));
            }
        }
    }

    info!("Build-id not found in ELF file");
    Ok(None)
}

pub fn build_id_equals(
    left: &[u8; 20],
    right: &[u8; 20]) -> bool {
    left == right
}

pub fn read_package_metadata(
    reader: &mut (impl Read + Seek),
    sections: &Vec<SectionMetadata>,
    section_offsets: &Vec<u64>,
    buf: &mut Vec<u8>) -> Result<(), Error> {
    for section in sections {
        let mut name_buf: [u8; 1024] = [0; 1024];
        if let Ok(name) = read_section_name(reader, section, section_offsets, &mut name_buf) {
            if name == ".note.package" {
                debug!("Found package metadata section: offset={:#x}, size={}", section.offset, section.size);
                let len = seek_to_note_data(reader, section)?;

                buf.clear();
                buf.resize(len, 0);

                reader.read_exact(&mut buf[0..])?;
                info!("Package metadata retrieved successfully: size={}", len);
                return Ok(());
            }
        }
    }

    info!("No package metadata found: section_count={}", sections.len());
    Err(Error::new(
        std::io::ErrorKind::Other,
        "No metadata found"))
}

pub fn read_debug_link<'a>(
    reader: &mut (impl Read + Seek),
    sections: &Vec<SectionMetadata>,
    section_offsets: &Vec<u64>,
    buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
    for section in sections {
        let mut name_buf: [u8; 1024] = [0; 1024];
        if let Ok(name) = read_section_name(reader, section, section_offsets, &mut name_buf) {
            if name == ".gnu_debuglink" {
                debug!("Found debug link section: offset={:#x}, size={}", section.offset, section.size);
                reader.seek(SeekFrom::Start(section.offset))?;
                reader.read_exact(&mut buf[0..section.size as usize])?;
                info!("Debug link retrieved successfully");
                return Ok(Some(buf));
            }
        }
    }

    info!("Debug link not found in ELF file");
    Ok(None)
}

/// The ELF section name that holds the Go line table when not stripped.
const GO_PCLNTAB_SECTION: &str = ".gopclntab";

/// Returns true if the ELF file contains a `.gopclntab` section.
///
/// Used as a cheap, one-time probe to decide whether a binary carries a Go
/// line table without reading the (potentially large) section contents.
pub(crate) fn has_go_pclntab(
    reader: &mut (impl Read + Seek)) -> bool {
    let mut sections = Vec::new();
    let mut section_offsets = Vec::new();

    if enum_section_metadata(reader, None, None, &mut sections).is_err() {
        return false;
    }
    if get_section_offsets(reader, None, &mut section_offsets).is_err() {
        return false;
    }

    find_section_by_name(reader, &sections, &section_offsets, GO_PCLNTAB_SECTION).is_some()
}

/// Finds the metadata for a section by name, if present.
fn find_section_by_name<'a>(
    reader: &mut (impl Read + Seek),
    sections: &'a [SectionMetadata],
    section_offsets: &[u64],
    name: &str) -> Option<&'a SectionMetadata> {
    for section in sections {
        let mut name_buf: [u8; 256] = [0; 256];
        if let Ok(sec_name) = read_section_name(reader, section, section_offsets, &mut name_buf) {
            if sec_name == name {
                return Some(section);
            }
        }
    }
    None
}

/// Reads the `.gopclntab` section bytes and resolves the Go runtime text start.
///
/// Returns `(pclntab_bytes, text_start)` when the `.gopclntab` section is
/// present, or `None` otherwise. `text_start` is the virtual address of
/// `runtime.text` (the base the line table's PC offsets are relative to), which
/// is **not** always the `.text` section address — for cgo / externally linked
/// binaries the first part of `.text` holds C startup stubs and `runtime.text`
/// is offset past them. It is resolved by priority:
///
/// 1. the `runtime.text` symbol (authoritative; present unless stripped),
/// 2. the pcHeader `textStart` field in the table (set for internally linked
///    binaries; zero/relocated otherwise),
/// 3. the `.text` section address (best-effort fallback).
///
/// The returned function virtual addresses are in the same space as ELF symbol
/// `st_value`, so the caller applies the usual load-header relocation.
pub(crate) fn read_go_pclntab(
    reader: &mut (impl Read + Seek)) -> Option<(Vec<u8>, u64)> {
    let mut sections = Vec::new();
    let mut section_offsets = Vec::new();

    enum_section_metadata(reader, None, None, &mut sections).ok()?;
    get_section_offsets(reader, None, &mut section_offsets).ok()?;

    let pclntab = find_section_by_name(reader, &sections, &section_offsets, GO_PCLNTAB_SECTION)?;
    let pclntab_offset = pclntab.offset;
    let pclntab_size = pclntab.size as usize;
    let pclntab_vaddr = pclntab.address;

    // Optional .text address for the fallback.
    let text_vaddr = find_section_by_name(reader, &sections, &section_offsets, ".text")
        .map(|s| s.address);

    let mut data = vec![0u8; pclntab_size];
    reader.seek(SeekFrom::Start(pclntab_offset)).ok()?;
    reader.read_exact(&mut data).ok()?;

    let text_start = resolve_go_text_start(reader, &data, Some(pclntab_vaddr), text_vaddr)?;

    debug!(
        "read_go_pclntab: pclntab size={} text_start={:#x}",
        pclntab_size, text_start);

    Some((data, text_start))
}

/// Resolves the Go `runtime.text` virtual address (the line table PC base).
///
/// `pclntab_vaddr`, when known, is the virtual address at which the line table
/// is mapped; it is used to look up the PIE relocation that supplies
/// `runtime.text` when the in-table field is unrelocated (zero).
fn resolve_go_text_start(
    reader: &mut (impl Read + Seek),
    pclntab: &[u8],
    pclntab_vaddr: Option<u64>,
    text_vaddr: Option<u64>) -> Option<u64> {
    // 1. The runtime.text symbol is authoritative when present.
    if let Some(value) = find_symbol_value(reader, "runtime.text") {
        if value != 0 {
            return Some(value);
        }
    }

    let ptr_size = if pclntab.len() >= 8 { pclntab[7] as usize } else { 0 };

    // 2. The pcHeader textStart field (offset 8 + 2*ptrSize). Non-zero for
    //    internally linked binaries; zero/relocated for externally linked ones.
    if ptr_size == 4 || ptr_size == 8 {
        let off = 8 + 2 * ptr_size;
        let header_text_start = match ptr_size {
            8 if pclntab.len() >= off + 8 => Some(u64::from_le_bytes(
                pclntab[off..off + 8].try_into().unwrap())),
            4 if pclntab.len() >= off + 4 => Some(u32::from_le_bytes(
                pclntab[off..off + 4].try_into().unwrap()) as u64),
            _ => None,
        };
        if let Some(ts) = header_text_start {
            if ts != 0 {
                return Some(ts);
            }
        }

        // 3. For PIE binaries the field above is zero and relocated at load. The
        //    relocation that targets the field carries runtime.text as its addend.
        if let Some(base) = pclntab_vaddr {
            let field_vaddr = base + off as u64;
            if let Some(addend) = find_relative_reloc_addend(reader, field_vaddr) {
                if addend != 0 {
                    return Some(addend);
                }
            }
        }
    }

    // 4. Fall back to the .text section address.
    text_vaddr
}

/// Finds the addend of an `R_*_RELATIVE` relocation targeting `target_vaddr`.
///
/// Used to recover `runtime.text` for position-independent Go binaries, where
/// the pcHeader `textStart` field is zero on disk and supplied by this
/// relocation at load time.
fn find_relative_reloc_addend(
    reader: &mut (impl Read + Seek),
    target_vaddr: u64) -> Option<u64> {
    let mut sections = Vec::new();
    if get_section_metadata(reader, None, SHT_RELA, &mut sections).is_err() {
        return None;
    }

    // Elf64_Rela: r_offset (u64), r_info (u64), r_addend (i64) = 24 bytes.
    const RELA_SIZE: usize = 24;
    let mut buf: Vec<u8> = Vec::new();

    for section in &sections {
        // Only 64-bit RELA is handled (sufficient for the supported targets).
        if section.class != ELFCLASS64 || section.entry_size as usize != RELA_SIZE {
            continue;
        }
        if section.size == 0 {
            continue;
        }

        buf.resize(section.size as usize, 0);
        if reader.seek(SeekFrom::Start(section.offset)).is_err() {
            continue;
        }
        if reader.read_exact(&mut buf).is_err() {
            continue;
        }

        let count = buf.len() / RELA_SIZE;
        for i in 0..count {
            let base = i * RELA_SIZE;
            let r_offset = u64::from_le_bytes(buf[base..base + 8].try_into().unwrap());
            if r_offset != target_vaddr {
                continue;
            }
            let r_info = u64::from_le_bytes(buf[base + 8..base + 16].try_into().unwrap());
            let r_type = (r_info & 0xffff_ffff) as u32;
            if r_type == R_X86_64_RELATIVE || r_type == R_AARCH64_RELATIVE {
                let r_addend = i64::from_le_bytes(buf[base + 16..base + 24].try_into().unwrap());
                return Some(r_addend as u64);
            }
        }
    }

    None
}


/// Finds the value (`st_value`) of a named ELF symbol in `.symtab` or `.dynsym`.
///
/// Unlike the function-symbol iterator this matches symbols of any type (e.g.
/// `runtime.text`, which is not `STT_FUNC`). Returns the first match.
fn find_symbol_value(
    reader: &mut (impl Read + Seek),
    name: &str) -> Option<u64> {
    let mut sections = Vec::new();
    let mut section_offsets = Vec::new();

    get_section_offsets(reader, None, &mut section_offsets).ok()?;
    get_section_metadata(reader, None, SHT_SYMTAB, &mut sections).ok()?;
    get_section_metadata(reader, None, SHT_DYNSYM, &mut sections).ok()?;

    let target = name.as_bytes();
    let mut name_buf = vec![0u8; target.len() + 1];

    for section in &sections {
        if section.entry_size == 0 {
            continue;
        }
        let strtab_off = match section_offsets.get(section.link as usize) {
            Some(off) => *off,
            None => continue,
        };

        let count = section.size / section.entry_size;
        for i in 0..count {
            let entry_pos = section.offset + i * section.entry_size;
            if reader.seek(SeekFrom::Start(entry_pos)).is_err() {
                break;
            }

            // st_name is the first 4 bytes in both ELF32 and ELF64.
            let mut name_off_buf = [0u8; 4];
            if reader.read_exact(&mut name_off_buf).is_err() {
                break;
            }
            let st_name = u32::from_le_bytes(name_off_buf) as u64;

            // st_value: ELF64 at entry+8 (u64); ELF32 at entry+4 (u32).
            let st_value = match section.class {
                ELFCLASS64 => {
                    if reader.seek(SeekFrom::Start(entry_pos + 8)).is_err() {
                        break;
                    }
                    let mut v = [0u8; 8];
                    if reader.read_exact(&mut v).is_err() {
                        break;
                    }
                    u64::from_le_bytes(v)
                }
                _ => {
                    if reader.seek(SeekFrom::Start(entry_pos + 4)).is_err() {
                        break;
                    }
                    let mut v = [0u8; 4];
                    if reader.read_exact(&mut v).is_err() {
                        break;
                    }
                    u32::from_le_bytes(v) as u64
                }
            };

            // Compare the name (exact length, NUL-terminated).
            if reader.seek(SeekFrom::Start(strtab_off + st_name)).is_err() {
                continue;
            }
            if reader.read_exact(&mut name_buf).is_err() {
                continue;
            }
            if name_buf[target.len()] == 0 && &name_buf[..target.len()] == target {
                return Some(st_value);
            }
        }
    }

    None
}

/// Returns true if the ELF file carries a Go build-info marker section.
///
/// `.go.buildinfo` (and `.note.go.buildid`) are allocated and survive `strip`,
/// so they remain even when the `.gopclntab` section header has been removed.
/// This is used as a cheap gate before attempting the (more expensive) scan to
/// recover a stripped line table: non-Go binaries lack these markers and never
/// pay for the scan.
pub(crate) fn has_go_build_info(
    reader: &mut (impl Read + Seek)) -> bool {
    let mut sections = Vec::new();
    let mut section_offsets = Vec::new();

    if enum_section_metadata(reader, None, None, &mut sections).is_err() {
        return false;
    }
    if get_section_offsets(reader, None, &mut section_offsets).is_err() {
        return false;
    }

    find_section_by_name(reader, &sections, &section_offsets, ".go.buildinfo").is_some()
        || find_section_by_name(reader, &sections, &section_offsets, ".note.go.buildid").is_some()
}

/// Magic prefix bytes shared by the supported pclntab versions: the low byte
/// (`0xf0`/`0xf1`) varies, the upper three bytes are `0xff`.
const PCLNTAB_MAGIC_GO118: [u8; 4] = [0xf0, 0xff, 0xff, 0xff];
const PCLNTAB_MAGIC_GO120: [u8; 4] = [0xf1, 0xff, 0xff, 0xff];

/// Recovers a Go line table whose `.gopclntab` section header has been stripped.
///
/// Scans the read-only `PT_LOAD` segments for a supported pclntab magic,
/// validates and parses each candidate, and returns the first table that parses
/// cleanly together with its resolved `runtime.text`. Only 64-bit ELF is
/// supported; returns `None` otherwise (callers fall back to ELF symbols).
///
/// Callers should gate this behind [`has_go_build_info`] and the absence of a
/// `.gopclntab` section so non-Go binaries never incur the scan.
pub(crate) fn recover_go_pclntab(
    reader: &mut (impl Read + Seek)) -> Option<(Vec<u8>, u64)> {
    use crate::ruwind::go_pclntab::GoPclnTab;

    // Determine class; only 64-bit recovery is supported.
    reader.seek(SeekFrom::Start(0)).ok()?;
    let ident = get_ident(reader).ok()?;
    if ident[..4] != ELF_MAGIC || ident[EI_CLASS] != ELFCLASS64 {
        return None;
    }

    // Read the ELF header for program-header table location. The ElfHeader64
    // struct begins after the 16-byte e_ident, so seek past it first.
    reader.seek(SeekFrom::Start(16)).ok()?;
    let mut header = ElfHeader64::default();
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                size_of::<ElfHeader64>())).ok()?;
    }

    // Optional .text address (fallback for text_start resolution).
    let text_vaddr = {
        let mut sections = Vec::new();
        let mut section_offsets = Vec::new();
        enum_section_metadata(reader, None, None, &mut sections).ok();
        get_section_offsets(reader, None, &mut section_offsets).ok();
        find_section_by_name(reader, &sections, &section_offsets, ".text").map(|s| s.address)
    };

    // Collect read-only PT_LOAD segments (where the line table lives).
    let mut segments: Vec<(u64, u64, u64)> = Vec::new(); // (p_offset, p_filesz, p_vaddr)
    let mut ph_offset = header.e_phoff;
    for _ in 0..header.e_phnum {
        reader.seek(SeekFrom::Start(ph_offset)).ok()?;
        let mut ph = ElfProgramHeader64::default();
        if get_program_header64(reader, &mut ph).is_err() {
            break;
        }
        ph_offset += header.e_phentsize as u64;

        // Loadable, non-executable segment (the line table is read-only data,
        // but on PIE binaries it lives in a writable data-rel-ro segment, so we
        // only exclude executable segments here).
        if ph.p_type == PT_LOAD
            && (ph.p_flags & PF_X) == 0
            && ph.p_filesz > 0 {
            segments.push((ph.p_offset, ph.p_filesz, ph.p_vaddr));
        }
    }

    for (seg_offset, seg_filesz, seg_vaddr) in segments {
        let mut bytes = vec![0u8; seg_filesz as usize];
        if reader.seek(SeekFrom::Start(seg_offset)).is_err() {
            continue;
        }
        if reader.read_exact(&mut bytes).is_err() {
            continue;
        }

        // Scan for a candidate magic.
        let mut i = 0usize;
        while i + 8 <= bytes.len() {
            let b = bytes[i];
            if (b == 0xf0 || b == 0xf1)
                && bytes[i..i + 4] == (if b == 0xf0 { PCLNTAB_MAGIC_GO118 } else { PCLNTAB_MAGIC_GO120 })
                // Header bytes 4,5 must be zero; minLC and ptrSize must be sane.
                && bytes[i + 4] == 0
                && bytes[i + 5] == 0
                && matches!(bytes[i + 6], 1 | 2 | 4)
                && matches!(bytes[i + 7], 4 | 8) {

                let candidate_vaddr = seg_vaddr + i as u64;
                let slice = bytes[i..].to_vec();
                let text_start = resolve_go_text_start(reader, &slice, Some(candidate_vaddr), text_vaddr)
                    .unwrap_or(0);

                if let Some(tab) = GoPclnTab::parse(slice, text_start) {
                    // Sanity-check: a real table has many functions whose first
                    // and last entries decode to non-empty names.
                    if tab.len() > 16
                        && tab.func(0).map(|(_, _, n)| !n.is_empty()).unwrap_or(false)
                        && tab.func(tab.len() - 1).map(|(_, _, n)| !n.is_empty()).unwrap_or(false) {
                        debug!(
                            "recover_go_pclntab: recovered {} funcs at vaddr={:#x} text_start={:#x}",
                            tab.len(), candidate_vaddr, text_start);
                        // Return the recovered table bytes; parse consumed the
                        // first copy, so produce a fresh one for the caller.
                        return Some((bytes[i..].to_vec(), text_start));
                    }
                }
            }
            i += 1;
        }
    }

    None
}

pub fn get_load_header(
    reader: &mut (impl Read + Seek)) -> Result<ElfLoadHeader, Error> {
    reader.seek(SeekFrom::Start(0))?;
    let slice = get_ident(reader)?;
    if slice[..4] != ELF_MAGIC {
        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "not an ELF file"));
    }
    let class = slice[EI_CLASS];
    match class {
        ELFCLASS32 => {
            return get_load_header32(reader);

        },
        ELFCLASS64 => {
            return get_load_header64(reader);
        },
        _ => {
            warn!("Unknown ELF class for load header: class={}", class);
            return Ok(ElfLoadHeader::default());
        }
    }
}

const EI_CLASS: usize = 4;

const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

const STT_FUNC: u8 = 2;

const PT_LOAD: u32 = 1;

const PF_X: u32 = 1;

type Elf32Addr = u32;
type Elf32Off = u32;
type Elf64Addr = u64;
type Elf64Off = u64;
type ElfHalf = u16;
type ElfWord = u32;
type ElfXWord = u64;

#[repr(C)]
#[derive(Default)]
struct ElfHeader32 {
    e_type: ElfHalf,
    e_machine: ElfHalf,
    e_version: ElfWord,
    e_entry: Elf32Addr,
    e_phoff: Elf32Off,
    e_shoff: Elf32Off,
    e_flags: ElfWord,
    e_ehsize: ElfHalf,
    e_phentsize: ElfHalf,
    e_phnum: ElfHalf,
    e_shentsize: ElfHalf,
    e_shnum: ElfHalf,
    e_shstrndx: ElfHalf,
}

#[repr(C)]
#[derive(Default)]
struct ElfHeader64 {
    e_type: ElfHalf,
    e_machine: ElfHalf,
    e_version: ElfWord,
    e_entry: Elf64Addr,
    e_phoff: Elf64Off,
    e_shoff: Elf64Off,
    e_flags: ElfWord,
    e_ehsize: ElfHalf,
    e_phentsize: ElfHalf,
    e_phnum: ElfHalf,
    e_shentsize: ElfHalf,
    e_shnum: ElfHalf,
    e_shstrndx: ElfHalf,
}

#[repr(C)]
#[derive(Default)]
struct ElfProgramHeader32 {
    p_type: ElfWord,
    p_offset: Elf32Off,
    p_vaddr: Elf32Addr,
    p_paddr: Elf32Addr,
    p_filesz: ElfWord,
    p_memsz: ElfWord,
    p_flags: ElfWord,
    p_align: ElfWord,
}

#[repr(C)]
#[derive(Default)]
struct ElfProgramHeader64 {
    p_type: ElfWord,
    p_flags: ElfWord,
    p_offset: Elf64Off,
    p_vaddr: Elf64Addr,
    p_paddr: Elf64Addr,
    p_filesz: Elf64Off,
    p_memsz: Elf64Off,
    p_align: Elf64Off,
}

#[repr(C)]
#[derive(Default)]
struct ElfSectionHeader32 {
    sh_name: ElfWord,
    sh_type: ElfWord,
    sh_flags: ElfWord,
    sh_addr: Elf32Addr,
    sh_offset: Elf32Off,
    sh_size: ElfWord,
    sh_link: ElfWord,
    sh_info: ElfWord,
    sh_addralign: ElfWord,
    sh_entsize: ElfWord,
}

#[repr(C)]
#[derive(Default)]
struct ElfSectionHeader64 {
    sh_name: ElfWord,
    sh_type: ElfWord,
    sh_flags: ElfXWord,
    sh_addr: Elf64Addr,
    sh_offset: Elf64Off,
    sh_size: ElfXWord,
    sh_link: ElfWord,
    sh_info: ElfWord,
    sh_addralign: ElfXWord,
    sh_entsize: ElfXWord,
}

#[repr(C)]
#[derive(Default)]
struct ElfSymbol32 {
    st_name: ElfWord,
    st_value: Elf32Addr,
    st_size: ElfWord,
    st_info: u8,
    st_other: u8,
    st_shndx: ElfHalf,
}

impl ElfSymbol32 {
    const fn is_function(&self) -> bool {
        self.st_info & 0xf == STT_FUNC
    }
}

#[repr(C)]
#[derive(Default)]
struct ElfSymbol64 {
    st_name: ElfWord,
    st_info: u8,
    st_other: u8,
    st_shndx: ElfHalf,
    st_value: Elf64Addr,
    st_size: ElfXWord,
}

impl ElfSymbol64 {
    const fn is_function(&self) -> bool {
        self.st_info & 0xf == STT_FUNC
    }
}

fn get_ident(
    reader: &mut (impl Read + Seek)) -> Result<[u8; 16], Error> {
    let mut slice: [u8; 16] = [0; 16];

    reader.read_exact(&mut slice)?;

    Ok(slice)
}

fn get_section_header32(
    reader: &mut (impl Read + Seek),
    section: &mut ElfSectionHeader32) -> Result<(), Error> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                section as *mut _ as *mut u8,
                size_of::<ElfSectionHeader32>()))?;
    }

    Ok(())
}

fn get_section_header64(
    reader: &mut (impl Read + Seek),
    section: &mut ElfSectionHeader64) -> Result<(), Error> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                section as *mut _ as *mut u8,
                size_of::<ElfSectionHeader64>()))?;
    }

    Ok(())
}

fn get_program_header32(
    reader: &mut (impl Read + Seek),
    header: &mut ElfProgramHeader32) -> Result<(), Error> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                header as *mut _ as *mut u8,
                size_of::<ElfProgramHeader32>()))?;
    }

    Ok(())
}

fn get_program_header64(
    reader: &mut (impl Read + Seek),
    header: &mut ElfProgramHeader64) -> Result<(), Error> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                header as *mut _ as *mut u8,
                size_of::<ElfProgramHeader64>()))?;
    }

    Ok(())
}

fn read_symbol32(
    reader: &mut (impl Read + Seek),
    sym: &mut ElfSymbol32) -> Result<(), Error> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                sym as *mut _ as *mut u8,
                size_of::<ElfSymbol32>()))?;
    }

    Ok(())
}

fn read_symbol64(
    reader: &mut (impl Read + Seek),
    sym: &mut ElfSymbol64) -> Result<(), Error> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                sym as *mut _ as *mut u8,
                size_of::<ElfSymbol64>()))?;
    }

    Ok(())
}

fn get_section_offsets32(
    reader: &mut (impl Read + Seek),
    offsets: &mut Vec<u64>) -> Result<(), Error> {
    let mut header: ElfHeader32;
    let mut sec: ElfSectionHeader32;

    unsafe {
        header = zeroed();
        sec = zeroed();

        reader.read_exact(
            slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                size_of::<ElfHeader32>()))?;
    }

    let mut sec_count = header.e_shnum as u32;
    let mut sec_offset = header.e_shoff as u64;

    reader.seek(SeekFrom::Start(sec_offset))?;
    get_section_header32(reader, &mut sec)?;

    if sec_count == 0 {
        sec_count = sec.sh_size;
        sec_offset += header.e_shentsize as u64;
        reader.seek(SeekFrom::Start(sec_offset))?;
        get_section_header32(reader, &mut sec)?;
    }

    for i in 0..sec_count {
        if i > 0 {
            sec_offset += header.e_shentsize as u64;
            reader.seek(SeekFrom::Start(sec_offset))?;
            get_section_header32(reader, &mut sec)?;
        }

        offsets.push(sec.sh_offset as u64);
    }

    Ok(())
}

fn get_section_offsets64(
    reader: &mut (impl Read + Seek),
    offsets: &mut Vec<u64>) -> Result<(), Error> {
    let mut header: ElfHeader64;
    let mut sec: ElfSectionHeader64;

    unsafe {
        header = zeroed();
        sec = zeroed();

        reader.read_exact(
            slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                size_of::<ElfHeader64>()))?;
    }

    let mut sec_count = header.e_shnum as u32;
    let mut sec_offset = header.e_shoff;

    reader.seek(SeekFrom::Start(sec_offset))?;
    get_section_header64(reader, &mut sec)?;

    if sec_count == 0 {
        sec_count = sec.sh_size as u32;
        sec_offset += header.e_shentsize as u64;
        reader.seek(SeekFrom::Start(sec_offset))?;
        get_section_header64(reader, &mut sec)?;
    }

    for i in 0..sec_count {
        if i > 0 {
            sec_offset += header.e_shentsize as u64;
            reader.seek(SeekFrom::Start(sec_offset))?;
            get_section_header64(reader, &mut sec)?;
        }

        offsets.push(sec.sh_offset);
    }

    Ok(())
}

fn get_section_metadata32(
    reader: &mut (impl Read + Seek),
    sec_type: Option<u32>,
    metadata: &mut Vec<SectionMetadata>) -> Result<(), Error> {
    let mut header: ElfHeader32;
    let mut sec: ElfSectionHeader32;

    unsafe {
        header = zeroed();
        sec = zeroed();

        reader.read_exact(
            slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                size_of::<ElfHeader32>()))?;
    }

    let mut sec_count = header.e_shnum as u32;
    let mut sec_offset = header.e_shoff as u64;

    reader.seek(SeekFrom::Start(sec_offset))?;
    get_section_header32(reader, &mut sec)?;

    if sec_count == 0 {
        sec_count = sec.sh_size;
        sec_offset += header.e_shentsize as u64;
        reader.seek(SeekFrom::Start(sec_offset))?;
        get_section_header32(reader, &mut sec)?;
    }

    let mut str_offset: u64 = 0;
    let added_index = metadata.len();

    for i in 0..sec_count {
        if i > 0 {
            sec_offset += header.e_shentsize as u64;
            reader.seek(SeekFrom::Start(sec_offset))?;
            get_section_header32(reader, &mut sec)?;
        }

        if i == header.e_shstrndx as u32 {
            str_offset = sec.sh_offset as u64;
        }

        let wanted = match sec_type {
            Some(sec_type) => { sec.sh_type == sec_type },
            None => { true },
        };

        if wanted {
            let address = sec.sh_addr as u64;
            let offset = sec.sh_offset as u64;
            let size = sec.sh_size as u64;
            let name_offset = sec.sh_name as u64;
            metadata.push(
                SectionMetadata {
                    class: ELFCLASS32,
                    sec_type: sec.sh_type,
                    address,
                    offset,
                    size,
                    entry_size: sec.sh_entsize as u64,
                    name_offset,
                    link: sec.sh_link,
                });
        }
    }

    for m in metadata.iter_mut().skip(added_index) {
        m.name_offset += str_offset;
    }

    Ok(())
}

fn get_section_metadata64(
    reader: &mut (impl Read + Seek),
    sec_type: Option<u32>,
    metadata: &mut Vec<SectionMetadata>) -> Result<(), Error> {
    let mut header: ElfHeader64;
    let mut sec: ElfSectionHeader64;

    unsafe {
        header = zeroed();
        sec = zeroed();

        reader.read_exact(
            slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                size_of::<ElfHeader64>()))?;
    }

    let mut sec_count = header.e_shnum as u32;
    let mut sec_offset = header.e_shoff;

    reader.seek(SeekFrom::Start(sec_offset))?;
    get_section_header64(reader, &mut sec)?;

    if sec_count == 0 {
        sec_count = sec.sh_size as u32;
        sec_offset += header.e_shentsize as u64;
        reader.seek(SeekFrom::Start(sec_offset))?;
        get_section_header64(reader, &mut sec)?;
    }

    let mut str_offset: u64 = 0;
    let added_index = metadata.len();

    for i in 0..sec_count {
        if i > 0 {
            sec_offset += header.e_shentsize as u64;
            reader.seek(SeekFrom::Start(sec_offset))?;
            get_section_header64(reader, &mut sec)?;
        }

        if i == header.e_shstrndx as u32 {
            str_offset = sec.sh_offset;
        }

        let wanted = match sec_type {
            Some(sec_type) => { sec.sh_type == sec_type },
            None => { true },
        };

        if wanted {
            let address = sec.sh_addr;
            let offset = sec.sh_offset;
            let size = sec.sh_size;
            let name_offset = sec.sh_name as u64;
            metadata.push(
                SectionMetadata {
                    class: ELFCLASS64,
                    sec_type: sec.sh_type,
                    address,
                    offset,
                    size,
                    entry_size: sec.sh_entsize,
                    name_offset,
                    link: sec.sh_link,
                });
        }
    }

    for m in metadata.iter_mut().skip(added_index) {
        m.name_offset += str_offset;
    }

    Ok(())
}

fn get_load_header32(
    reader: &mut (impl Read + Seek)) -> Result<ElfLoadHeader, Error> {
    let mut header = ElfHeader32::default();
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                size_of::<ElfHeader32>()))?;
    }
    let sec_count = header.e_phnum as u32;
    let mut sec_offset = header.e_phoff as u64;
    debug!("Scanning program headers: count={}, offset={:#x}", sec_count, sec_offset);
    let mut pheader = ElfProgramHeader32::default();
    for _ in 0..sec_count {
        reader.seek(SeekFrom::Start(sec_offset))?;
        get_program_header32(reader, &mut pheader)?;
        if pheader.p_type == PT_LOAD &&
            (pheader.p_flags & PF_X) == PF_X {
            info!("Load header retrieved successfully: p_offset={:#x}, p_vaddr={:#x}", pheader.p_offset, pheader.p_vaddr);
            return Ok(ElfLoadHeader::new(
                pheader.p_offset as u64,
                pheader.p_vaddr as u64));
        }
        sec_offset += header.e_phentsize as u64;
    }
    /* No program headers, assume absolute */
    info!("No executable PT_LOAD segment found, using default load header");
    Ok(ElfLoadHeader::default())
}

fn get_load_header64(
    reader: &mut (impl Read + Seek)) -> Result<ElfLoadHeader, Error> {
    let mut header = ElfHeader64::default();
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                size_of::<ElfHeader64>()))?;
    }
    let sec_count = header.e_phnum as u32;
    let mut sec_offset = header.e_phoff as u64;
    debug!("Scanning program headers: count={}, offset={:#x}", sec_count, sec_offset);
    let mut pheader = ElfProgramHeader64::default();
    for _ in 0..sec_count {
        reader.seek(SeekFrom::Start(sec_offset))?;
        get_program_header64(reader, &mut pheader)?;
        if pheader.p_type == PT_LOAD &&
            (pheader.p_flags & PF_X) == PF_X {
            info!("Load header retrieved successfully: p_offset={:#x}, p_vaddr={:#x}", pheader.p_offset, pheader.p_vaddr);
            return Ok(ElfLoadHeader::new(
                pheader.p_offset,
                pheader.p_vaddr));
        }
        sec_offset += header.e_phentsize as u64;
    }
    /* No program headers, assume absolute */
    info!("No executable PT_LOAD segment found, using default load header");
    Ok(ElfLoadHeader::default())
}

#[cfg(test)]
mod tests {
    use crate::ruwind::elf;

    use super::*;
    #[cfg(target_os = "linux")]
    use std::fs::File;

    #[test]
    #[cfg(target_os = "linux")]
    fn symbols() {
        #[cfg(all(target_arch = "x86_64", target_env = "gnu"))]
        let paths = [
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/libc.so.6"
        ];

        #[cfg(all(target_arch = "x86_64", target_env = "musl"))]
        let paths = [
            "/lib/ld-musl-x86_64.so.1",
            "/lib/libc.musl-x86_64.so.1",
            "/usr/lib/libc.musl-x86_64.so.1"
        ];

        #[cfg(all(target_arch = "aarch64", target_env = "gnu"))]
        let paths = [
            "/usr/lib/aarch64-linux-gnu/libc.so.6",
            "/usr/lib/libc.so.6"
        ];

        #[cfg(all(target_arch = "aarch64", target_env = "musl"))]
        let paths = [
            "/lib/ld-musl-aarch64.so.1",
            "/lib/libc.musl-aarch64.so.1",
            "/usr/lib/libc.musl-aarch64.so.1"
        ];

        let mut test_path = None;
        for path in &paths {
            if std::path::Path::new(path).exists() {
                test_path = Some(*path);
                break;
            }
        }

        let path = test_path.expect("No libc found in any of the expected locations");
        let mut file = File::open(path).unwrap();
        let mut sections = Vec::new();

        /* Get load header */
        let load_header = elf::get_load_header(&mut file).unwrap();

        /* Get the system page mask */
        let system_page_mask = system_page_mask();

        /* Get Dyn and Function Symbols */
        get_section_metadata(&mut file, None, SHT_SYMTAB, &mut sections).unwrap();
        get_section_metadata(&mut file, None, SHT_DYNSYM, &mut sections).unwrap();

        let mut found = false;

        get_symbols(&mut file, &load_header, system_page_mask, &sections, |symbol| {
            if symbol.name() == "malloc" {
                println!("{} - {}: {}", symbol.start, symbol.end, symbol.name());
                found = true;
            }
        }).unwrap();

        assert!(found);
    }

    #[cfg(target_os = "linux")]
    fn system_page_mask() -> u64 {
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGESIZE);
            if page_size > 0 {
                !((page_size - 1) as u64)
            } else {
                panic!("Failed to get system page size via sysconf(_SC_PAGESIZE)");
            }
        }
    }

    #[test]
    fn demangle() {
        // C++
        assert_eq!(
            "WriteToBuffer(unsigned char const*, unsigned long, char*&, unsigned long&, unsigned long&, bool&)",
            demangle_symbol("_Z13WriteToBufferPKhmRPcRmS3_Rb").unwrap());
        assert_eq!(
            "SetInternalSystemDirectory()",
            demangle_symbol("_Z26SetInternalSystemDirectoryv").unwrap());
        assert_eq!(
            "FileLoadLock::Create(PEFileListLock*, PEAssembly*, DomainAssembly*)",
            demangle_symbol("_ZN12FileLoadLock6CreateEP14PEFileListLockP10PEAssemblyP14DomainAssembly").unwrap());
        assert_eq!(
            "AppDomain::LoadDomainAssembly(DomainAssembly*, FileLoadLevel)",
            demangle_symbol("_ZN9AppDomain18LoadDomainAssemblyEP14DomainAssembly13FileLoadLevel").unwrap());

        // Rust
        assert_eq!(
            "<std::path::PathBuf>::new",
            demangle_symbol("_RNvMsr_NtCs3ssYzQotkvD_3std4pathNtB5_7PathBuf3newCs15kBYyAo9fc_7mycrate").unwrap());
        assert_eq!(
            "<mycrate::Example as mycrate::Trait>::foo",
            demangle_symbol("_RNvXCs15kBYyAo9fc_7mycrateNtB2_7ExampleNtB2_5Trait3foo").unwrap());

        // Example failure cases.
        assert_eq!(
            None,
            demangle_symbol("Foo"));
        assert_eq!(
            None,
            demangle_symbol("_FunctionName"));
        assert_eq!(
            None,
            demangle_symbol("_ZFoo"));
        assert_eq!(
            None,
            demangle_symbol("_RFoo"));
    }

    #[test]
    fn build_id_equals() {
        let build_id_1: [u8; 20] = [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x61, 0x62,
            0x63, 0x64, 0x65, 0x66,
            0x67, 0x68, 0x69, 0x6A
        ];

        let build_id_2: [u8; 20] = [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x61, 0x62,
            0x63, 0x64, 0x65, 0x66,
            0x67, 0x68, 0x69, 0x6A
        ];

        let build_id_3: [u8; 20] = [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x61, 0x62,
            0x63, 0x64, 0x66, 0x66,
            0x67, 0x68, 0x69, 0x6A
        ];

        assert!(elf::build_id_equals(&build_id_1, &build_id_2));
        assert!(!elf::build_id_equals(&build_id_1, &build_id_3));
    }
}
