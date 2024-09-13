use std::fs::File;
use std::io::{BufReader, Error, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::mem::{zeroed, size_of};
use std::slice;
use cpp_demangle::{DemangleOptions, Symbol};
use rustc_demangle::{demangle, try_demangle};

pub const SHT_PROGBITS: ElfWord = 1;

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

pub struct ElfSymbolIterator<'a> {
    phantom: PhantomData<&'a ()>,
    reader: BufReader<File>,
    va_start: u64,
    
    sections: Vec<SectionMetadata>,
    section_index: usize,
    section_offsets: Vec<u64>,
    section_str_offset: u64,

    entry_count: u64,
    entry_index: u64,

    reset: bool,
}

impl<'a> ElfSymbolIterator<'a> {
    pub fn new(file: File) -> Self {
        Self {
            phantom: std::marker::PhantomData,
            reader: BufReader::new(file),
            va_start: 0,
            sections: Vec::new(),
            section_index: 0,
            section_offsets: Vec::new(),
            section_str_offset: 0,
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
            clear(self);
        }
    }

    fn initialize(&mut self) -> Result<(), Error> {
        // Seek to the beginning of the file in-case this is not the first call to initialize.
        self.reader.seek(SeekFrom::Start(0))?;

        // Read the section metadata and store it.
        get_section_metadata(&mut self.reader, None, 0x2, &mut self.sections)
            .unwrap_or_default();
        get_section_metadata(&mut self.reader, None, 0xb, &mut self.sections)
            .unwrap_or_default();

        self.va_start = get_va_start(&mut self.reader)?;
        get_section_offsets(&mut self.reader, None, &mut self.section_offsets)?;

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
                self.va_start,
                self.section_str_offset,
                symbol);

            self.entry_index+=1;

            if result.is_ok() {
                return true;
            }
        }
    }
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
    metadata: &SectionMetadata,
    count: u64,
    va_start: u64,
    str_offset: u64,
    mut callback: impl FnMut(&ElfSymbol)) -> Result<(), Error> {
    let mut symbol = ElfSymbol::new();
    
    for i in 0..count {
        if get_symbol32(
            reader,
            metadata,
            i,
            va_start,
            str_offset,
            &mut symbol).is_err() {
                continue;
            }

        callback(&symbol);
    }

    Ok(())
}

fn get_symbol32(
    reader: &mut (impl Read + Seek),
    metadata: &SectionMetadata,
    sym_index: u64,
    va_start: u64,
    str_offset: u64,
    symbol: &mut ElfSymbol) -> Result<(), Error> {
    let mut sym = ElfSymbol32::default();
    let pos = metadata.offset + (sym_index * metadata.entry_size);
    reader.seek(SeekFrom::Start(pos))?;
    read_symbol32(reader, &mut sym)?;

    if !sym.is_function() || sym.st_value == 0 || sym.st_size == 0 {
        return Err(Error::new(std::io::ErrorKind::InvalidData, "Invalid symbol"));
    }

    symbol.start = sym.st_value as u64 - va_start;
    symbol.end = symbol.start + (sym.st_size as u64 - 1);
    let str_pos = sym.st_name as u64 + str_offset;

    reader.seek(SeekFrom::Start(str_pos))?;
    symbol.name_len = reader.read(&mut symbol.name_buf[..])?;

    Ok(())
}

fn get_symbols64(
    reader: &mut (impl Read + Seek),
    metadata: &SectionMetadata,
    count: u64,
    va_start: u64,
    str_offset: u64,
    mut callback: impl FnMut(&ElfSymbol)) -> Result<(), Error> {
    let mut symbol = ElfSymbol::new();

    for i in 0..count {
        if get_symbol64(
            reader,
            metadata,
            i,
            va_start,
            str_offset,
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
    va_start: u64,
    str_offset: u64,
    symbol: &mut ElfSymbol) -> Result<(), Error> {
    let mut sym = ElfSymbol64::default();
    let pos = metadata.offset + (sym_index * metadata.entry_size);
    reader.seek(SeekFrom::Start(pos))?;
    read_symbol64(reader, &mut sym)?;

    if !sym.is_function() || sym.st_value == 0 || sym.st_size == 0 {
        return Err(Error::new(std::io::ErrorKind::InvalidData, "Invalid symbol"));
    }

    symbol.start = sym.st_value - va_start;
    symbol.end = symbol.start + (sym.st_size - 1);
    let str_pos = sym.st_name as u64 + str_offset;

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


fn get_va_start32(
    reader: &mut (impl Read + Seek)) -> Result<u64, Error> {
    let mut header = ElfHeader32::default();

    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                size_of::<ElfHeader32>()))?;
    }

    let sec_count = header.e_phnum as u32;
    let mut sec_offset = header.e_phoff as u64;
    let mut pheader = ElfProgramHeader32::default();

    for _ in 0..sec_count {
        reader.seek(SeekFrom::Start(sec_offset))?;
        get_program_header32(reader, &mut pheader)?;

        if pheader.p_type == PT_LOAD &&
            (pheader.p_flags & PF_X) == PF_X {
            return Ok(pheader.p_vaddr as u64);
        }

        sec_offset += header.e_phentsize as u64;
    }

    /* No program headers, assume absolute */
    Ok(0)
}

fn get_va_start64(
    reader: &mut (impl Read + Seek)) -> Result<u64, Error> {
    let mut header = ElfHeader64::default();

    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                size_of::<ElfHeader32>()))?;
    }

    let sec_count = header.e_phnum as u32;
    let mut sec_offset = header.e_phoff;
    let mut pheader = ElfProgramHeader64::default();

    for _ in 0..sec_count {
        reader.seek(SeekFrom::Start(sec_offset))?;
        get_program_header64(reader, &mut pheader)?;

        if pheader.p_type == PT_LOAD &&
            (pheader.p_flags & PF_X) == PF_X {
            return Ok(pheader.p_vaddr);
        }

        sec_offset += header.e_phentsize as u64;
    }

    /* No program headers, assume absolute */
    Ok(0)
}

fn get_va_start(
    reader: &mut (impl Read + Seek)) -> Result<u64, Error> {
    reader.seek(SeekFrom::Start(0))?;
    let slice = get_ident(reader)?;
    let class = slice[EI_CLASS];

    match class {
        ELFCLASS32 => { get_va_start32(reader) },
        ELFCLASS64 => { get_va_start64(reader) },

        /* Unknown, assume absolute values */
        _ => { Ok(0) },
    }
}

pub fn get_symbols(
    reader: &mut (impl Read + Seek),
    metadata: &Vec<SectionMetadata>,
    mut callback: impl FnMut(&ElfSymbol)) -> Result<(), Error> {
    let va_start = get_va_start(reader)?;
    let mut offsets: Vec<u64> = Vec::new();

    get_section_offsets(reader, None, &mut offsets)?;

    for m in metadata {
        let count = m.size / m.entry_size;
        let mut str_offset = 0u64;

        if m.link < offsets.len() as u32 {
            str_offset = offsets[m.link as usize];
        }

        match m.class {
            ELFCLASS32 => {
                get_symbols32(reader, m, count, va_start, str_offset, &mut callback)?;
            },
            ELFCLASS64 => {
                get_symbols64(reader, m, count, va_start, str_offset, &mut callback)?;
            },
            _ => {
                /* Unknown, no symbols */
            },
        }
    }

    Ok(())
}

pub fn get_symbol(
    reader: &mut (impl Read + Seek),
    metadata: &SectionMetadata,
    sym_index: u64,
    va_start: u64,
    str_offset: u64,
    symbol: &mut ElfSymbol) -> Result<(), Error> {
    match metadata.class {
        ELFCLASS32 => {
            return get_symbol32(reader, metadata, sym_index, va_start, str_offset, symbol);
        },
        ELFCLASS64 => {
            return get_symbol64(reader, metadata, sym_index, va_start, str_offset, symbol);
        }
        _ => {
            /* Unknown, no symbols */
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
            /* Unknown, no offsets */
            Ok(())
        },
    }
}

pub fn get_section_metadata(
    reader: &mut (impl Read + Seek),
    ident: Option<&[u8]>,
    sec_type: u32,
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
            /* Unknown, no metadata */
            Ok(())
        },
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
    fn is_function(&self) -> bool {
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
    fn is_function(&self) -> bool {
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
    sec_type: u32,
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

        if sec.sh_type == sec_type {
            let offset = sec.sh_offset as u64;
            let size = sec.sh_size as u64;
            let name_offset = sec.sh_name as u64;
            metadata.push(
                SectionMetadata {
                    class: ELFCLASS32,
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
    sec_type: u32,
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

        if sec.sh_type == sec_type {
            let offset = sec.sh_offset;
            let size = sec.sh_size;
            let name_offset = sec.sh_name as u64;
            metadata.push(
                SectionMetadata {
                    class: ELFCLASS64,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    #[cfg(target_os = "linux")]
    fn symbols() {
        #[cfg(target_arch = "x86_64")]
        let path = "/usr/lib/x86_64-linux-gnu/libc.so.6";

        #[cfg(target_arch = "aarch64")]
        let path = "/usr/lib/aarch64-linux-gnu/libc.so.6";

        let mut file = File::open(path).unwrap();
        let mut sections = Vec::new();

        /* Get Dyn and Function Symbols */
        get_section_metadata(&mut file, None, 0x2, &mut sections).unwrap();
        get_section_metadata(&mut file, None, 0xb, &mut sections).unwrap();

        let mut found = false;

        get_symbols(&mut file, &sections, |symbol| {
            if symbol.name() == "malloc" {
                println!("{} - {}: {}", symbol.start, symbol.end, symbol.name());
                found = true;
            }
        }).unwrap();

        assert!(found);
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
}
