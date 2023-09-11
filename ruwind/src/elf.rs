use std::io::{Error, Read, Seek, SeekFrom};
use std::mem::{zeroed, size_of};
use std::slice;

pub const SHT_PROGBITS: ElfWord = 1;

pub struct SectionMetadata {
    pub offset: u64,
    pub size: u64,
    pub name_offset: u64,
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

type Elf32Addr = u32;
type Elf32Off = u32;
type Elf64Addr = u64;
type Elf64Off = u64;
type ElfHalf = u16;
type ElfWord = u32;
type ElfXWord = u64;

#[repr(C)]
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
                    offset,
                    size,
                    name_offset,
                });
        }
    }

    for m in metadata {
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
                    offset,
                    size,
                    name_offset,
                });
        }
    }

    for m in metadata {
        m.name_offset += str_offset;
    }

    Ok(())
}
