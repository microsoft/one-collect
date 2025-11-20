// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use std::mem::{zeroed, size_of};
use std::string::{FromUtf8Error, FromUtf16Error};
use std::slice;
use tracing::{debug};

use crate::intern::InternedStrings;

pub struct PEModuleMetadata {
    machine: u16,
    date_time: u32,
    symbol_name_id: usize,
    symbol_age: u32,
    symbol_sig: [u8; 16],
    version_name_id: usize,
    perfmap_sig: [u8; 16],
    perfmap_version: u32,
    perfmap_name_id: usize,
    text_loaded_layout_offset: u64,
}

impl Default for PEModuleMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl PEModuleMetadata {
    pub fn new() -> Self {
        Self {
            machine: 0,
            date_time: 0,
            symbol_name_id: 0,
            symbol_age: 0,
            symbol_sig: [0; 16],
            version_name_id: 0,
            perfmap_sig: [0; 16],
            perfmap_version: 0,
            perfmap_name_id: 0,
            text_loaded_layout_offset: 0,
        }
    }

    pub fn to_symbol_metadata(
        &self,
        strings: &InternedStrings,
        out: &mut String) {
        out.clear();
        out.push_str("{");
        out.push_str("\"type\": \"PE\",");

        if let Ok(symbol_name) = strings.from_id(self.symbol_name_id) {
            out.push_str("\"name\": \"");
            out.push_str(symbol_name);
            out.push_str("\",");
        }

        out.push_str(&format!("\"date_time\": {},", self.date_time));
        out.push_str(&format!("\"age\": {},", self.symbol_age));
        out.push_str("\"signature\": \"");
        for b in self.symbol_sig {
            out.push_str(&format!("{:02x}", b));
        }
        out.push_str("\",");

        out.push_str("\"perfmap_signature\": \"");
        for b in self.perfmap_sig {
            out.push_str(&format!("{:02x}", b));
        }
        out.push_str("\",");

        out.push_str(&format!("\"perfmap_version\": {},", self.perfmap_version));

        if let Ok(perfmap_name) = strings.from_id(self.perfmap_name_id) {
            out.push_str("\"perfmap_name\": \"");
            out.push_str(perfmap_name);
            out.push_str("\",");
        }

        out.push_str(&format!("\"text_offset\": {},", self.text_loaded_layout_offset));

        /* Remove trailing comma if it exists */
        if out.ends_with(',') {
            out.pop();
        }

        out.push_str("}");
    }

    pub fn to_version_metadata(
        &self,
        strings: &InternedStrings,
        out: &mut String) {
        out.clear();
        out.push_str("{");

        if let Ok(version_name) = strings.from_id(self.version_name_id) {
            out.push_str("\"version\": \"");
            out.push_str(version_name);
            out.push_str("\"");
        }

        out.push_str("}");
    }

    pub fn get_metadata(
        &mut self,
        path: &str,
        strings: &mut InternedStrings) -> anyhow::Result<()> {
        let file = File::open(path)?;
        self.get_metadata_direct(
            file,
            strings)?;
        Ok(())
    }

    pub fn get_metadata_direct(
        &mut self,
        mut file: File,
        strings: &mut InternedStrings) -> anyhow::Result<()> {
        get_pe_info(&mut file, self, strings)?;
        Ok(())
    }

    pub fn reset(&mut self) {
        self.machine = 0;
        self.date_time = 0;
        self.symbol_name_id = 0;
        self.symbol_age = 0;
        self.symbol_sig = [0; 16];
        self.version_name_id = 0;
        self.perfmap_sig = [0; 16];
        self.perfmap_version = 0;
        self.perfmap_name_id = 0;
        self.text_loaded_layout_offset = 0;
    }

    pub fn machine(&self) -> u16 {
        self.machine
    }

    pub fn date_time(&self) -> u32 {
        self.date_time
    }

    pub fn symbol_name_id(&self) -> usize {
        self.symbol_name_id
    }

    pub fn symbol_name<'a>(&self, strings: &'a InternedStrings) -> Option<&'a str> {
        match strings.from_id(self.symbol_name_id) {
            Ok(name) => Some(name),
            Err(_) => None
        }
    }

    pub fn symbol_age(&self) -> u32 {
        self.symbol_age
    }

    pub fn symbol_sig(&self) -> &[u8; 16] {
        &self.symbol_sig
    }

    pub fn version_name_id(&self) -> usize {
        self.version_name_id
    }

    pub fn version_name<'a>(&self, strings: &'a InternedStrings) -> Option<&'a str> {
        match strings.from_id(self.version_name_id) {
            Ok(name) => Some(name),
            Err(_) => None
        }
    }

    pub fn perfmap_sig(&self) -> &[u8; 16] {
        &self.perfmap_sig
    }

    pub fn perfmap_version(&self) -> u32 {
        self.perfmap_version
    }

    pub fn perfmap_name_id(&self) -> usize {
        self.perfmap_name_id
    }

    pub fn perfmap_name<'a>(&self, strings: &'a InternedStrings) -> Option<&'a str> {
        match strings.from_id(self.perfmap_name_id) {
            Ok(name) => Some(name),
            Err(_) => None
        }
    }

    pub fn text_loaded_layout_offset(&self) -> u64 {
        self.text_loaded_layout_offset
    }
}

#[repr(C)]
struct PEHeader {
    signature: u32,
    machine: u16,
    sec_count: u16,
    date_time: u32,
    sym_table: u32,
    sym_count: u32,
    opt_header_size: u16,
    characteristics: u16,
    magic: u16,
}

#[repr(C)]
struct PEDataDirectory {
    virt_addr: u32,
    size: u32,
}

#[repr(C)]
struct PEDebugDirectory {
    reserved: u32,
    date_time: u32,
    major_ver: u16,
    minor_ver: u16,
    debug_type: u32,
    size: u32,
    virt_addr: u32,
    raw_offset: u32,
}

#[repr(C)]
struct PEResDirectory {
    flags: u32,
    date_time: u32,
    major_ver: u16,
    minor_ver: u16,
    named_count: u16,
    id_count: u16,
}

#[repr(C)]
struct PEResEntry {
    name_id_offset: u32,
    dir_data_offset: u32,
}

#[repr(C)]
struct PEResData {
    data_offset: u32,
    size: u32,
    code_page: u32,
    reserved: u32,
}

impl PEResEntry {
    fn is_named(&self) -> bool {
        (self.name_id_offset & 0x80000000) != 0
    }

    fn name_id_value(&self) -> u32 {
        self.name_id_offset & 0x7FFFFFFF
    }

    fn is_dir(&self) -> bool {
        (self.dir_data_offset & 0x80000000) != 0
    }

    fn dir_data_value(&self) -> u32 {
        self.dir_data_offset & 0x7FFFFFFF
    }
}

#[repr(C)]
struct PESection {
    name: [u8; 8],
    virt_size: u32,
    virt_addr: u32,
    raw_size: u32,
    raw_offset: u32,
    rel_offset: u32,
    line_offset: u32,
    rel_count: u16,
    line_count: u16,
    characteristics: u32,
}

#[repr(C)]
struct CodeViewNb10 {
    offset: u32,
    pdb_sig: [u8; 4],
    pdb_age: u32,
    pdb_name: [u8; 128],
}

#[repr(C)]
struct CodeViewRsds {
    pdb_sig: [u8; 16],
    pdb_age: u32,
    pdb_name: [u8; 128],
}

const PERFMAP_MAGIC: u32 = 0x4D523252;

#[derive(Debug)]
#[repr(C)]
struct CodeViewPerfMap {
    perfmap_magic: u32,
    perfmap_sig: [u8; 16],
    perfmap_ver: u32,
    perfmap_name: [u8; 128],
}

fn read_header(
    reader: &mut impl Read,
    header: &mut PEHeader) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                header as *mut _ as *mut u8,
                size_of::<PEHeader>()))?;
    }

    Ok(())
}

fn read_directory(
    reader: &mut impl Read,
    dir: &mut PEDataDirectory) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                dir as *mut _ as *mut u8,
                size_of::<PEDataDirectory>()))?;
    }

    Ok(())
}

fn read_cv_nb10(
    reader: &mut impl Read,
    dir: &mut CodeViewNb10) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                dir as *mut _ as *mut u8,
                size_of::<CodeViewNb10>()))?;
    }

    Ok(())
}

fn read_cv_rsds(
    reader: &mut impl Read,
    dir: &mut CodeViewRsds) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                dir as *mut _ as *mut u8,
                size_of::<CodeViewRsds>()))?;
    }

    Ok(())
}

fn read_cv_perfmap(
    reader: &mut impl Read,
    dir: &mut CodeViewPerfMap) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                dir as *mut _ as *mut u8,
                size_of::<CodeViewPerfMap>()))?;
    }

    Ok(())
}

fn read_debug_directory(
    reader: &mut impl Read,
    dir: &mut PEDebugDirectory) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                dir as *mut _ as *mut u8,
                size_of::<PEDebugDirectory>()))?;
    }

    Ok(())
}

fn read_res_directory(
    reader: &mut impl Read,
    dir: &mut PEResDirectory) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                dir as *mut _ as *mut u8,
                size_of::<PEResDirectory>()))?;
    }

    Ok(())
}

fn read_res_entry(
    reader: &mut impl Read,
    entry: &mut PEResEntry) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                entry as *mut _ as *mut u8,
                size_of::<PEResEntry>()))?;
    }

    Ok(())
}

fn read_res_data(
    reader: &mut impl Read,
    entry: &mut PEResData) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                entry as *mut _ as *mut u8,
                size_of::<PEResData>()))?;
    }

    Ok(())
}

fn find_res_entry(
    reader: &mut (impl Read + Seek),
    offset: u64,
    wanted_id: u32) -> anyhow::Result<Option<PEResEntry>> {
    let mut res_dir: PEResDirectory = unsafe { zeroed() };
    let mut entry: PEResEntry = unsafe { zeroed() };
    reader.seek(SeekFrom::Start(offset))?;
    read_res_directory(reader, &mut res_dir)?;
    let count = res_dir.named_count + res_dir.id_count;

    for _i in 0 .. count {
        read_res_entry(reader, &mut entry)?;

        if !entry.is_named() {
            let id = entry.name_id_value() & 0xFFFF;

            if id == wanted_id || wanted_id == 0 {
                return Ok(Some(entry));
            }
        }
    }

    Ok(None)
}

fn read_section(
    reader: &mut impl Read,
    sec: &mut PESection) -> anyhow::Result<()> {
    unsafe {
        reader.read_exact(
            slice::from_raw_parts_mut(
                sec as *mut _ as *mut u8,
                size_of::<PESection>()))?;
    }

    Ok(())
}

fn read_u32(
    reader: &mut impl Read) -> anyhow::Result<u32> {
    let mut v: [u8; 4] = [0; 4];
    reader.read_exact(&mut v)?;
    Ok(u32::from_le_bytes(v))
}

fn get_pe_header(
    reader: &mut (impl Read + Seek),
    pe_header: &mut PEHeader,
    pe_offset: &mut u64) -> anyhow::Result<()> {
    /* Get offset to pe header */
    reader.seek(SeekFrom::Start(0x3C))?;
    *pe_offset = read_u32(reader)? as u64;
    debug!("Reading PE header: pe_offset={:#x}", *pe_offset);

    /* Read PE header */
    reader.seek(SeekFrom::Start(*pe_offset))?;
    read_header(reader, pe_header)?;

    Ok(())
}

fn va_to_offset(
    reader: &mut (impl Read + Seek),
    pe_header: &PEHeader,
    pe_offset: u64,
    va: u32) -> anyhow::Result<Option<u64>> {
    /* Read sections */
    let mut sections_offset: u64 = pe_offset as u64;
    sections_offset += 24;
    sections_offset += pe_header.opt_header_size as u64;
    reader.seek(SeekFrom::Start(sections_offset))?;
    let mut section: PESection = unsafe { zeroed() };

    for _i in 0 .. pe_header.sec_count {
        read_section(reader, &mut section)?;
        let va_start = section.virt_addr;
        let va_end = va_start + section.raw_size;

        /* Check if within virtual address range */
        if va >= va_start &&
           va < va_end {
            let rva = va - va_start;
            return Ok(Some((rva + section.raw_offset) as u64));
        }
    }

    return Ok(None)
}

const TEXT_SECTION_NAME: &[u8; 8] = b".text\0\0\0";

fn get_text_addresses(
    reader: &mut (impl Read + Seek),
    pe_header: &PEHeader,
    pe_offset: u64) -> anyhow::Result<Option<(u64, u64)>> {
    /* Read sections */
    let mut sections_offset: u64 = pe_offset as u64;
    sections_offset += 24;
    sections_offset += pe_header.opt_header_size as u64;
    reader.seek(SeekFrom::Start(sections_offset))?;
    let mut section: PESection = unsafe { zeroed() };

    for _i in 0 .. pe_header.sec_count {
        read_section(reader, &mut section)?;

        if section.name == *TEXT_SECTION_NAME {
            return Ok(Some((section.virt_addr as u64, section.raw_offset as u64)));
        }
    }

    return Ok(None)
}

fn get_directory_data(
    reader: &mut (impl Read + Seek),
    pe_header: &PEHeader,
    pe_offset: u64,
    index: u64) -> anyhow::Result<(u64, u64)> {
    /* Get data header offset */
    let data_offset: u64;

    if pe_header.magic == 0x10b {
        data_offset = pe_offset + 24 + 96 + (index * 8);
    } else if pe_header.magic == 0x20b {
        data_offset = pe_offset + 24 + 112 + (index * 8);
    } else {
        return Err(anyhow::Error::msg(
            format!(
                "Unexpected magic value {}",
                pe_header.magic)));
    }

    /* Read data directory */
    reader.seek(SeekFrom::Start(data_offset))?;
    let mut data_dir: PEDataDirectory = unsafe { zeroed() };
    read_directory(reader, &mut data_dir)?;

    /* Not there */
    if data_dir.virt_addr == 0 {
        return Ok((0, 0));
    }

    /* Read sections */
    let mut sections_offset: u64 = pe_offset as u64;
    sections_offset += 24;
    sections_offset += pe_header.opt_header_size as u64;
    reader.seek(SeekFrom::Start(sections_offset))?;
    let mut section: PESection = unsafe { zeroed() };
    let mut data_offset: u64 = 0;

    for _i in 0 .. pe_header.sec_count {
        read_section(reader, &mut section)?;
        let va_start = section.virt_addr;
        let va_end = va_start + section.raw_size;

        /* Check if within virtual address range */
        if data_dir.virt_addr >= va_start &&
           data_dir.virt_addr < va_end {
            let rva = data_dir.virt_addr - va_start;
            data_offset = (rva + section.raw_offset) as u64;
            break;
        }
    }

    Ok((data_offset, data_dir.size as u64))
}

fn get_unicode_string(
    name: &[u8]) -> Result<String, FromUtf16Error> {
    unsafe {
        let (_, values, _) = name.align_to::<u16>();
        let null_pos = values.iter()
            .position(|&c| c == 0u16)
            .unwrap_or(values.len());

        String::from_utf16(&values[0..null_pos])
    }
}

fn get_string(
    name: &[u8]) -> Result<String, FromUtf8Error> {
    let null_pos = name.iter()
        .position(|&c| c == b'\0')
        .unwrap_or(name.len());

    String::from_utf8((&name[0..null_pos]).to_vec())
}

/// Extract the filename portion from a path string regardless of platform.
/// Handles both Windows-style backslash and Unix-style forward slash separators.
fn extract_filename(path: &str) -> &str {
    let windows_pos = path.rfind('\\').map(|pos| pos + 1).unwrap_or(0);
    let unix_pos = path.rfind('/').map(|pos| pos + 1).unwrap_or(0);
    
    // Take the rightmost separator position
    let pos = windows_pos.max(unix_pos);
    &path[pos..] 
}

fn get_pe_info(
    reader: &mut (impl Read + Seek),
    module: &mut PEModuleMetadata,
    strings: &mut InternedStrings) -> anyhow::Result<()> {
    let dbg_offset: u64;
    let dbg_size: u64;
    let res_offset: u64;
    let mut pe_header: PEHeader = unsafe { zeroed() };
    let mut pe_offset: u64 = 0;

    module.machine = 0;
    module.date_time = 0;
    module.symbol_name_id = 0;
    module.symbol_age = 0;
    module.symbol_sig = [0; 16];
    module.version_name_id = 0;

    get_pe_header(reader, &mut pe_header, &mut pe_offset)?;
    module.machine = pe_header.machine;
    module.date_time = pe_header.date_time;
    debug!("PE header parsed: machine={}, date_time={}, pe_offset={:#x}", pe_header.machine, pe_header.date_time, pe_offset);

    if let Some((virtual_address, file_offset)) = get_text_addresses(reader, &pe_header, pe_offset)? {
        module.text_loaded_layout_offset = virtual_address - file_offset;
        debug!("Text section addresses found: virtual_address={:#x}, file_offset={:#x}", virtual_address, file_offset);
    } else {
        debug!("No text section addresses found");
    }

    (dbg_offset, dbg_size) = get_directory_data(
        reader, &pe_header, pe_offset, 6)?;

    if dbg_offset != 0 {
        debug!("Processing debug directory: offset={:#x}, size={}", dbg_offset, dbg_size);
        let mut debug_dir: PEDebugDirectory = unsafe { zeroed() };
        reader.seek(SeekFrom::Start(dbg_offset))?;
        let debug_count = dbg_size / size_of::<PEDebugDirectory>() as u64;

        for i in 0 .. debug_count {
            reader.seek(SeekFrom::Start(dbg_offset + (i * size_of::<PEDebugDirectory>() as u64)))?;
            read_debug_directory(reader, &mut debug_dir)?;

            /* Codeview */
            if debug_dir.debug_type == 2 {
                reader.seek(SeekFrom::Start(debug_dir.raw_offset as u64))?;
                let cv_type = read_u32(reader)?;

                if cv_type == 0x3031424e {
                    /* NB10 */
                    let mut cv: CodeViewNb10 = unsafe { zeroed() };
                    read_cv_nb10(reader, &mut cv)?;
                    module.symbol_age = cv.pdb_age;
                    module.symbol_sig[0..4].clone_from_slice(&cv.pdb_sig);
                    let pdb_path_str = get_string(&cv.pdb_name)?;
                    let file_name = extract_filename(&pdb_path_str);
                    module.symbol_name_id = strings.to_id(file_name);
                    debug!("Found CodeView NB10: pdb_name={}, age={}", file_name, cv.pdb_age);
                } else if cv_type == 0x53445352 {
                    /* RSDS */
                    let mut cv: CodeViewRsds = unsafe { zeroed() };
                    read_cv_rsds(reader, &mut cv)?;
                    module.symbol_age = cv.pdb_age;
                    module.symbol_sig[0..16].clone_from_slice(&cv.pdb_sig);
                    let pdb_path_str = get_string(&cv.pdb_name)?;
                    let file_name = extract_filename(&pdb_path_str);
                    module.symbol_name_id = strings.to_id(file_name);
                    debug!("Found CodeView RSDS: pdb_name={}, age={}", file_name, cv.pdb_age);
                }
            }
            /* PerfMap */
            else if debug_dir.debug_type == 21 && debug_dir.major_ver == 1 && debug_dir.minor_ver == 0 {
                reader.seek(SeekFrom::Start(debug_dir.raw_offset as u64))?;

                let mut cv: CodeViewPerfMap = unsafe { zeroed() };
                read_cv_perfmap(reader, &mut cv)?;
                if cv.perfmap_magic == PERFMAP_MAGIC {
                    module.perfmap_sig[0..16].clone_from_slice(&cv.perfmap_sig);
                    module.perfmap_version = cv.perfmap_ver;
                    module.perfmap_name_id = strings.to_id(get_string(&cv.perfmap_name)?.as_str());
                    debug!("Found PerfMap: version={}", cv.perfmap_ver);
                }
            }
        }
    } else {
        debug!("No debug directory found");
    }

    /* Get file version information */
    (res_offset, _) = get_directory_data(
        reader, &pe_header, pe_offset, 2)?;

    if res_offset != 0 {
        // Locate directory tree: 16 / 1 / 0
        let mut cont: bool = false;
        let mut offset: u64 = 0;

        if let Some(entry) = find_res_entry(reader, res_offset + offset, 16)? {
            if entry.is_dir() {
                offset = entry.dir_data_value() as u64;
                cont = true;
            }
        }

        if cont {
            cont = false;
            if let Some(entry) = find_res_entry(reader, res_offset + offset, 1)? {
                if entry.is_dir() {
                    offset = entry.dir_data_value() as u64;
                    cont = true;
                }
            }
        }

        if cont {
            if let Some(entry) = find_res_entry(reader, res_offset + offset, 0)? {
                let mut data: PEResData = unsafe { zeroed() };
                offset = entry.dir_data_value() as u64;
                reader.seek(SeekFrom::Start(res_offset + offset))?;
                read_res_data(reader, &mut data)?;

                /* Resource offset is a VA within the binary */
                if let Some(data_offset) = va_to_offset(
                    reader,
                    &pe_header,
                    pe_offset,
                    data.data_offset)? {
                    /* Read data at found file offset */
                    let mut block_array = [0u8; 4096];
                    let block_size = std::cmp::min(data.size, 4096);
                    reader.seek(SeekFrom::Start(data_offset))?;
                    reader.read_exact(&mut block_array[..block_size as usize])?;
                    let mut slice = &block_array[..block_size as usize];

                    let mut product: Option<String> = None;
                    let mut file_ver: Option<String> = None;
                    let mut file_desc: Option<String> = None;

                    while slice.len() > 8 {
                        /*let len = u16::from_ne_bytes(slice[0..2].try_into().unwrap());*/
                        let mut data_len = u16::from_ne_bytes(slice[2..4].try_into().unwrap());
                        let data_type = u16::from_ne_bytes(slice[4..6].try_into().unwrap());

                        /* Data is string */
                        if data_type == 1 {
                            /* Characters vs bytes */
                            data_len *= 2;
                        }

                        let name = get_unicode_string(&slice[6..])?;
                        let header_len = 8 + (name.len() * 2);
                        /* Align header */
                        let header_len = (header_len + 3) & !3;

                        match name.as_str() {
                            "ProductVersion" => {
                                if product.is_none() {
                                    product = Some(
                                        get_unicode_string(
                                            &slice[header_len..])?);
                                }
                            },
                            "FileVersion" => {
                                if file_ver.is_none() {
                                    file_ver = Some(
                                        get_unicode_string(
                                            &slice[header_len..])?);
                                }
                            },
                            "FileDescription" => {
                                if file_desc.is_none() {
                                    file_desc = Some(
                                        get_unicode_string(
                                            &slice[header_len..])?);
                                }
                            },
                            _ => {},
                        }

                        let total_len = header_len + data_len as usize;
                        /* Must align data */
                        let total_len = (total_len + 3) & !3;

                        /* No more data */
                        if slice.len() <= total_len {
                            break;
                        }

                        /* No more to get */
                        if product.is_some() &&
                           file_ver.is_some() &&
                           file_desc.is_some() {
                           break;
                        }

                        slice = &slice[total_len..];
                    }

                    /* Must have a file description */
                    if file_desc.is_some() {
                        /* Prefer product version to file version */
                        if product.is_some() {
                            module.version_name_id = strings.to_id(format!("{}, {}",
                                product.unwrap(),
                                file_desc.unwrap()).as_str());
                            debug!("Version information found: using product version");
                        } else if file_ver.is_some() {
                            module.version_name_id = strings.to_id(format!("{}, {}",
                                file_ver.unwrap(),
                                file_desc.unwrap()).as_str());
                            debug!("Version information found: using file version");
                        }
                    } else {
                        debug!("No file description found in version resources");
                    }
                } else {
                    debug!("Could not resolve resource data offset");
                }
            } else {
                debug!("Resource entry not found at final level");
            }
        } else {
            debug!("Resource entry not found at intermediate level");
        }
    } else {
        debug!("No resource directory found");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[cfg(target_os = "windows")]
    #[test]
    fn get_details() {
        let mut strings = InternedStrings::new(8);
        let mut m = PEModuleMetadata::default();

        let windir = env::var("WINDIR").unwrap();
        let ntdll_path = format!("{}\\System32\\ntdll.dll", windir);
        for _i in 0..1024 {
            let mut f = File::open(&ntdll_path).unwrap();
            get_pe_info(&mut f, &mut m, &mut strings).unwrap();
        }
    }

    #[test]
    fn to_symbol_metadata() {
        let mut strings = InternedStrings::new(8);
        let mut m = PEModuleMetadata::default();

        m.symbol_name_id = strings.to_id("symbol_name");
        m.date_time = 1;
        m.symbol_age = 2;
        m.symbol_sig = [3; 16];
        m.perfmap_sig = [4; 16];
        m.perfmap_version = 5;
        m.perfmap_name_id = strings.to_id("perfmap_name");
        m.text_loaded_layout_offset = 65516;

        let mut out = String::new();

        m.to_symbol_metadata(&strings, &mut out);

        let mut expected = String::new();

        expected.push_str("{");
        expected.push_str("\"type\": \"PE\",");
        expected.push_str("\"name\": \"symbol_name\",");
        expected.push_str("\"date_time\": 1,");
        expected.push_str("\"age\": 2,");
        expected.push_str("\"signature\": \"03030303030303030303030303030303\",");
        expected.push_str("\"perfmap_signature\": \"04040404040404040404040404040404\",");
        expected.push_str("\"perfmap_version\": 5,");
        expected.push_str("\"perfmap_name\": \"perfmap_name\",");
        expected.push_str("\"text_offset\": 65516");
        expected.push_str("}");

        assert_eq!(expected, out);
    }

    #[test]
    fn to_version_metadata() {
        let mut strings = InternedStrings::new(8);
        let mut m = PEModuleMetadata::default();

        m.version_name_id = strings.to_id("version_name");

        let mut out = String::new();

        m.to_version_metadata(&strings, &mut out);

        let mut expected = String::new();

        expected.push_str("{");
        expected.push_str("\"version\": \"version_name\"");
        expected.push_str("}");

        assert_eq!(expected, out);
    }
    
    
    #[test]
    fn pdb_path_integration_test() {
        // Test that our cross-platform filename extraction works
        // Windows-style path
        let win_path = "C:\\Path\\To\\File.pdb";
        assert_eq!("File.pdb", extract_filename(win_path));
        
        // Unix-style path
        let unix_path = "/path/to/file.pdb";
        assert_eq!("file.pdb", extract_filename(unix_path));
        
        // Mixed separators
        let mixed_path = "C:/Path\\to/File.pdb";
        assert_eq!("File.pdb", extract_filename(mixed_path));
        
        // Just a filename (no path) - should remain unchanged
        let just_filename = "simple.pdb";
        assert_eq!("simple.pdb", extract_filename(just_filename));
    }
}
