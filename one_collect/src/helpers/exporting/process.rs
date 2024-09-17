use std::borrow::BorrowMut;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::PathBufInteger;
use crate::intern::InternedCallstacks;

#[cfg(target_os = "linux")]
use crate::openat::OpenAt;
#[cfg(target_os = "linux")]
use crate::procfs;

use ruwind::elf::{get_section_metadata, get_section_offsets, get_str, ElfSymbol, SHT_PROGBITS};
use ruwind::{CodeSection, Unwindable};
use symbols::ElfSymbolReader;

use super::*;

#[derive(Clone, Copy)]
pub struct ExportProcessSample {
    time: u64,
    value: u64,
    cpu: u16,
    kind: u16,
    tid: u32,
    ip: u64,
    callstack_id: usize,
}

impl ExportProcessSample {
    pub fn new(
        time: u64,
        value: u64,
        cpu: u16,
        kind: u16,
        tid: u32,
        ip: u64,
        callstack_id: usize) -> Self {
        Self {
            time,
            value,
            cpu,
            kind,
            tid,
            ip,
            callstack_id,
        }
    }

    pub fn time_mut(&mut self) -> &mut u64 { &mut self.time }

    pub fn value_mut(&mut self) -> &mut u64 { &mut self.value }

    pub fn time(&self) -> u64 { self.time }

    pub fn value(&self) -> u64 { self.value }

    pub fn cpu(&self) -> u16 { self.cpu }

    pub fn kind(&self) -> u16 { self.kind }

    pub fn tid(&self) -> u32 { self.tid }

    pub fn ip(&self) -> u64 { self.ip }

    pub fn callstack_id(&self) -> usize { self.callstack_id }
}

pub struct ExportProcess {
    pid: u32,
    #[cfg(target_os = "linux")]
    ns_pid: Option<u32>,
    comm_id: Option<usize>,
    #[cfg(target_os = "linux")]
    root_fs: Option<OpenAt>,
    samples: Vec<ExportProcessSample>,
    mappings: Vec<ExportMapping>,
    anon_maps: bool,
}

impl Unwindable for ExportProcess {
    fn find<'a>(
        &'a self,
        ip: u64) -> Option<&'a dyn CodeSection> {
        self.find_section(ip)
    }
}

impl ExportProcess {
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            #[cfg(target_os = "linux")]
            ns_pid: None,
            comm_id: None,
            #[cfg(target_os = "linux")]
            root_fs: None,
            samples: Vec::new(),
            mappings: Vec::new(),
            anon_maps: false,
        }
    }

    fn find_section(
        &self,
        ip: u64) -> Option<&dyn CodeSection> {
        if self.mappings.is_empty() {
            return None;
        }

        let mut index = self.mappings.partition_point(
            |map| map.start() <= ip );

        index = index.saturating_sub(1);

        let map = &self.mappings[index];

        if map.start() <= ip &&
           map.end() >= ip {
            return Some(map);
        }

        None
    }

    #[cfg(target_os = "linux")]
    pub fn add_ns_pid(
        &mut self,
        path_buf: &mut PathBuf) {
        self.ns_pid = procfs::ns_pid(path_buf, self.pid);
    }

    #[cfg(target_os = "linux")]
    pub fn add_root_fs(
        &mut self,
        path_buf: &mut PathBuf) -> anyhow::Result<()> {
        path_buf.clear();
        path_buf.push("/proc");
        path_buf.push_u32(self.pid);
        path_buf.push("root");
        path_buf.push(".");

        if let Ok(root) = File::open(path_buf) {
            self.root_fs = Some(OpenAt::new(root));
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn open_file(
        &self,
        path: &Path) -> anyhow::Result<File> {
        match &self.root_fs {
            None => {
                anyhow::bail!("Root fs is not set or had an error.");
            },
            Some(root_fs) => {
                root_fs.open_file(path)
            }
        }
    }

    pub fn add_mapping(
        &mut self,
        mapping: ExportMapping) {
        if mapping.anon() {
            self.anon_maps = true;
        }

        self.mappings.push(mapping);
        self.mappings.sort();
    }

    pub fn add_sample(
        &mut self,
        sample: ExportProcessSample) {
        self.samples.push(sample);
    }

    pub fn set_comm_id(
        &mut self,
        comm_id: usize) {
        self.comm_id = Some(comm_id);
    }

    pub fn pid(&self) -> u32 { self.pid }

    #[cfg(target_os = "linux")]
    pub fn ns_pid(&self) -> Option<u32> { self.ns_pid }

    pub fn comm_id(&self) -> Option<usize> { self.comm_id }

    pub fn samples(&self) -> &Vec<ExportProcessSample> { &self.samples }

    pub fn mappings(&self) -> &Vec<ExportMapping> { &self.mappings }

    pub fn mappings_mut(&mut self) -> &mut Vec<ExportMapping> { &mut self.mappings }

    pub fn has_anon_mappings(&self) -> bool { self.anon_maps }

    pub fn get_unique_kernel_ips(
        &self,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks) {
        addrs.clear();
        frames.clear();

        for sample in &self.samples {
            /* Skip user mode samples */
            if sample.ip() < KERNEL_START {
                continue;
            }

            addrs.insert(sample.ip());

            if callstacks.from_id(
                sample.callstack_id(),
                frames).is_ok() {
                for frame in frames.iter() {
                    /* Stop on first user-mode frame */
                    if *frame < KERNEL_START {
                        break;
                    }

                    addrs.insert(*frame);
                }
            }
        }
    }

    pub fn add_matching_anon_symbols(
        &mut self,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        sym_reader: &mut impl ExportSymbolReader,
        callstacks: &InternedCallstacks,
        strings: &mut InternedStrings) {
        addrs.clear();
        frames.clear();

        for map in &mut self.mappings {
            if !map.anon() {
                continue;
            }

            Self::get_unique_user_ips(
                &self.samples,
                addrs,
                frames,
                &callstacks,
                Some(map));

            if addrs.is_empty() {
                continue;
            }

            for addr in addrs.iter() {
                frames.push(*addr);
            }

            map.add_matching_symbols(
                frames,
                sym_reader,
                strings);
        }
    }

    pub fn add_matching_elf_symbols(
        &mut self,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks,
        strings: &mut InternedStrings) {
        addrs.clear();
        frames.clear();

        if self.root_fs.is_none() {
            return;
        }

        println!("Processing PID {}", self.pid);
        for map_index in 0..self.mappings.len() {
            let map = self.mappings.get(map_index).unwrap();
            if map.anon() {
                continue;
            }

            Self::get_unique_user_ips(
                &self.samples,
                addrs,
                frames,
                &callstacks,
                Some(map));

            if addrs.is_empty() {
                continue;
            }

            for addr in addrs.iter() {
                frames.push(*addr);
            }

            // Get the binary path.
            let filename= strings.from_id(map.filename_id());
            if filename.is_err() {
                continue;
            }

            let name = filename.unwrap();
            println!("\tImage: {}", &name);
            let file_path = Path::new(name);
            if let Ok(mut file) = self.open_file(file_path) {
                // TODO: Get the path to the symbol file.
                // If we can't open it, then it's time to bail.
                // Use open_at and the root_fs to make sure that we do this properly for containers.
                let _path = Self::find_symbol_file(map, &mut file, strings);
                let mut reader = ElfSymbolReader::new(file);
                let mut sym_reader = reader.borrow_mut();
                let map_mut = self.mappings.get_mut(map_index).unwrap();
                map_mut.add_matching_symbols(
                    frames,
                    sym_reader,
                    strings);
            }
            else {
                println!("Failed to open.");
            }
        }
    }

    fn find_symbol_file<'a>(
        mapping: &ExportMapping,
        file: &mut File,
        strings: &'a InternedStrings) -> Option<&'a str> {

        // DEBUGLINK
        let mut path_buf: [u8; 1024] = [0; 1024];
        if let Ok(Some(_)) = Self::read_debuglink_section(file, &mut path_buf) {
            let debug_link_value = get_str(&path_buf);
            println!("\t.gnu_debuglink: {}", debug_link_value);
        }
        // FEDORA
        // UBUNTU
        // FIXUP UBUNTU

        None
    }

    fn read_debuglink_section<'a>(
        file: &'a mut File,
        value_buf: &'a mut [u8]) -> anyhow::Result<Option<()>> {
        let mut sections = Vec::new();
        let mut section_offsets = Vec::new();
        let mut reader = BufReader::new(file);

        get_section_metadata(&mut reader, None, SHT_PROGBITS, &mut sections)?;
        get_section_offsets(&mut reader, None, &mut section_offsets)?;

        for section in &sections {
            let mut str_offset = 0u64;
            if section.link < section_offsets.len() as u32 {
                str_offset = section_offsets[section.link as usize];
            }

            let str_pos = section.name_offset + str_offset;
            reader.seek(SeekFrom::Start(str_pos))?;

            let mut section_name_buf: [u8; 1024] = [0; 1024];
            if let Ok(bytes_read) = reader.read(&mut section_name_buf) {
                let name = get_str(&section_name_buf[0..bytes_read]);
                if name == ".gnu_debuglink" {
                    reader.seek(SeekFrom::Start(section.offset))?;
                    reader.read(&mut value_buf[0..section.size as usize])?;
                    return Ok(Some(()))
                }
            }
        }

        Ok(None)
    }

    pub fn get_unique_user_ips(
        samples: &[ExportProcessSample],
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks,
        mapping: Option<&ExportMapping>) {
        addrs.clear();
        frames.clear();

        for sample in samples {
            /* Only add user frames */
            if sample.ip() < KERNEL_START {
                match mapping {
                    Some(mapping) => {
                        if mapping.contains_ip(sample.ip()) {
                            addrs.insert(sample.ip());
                        }
                    },
                    None => { addrs.insert(sample.ip()); }
                }
            }

            if callstacks.from_id(
                sample.callstack_id(),
                frames).is_ok() {
                for frame in frames.iter() {
                    /* Only add user frames */
                    if *frame < KERNEL_START {
                        match mapping {
                            Some(mapping) => {
                                if mapping.contains_ip(*frame) {
                                    addrs.insert(*frame);
                                }
                            },
                            None => { addrs.insert(*frame); }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn fork(
        &self,
        pid: u32) -> Self { 
        let mut fork = Self::new(pid);

        fork.comm_id = self.comm_id;
        fork.mappings = self.mappings.clone();
        fork.root_fs = self.root_fs.clone();

        fork
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_mapping(
        start: u64,
        end: u64,
        id: usize) -> ExportMapping {
        let mut map = ExportMapping::new(0, start, end, 0, false, id);
        map.set_node(ExportDevNode::from_parts(0, 0, id as u64));
        map
    }

    #[test]
    fn find_section() {
        let mut proc = ExportProcess::new(1);
        proc.add_mapping(new_mapping(0, 1023, 1));
        proc.add_mapping(new_mapping(1024, 2047, 2));
        proc.add_mapping(new_mapping(2048, 3071, 3));

        /* Find should work properly */
        let found = proc.find_section(0);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(1, found.key().ino);

        let found = proc.find_section(512);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(1, found.key().ino);

        let found = proc.find_section(1024);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(2, found.key().ino);

        let found = proc.find_section(2000);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(2, found.key().ino);

        let found = proc.find_section(2048);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(3, found.key().ino);

        let found = proc.find_section(3071);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(3, found.key().ino);

        /* Outside all should find none */
        assert!(proc.find_section(3072).is_none());
    }
}
