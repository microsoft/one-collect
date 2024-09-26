use core::str;
use std::fs::File;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use crate::PathBufInteger;
use crate::intern::InternedCallstacks;

#[cfg(target_os = "linux")]
use crate::helpers::exporting::os::{ElfBinaryMetadata, ElfBinaryMetadataLookup};

#[cfg(target_os = "linux")]
use crate::openat::OpenAt;
#[cfg(target_os = "linux")]
use crate::procfs;

#[cfg(target_os = "linux")]
use ruwind::elf::{build_id_equals, get_build_id, get_section_metadata, SHT_SYMTAB, SHT_DYNSYM};

use ruwind::{CodeSection, Unwindable};
use symbols::ElfSymbolReader;

use super::*;
use super::mappings::ExportMappingLookup;

struct ElfSymbolFileMatch {
    file: File,
    contains_symtab: bool,
    contains_dynsym: bool,
}

impl ElfSymbolFileMatch {
    fn new(
        file: File,
        contains_symtab: bool,
        contains_dynsym: bool) -> Self {
        Self {
            file,
            contains_symtab,
            contains_dynsym
        }
    }
}

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
    ns_pid: Option<u32>,
    comm_id: Option<usize>,
    #[cfg(target_os = "linux")]
    root_fs: Option<OpenAt>,
    samples: Vec<ExportProcessSample>,
    mappings: ExportMappingLookup,
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
            ns_pid: None,
            comm_id: None,
            #[cfg(target_os = "linux")]
            root_fs: None,
            samples: Vec::new(),
            mappings: ExportMappingLookup::default(),
            anon_maps: false,
        }
    }

    fn find_section(
        &self,
        ip: u64) -> Option<&dyn CodeSection> {
        match self.find_mapping(ip, None) {
            Some(mapping) => { Some(mapping) },
            None => { None },
        }
    }

    #[cfg(target_os = "linux")]
    pub fn add_ns_pid(
        &mut self,
        path_buf: &mut PathBuf) {
        self.ns_pid = procfs::ns_pid(path_buf, self.pid);
    }

    #[cfg(target_os = "windows")]
    pub fn add_ns_pid(
        &mut self,
        pid: u32) {
        self.ns_pid = Some(pid);
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

    pub fn find_mapping(
        &self,
        ip: u64,
        time: Option<u64>) -> Option<&ExportMapping> {
        self.mappings.find(ip, time)
    }

    pub fn add_mapping(
        &mut self,
        mapping: ExportMapping) {
        if mapping.anon() {
            self.anon_maps = true;
        }

        self.mappings.mappings_mut().push(mapping);
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

    pub fn ns_pid(&self) -> Option<u32> { self.ns_pid }

    pub fn comm_id(&self) -> Option<usize> { self.comm_id }

    pub fn samples(&self) -> &Vec<ExportProcessSample> { &self.samples }

    pub fn mappings(&self) -> &Vec<ExportMapping> { self.mappings.mappings() }

    pub fn mappings_mut(&mut self) -> &mut Vec<ExportMapping> { self.mappings.mappings_mut() }

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

        for map in self.mappings.mappings_mut() {
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

            frames.clear();
            for addr in addrs.iter() {
                frames.push(*addr);
            }

            map.add_matching_symbols(
                frames,
                sym_reader,
                0u64,
                strings);
        }
    }

    #[cfg(target_os = "linux")]
    pub fn add_matching_elf_symbols(
        &mut self,
        elf_metadata: &ElfBinaryMetadataLookup,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks,
        strings: &mut InternedStrings) {
        addrs.clear();
        frames.clear();

        if self.root_fs.is_none() {
            return;
        }

        for map_index in 0..self.mappings.mappings().len() {
            let map = self.mappings.mappings().get(map_index).unwrap();
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

            frames.clear();
            for addr in addrs.iter() {
                frames.push(*addr);
            }

            // Get the file path or continue.
            let filename = match strings.from_id(map.filename_id()) {
                Ok(str) => str,
                Err(_) => continue
            };

            // Get the dev node or continue.
            let dev_node = match map.node() {
                Some(key) => key,
                None => continue
            };

            // If there is no metadata, then we can't load symbols.
            // It's possible that metadata fields are empty, but if there is no metadata entry,
            // then we should not proceed.
            if let Some(metadata) = elf_metadata.get(dev_node) {

                // Find the set of symbol files, including the binary.
                let mut symbol_files = Vec::new();
                self.find_symbol_files(filename, metadata, &mut symbol_files);
                
                for symbol_file in symbol_files {
                    let mut sym_reader = ElfSymbolReader::new(symbol_file.file);
                    let map_mut = self.mappings.mappings_mut().get_mut(map_index).unwrap();
                    let text_offset = metadata.text_offset().unwrap_or(0);

                    map_mut.add_matching_symbols(
                        frames,
                        &mut sym_reader,
                        text_offset,
                        strings);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn find_symbol_files<'a>(
        &self,
        bin_path: &str,
        metadata: &ElfBinaryMetadata,
        matching_symbol_files: &mut Vec<ElfSymbolFileMatch>) {

        // Keep evaluating symbol files until we have one or two files that contain symtab and dynsym sections.
        let mut contains_symtab = false;
        let mut contains_dynsym = false;
        let mut path_buf = PathBuf::new();

        // Look at the binary itself.
        path_buf.push(bin_path);
        if let Some(sym_file) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            contains_symtab |= sym_file.contains_symtab;
            contains_dynsym |= sym_file.contains_dynsym;
            matching_symbol_files.push(sym_file);

            // We've found everything we need.
            if contains_symtab && contains_dynsym {
                return;
            }
        }

        // Look next to the binary.
        path_buf.clear();
        path_buf.push(format!("{}.dbg", bin_path));
        if let Some(sym_file) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            contains_symtab |= sym_file.contains_symtab;
            contains_dynsym |= sym_file.contains_dynsym;
            matching_symbol_files.push(sym_file);

            // We've found everything we need.
            if contains_symtab && contains_dynsym {
                return;
            }
        }

        path_buf.clear();
        path_buf.push(format!("{}.debug", bin_path));
        if let Some(sym_file) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            contains_symtab |= sym_file.contains_symtab;
            contains_dynsym |= sym_file.contains_dynsym;
            matching_symbol_files.push(sym_file);

            // We've found everything we need.
            if contains_symtab && contains_dynsym {
                return;
            }
        }

        // Debug link.
        if let Some(debug_link) = metadata.debug_link() {

            // Directly open debug_link.
            path_buf.clear();
            path_buf.push(debug_link);
            if let Some(sym_file) = self.check_candidate_symbol_file(
                metadata.build_id(),
                &path_buf) {
                contains_symtab |= sym_file.contains_symtab;
                contains_dynsym |= sym_file.contains_dynsym;
                matching_symbol_files.push(sym_file);

                // We've found everything we need.
                if contains_symtab && contains_dynsym {
                    return;
                }
            }

            // These lookups require the directory path containing the binary.
            path_buf.clear();
            path_buf.push(bin_path);
            if let Some(bin_dir_path) = path_buf.parent() {
                let mut path_buf = PathBuf::new();

                // Open /path/to/binary/debug_link.
                path_buf.push(bin_dir_path);
                path_buf.push(debug_link);
                if let Some(sym_file) = self.check_candidate_symbol_file(
                    metadata.build_id(),
                    &path_buf) {
                    contains_symtab |= sym_file.contains_symtab;
                    contains_dynsym |= sym_file.contains_dynsym;
                    matching_symbol_files.push(sym_file);

                    // We've found everything we need.
                    if contains_symtab && contains_dynsym {
                        return;
                    }
                }

                // Open /path/to/binary/.debug/debug_link.
                path_buf.clear();
                path_buf.push(bin_dir_path);
                path_buf.push(".debug");
                path_buf.push(debug_link);
                if let Some(sym_file) = self.check_candidate_symbol_file(
                    metadata.build_id(),
                    &path_buf) {
                    contains_symtab |= sym_file.contains_symtab;
                    contains_dynsym |= sym_file.contains_dynsym;
                    matching_symbol_files.push(sym_file);

                    // We've found everything we need.
                    if contains_symtab && contains_dynsym {
                        return;
                    }
                }

                // Open /usr/lib/debug/path/to/binary/debug_link.
                path_buf.clear();
                path_buf.push("/usr/lib/debug");
                path_buf.push(&bin_dir_path.to_str().unwrap()[1..]);
                path_buf.push(debug_link);
                if let Some(sym_file) = self.check_candidate_symbol_file(
                    metadata.build_id(),
                    &path_buf) {
                    contains_symtab |= sym_file.contains_symtab;
                    contains_dynsym |= sym_file.contains_dynsym;
                    matching_symbol_files.push(sym_file);

                    // We've found everything we need.
                    if contains_symtab && contains_dynsym {
                        return;
                    }
                }
            }
        }

        // Build-id-based debuginfo.
        if let Some(build_id) = metadata.build_id() {
            // Convert the build id to a String.
            let build_id_string: String = build_id.iter().fold(
                String::default(),
                |mut str, byte| {
                    write!(&mut str, "{:02x}", byte).unwrap_or_default();
                    str
                });
            path_buf.clear();
            path_buf.push("/usr/lib/debug/.build-id/");
            path_buf.push(format!("{}/{}.debug",
                &build_id_string[0..2],
                &build_id_string[2..]));
            if let Some(sym_file) = self.check_candidate_symbol_file(
                metadata.build_id(),
                &path_buf) {
                contains_symtab |= sym_file.contains_symtab;
                contains_dynsym |= sym_file.contains_dynsym;
                matching_symbol_files.push(sym_file);

                // We've found everything we need.
                if contains_symtab && contains_dynsym {
                    return;
                }
            }
        }

        // Fedora-specific path-based lookup.
        // Example path: /usr/lib/debug/path/to/binary/binaryname.so.debug
        path_buf.clear();
        path_buf.push("/usr/lib/debug");
        path_buf.push(format!("{}{}", &bin_path[1..], ".debug"));
        if let Some(sym_file) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            contains_symtab |= sym_file.contains_symtab;
            contains_dynsym |= sym_file.contains_dynsym;
            matching_symbol_files.push(sym_file);

            // We've found everything we need.
            if contains_symtab && contains_dynsym {
                return;
            }
        }

        // Ubuntu-specific path-based lookup.
        // Example path: /usr/lib/debug/path/to/binary/binaryname.so
        path_buf.clear();
        path_buf.push("/usr/lib/debug");
        path_buf.push(&bin_path[1..]);
        if let Some(sym_file) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            contains_symtab |= sym_file.contains_symtab;
            contains_dynsym |= sym_file.contains_dynsym;
            matching_symbol_files.push(sym_file);

            // We've found everything we need.
            if contains_symtab && contains_dynsym {
                return;
            }
        }

        // In some cases, Ubuntu puts symbols that should be in /usr/lib/debug/usr/lib/... into
        // /usr/lib/debug/lib/...
        if bin_path.len() > 9 && &bin_path[0..9] == "/usr/lib/" {
            path_buf.clear();
            path_buf.push("/usr/lib/debug/lib/");
            path_buf.push(&bin_path[9..]);
            if let Some(sym_file) = self.check_candidate_symbol_file(
                metadata.build_id(),
                &path_buf) {
                contains_symtab |= sym_file.contains_symtab;
                contains_dynsym |= sym_file.contains_dynsym;
                matching_symbol_files.push(sym_file);

                // We've found everything we need.
                if contains_symtab && contains_dynsym {
                    return;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn check_candidate_symbol_file(
        &self,
        binary_build_id: Option<&[u8; 20]>,
        filename: &PathBuf) -> Option<ElfSymbolFileMatch> {
        let file_path = Path::new(filename);
        let mut matching_sym_file = None;
        if let Ok(mut reader) = self.open_file(file_path) {

            let mut build_id_buf: [u8; 20] = [0; 20];
            if let Ok(sym_build_id) = get_build_id(&mut reader, &mut build_id_buf) {
                // If the symbol file has a build id and the binary has a build_id, compare them.
                // If one has a build id and the other does not, the symbol file does not match.
                // If neither the binary or the symbol file have a build id, consider the candidate a match.
                match sym_build_id {
                    Some(sym_id) => {
                        match binary_build_id {
                            Some(bin_id) => {
                                if build_id_equals(bin_id, sym_id) {
                                    matching_sym_file = Some(reader);
                                }
                            }
                            None => return None,
                        }
                    },
                    None => {
                        match binary_build_id {
                            Some(_) => return None,
                            None => matching_sym_file = Some(reader),
                        }
                    }
                }
            }
        }

        // If we found a match, look for symbols in the file.
        if let Some(mut reader) = matching_sym_file {
            let mut contains_symtab = false;
            let mut contains_dynsym = false;
            let mut sections = Vec::new();
            if get_section_metadata(&mut reader, None, SHT_SYMTAB, &mut sections).is_err() {
                return None;
            }
            if !sections.is_empty() {
                contains_symtab = true;
            }

            sections.clear();
            if get_section_metadata(&mut reader, None, SHT_DYNSYM, &mut sections).is_err() {
                return None;
            }
            if !sections.is_empty() {
                contains_dynsym = true;
            }

            if contains_dynsym || contains_symtab {
                let elf_match = ElfSymbolFileMatch::new(
                    reader,
                    contains_symtab,
                    contains_dynsym);

                return Some(elf_match);
            }
        }

        // If the symbol file cannot be opened, does not match, or does not contain any symbols.
        None
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
        time: u64,
        start: u64,
        end: u64,
        id: usize) -> ExportMapping {
        let mut map = ExportMapping::new(time, 0, start, end, 0, false, id);
        map.set_node(ExportDevNode::from_parts(0, 0, id as u64));
        map
    }

    #[test]
    fn find_section() {
        let mut proc = ExportProcess::new(1);
        proc.add_mapping(new_mapping(0, 0, 1023, 1));
        proc.add_mapping(new_mapping(0, 1024, 2047, 2));
        proc.add_mapping(new_mapping(0, 2048, 3071, 3));

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

        /* Should always find latest mapping */
        proc.add_mapping(new_mapping(200, 0, 1023, 4));

        let found = proc.find_section(0);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(4, found.key().ino);

        proc.add_mapping(new_mapping(100, 10, 1023, 5));

        let found = proc.find_section(10);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(4, found.key().ino);

        let found = proc.find_section(0);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(4, found.key().ino);

        proc.add_mapping(new_mapping(300, 20, 1023, 6));

        let found = proc.find_section(0);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(4, found.key().ino);

        let found = proc.find_section(20);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(6, found.key().ino);
    }

    #[test]
    fn find_mapping_for_time() {
        let mut proc = ExportProcess::new(1);

        proc.add_mapping(new_mapping(0, 0, 1023, 1));
        proc.add_mapping(new_mapping(0, 1024, 2047, 2));
        proc.add_mapping(new_mapping(0, 2048, 3071, 3));

        /* Find should work properly */
        let found = proc.find_mapping(0, Some(0));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(1, found.key().ino);

        let found = proc.find_mapping(512, Some(0));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(1, found.key().ino);

        let found = proc.find_mapping(1024, Some(0));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(2, found.key().ino);

        let found = proc.find_mapping(2000, Some(0));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(2, found.key().ino);

        let found = proc.find_mapping(2048, Some(0));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(3, found.key().ino);

        let found = proc.find_mapping(3071, Some(0));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(3, found.key().ino);

        /* Outside all should find none */
        assert!(proc.find_mapping(3072, Some(0)).is_none());

        /* Find at times before and after should work */
        proc.add_mapping(new_mapping(200, 0, 1023, 5));
        proc.add_mapping(new_mapping(100, 10, 1023, 4));
        proc.add_mapping(new_mapping(300, 20, 1023, 6));

        let found = proc.find_mapping(0, Some(0));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(1, found.key().ino);

        let found = proc.find_mapping(10, Some(100));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(4, found.key().ino);

        let found = proc.find_mapping(0, Some(200));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(5, found.key().ino);

        let found = proc.find_mapping(20, Some(1024));
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(6, found.key().ino);
    }
}
