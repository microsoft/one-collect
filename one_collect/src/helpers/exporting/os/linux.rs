use super::*;
use std::collections::hash_map::Entry;
use std::collections::hash_map::Entry::{Vacant, Occupied};
use std::path::{Path, PathBuf};

use std::fs::File;
use std::fmt::Write;
use std::io::BufReader;
use std::str::FromStr;

use crate::{ReadOnly, Writable};
use crate::event::DataFieldRef;
use crate::PathBufInteger;
use crate::openat::{OpenAt, DupFd};
use crate::procfs;
use crate::perf_event::{AncillaryData, PerfSession};
use crate::perf_event::{RingBufSessionBuilder, RingBufBuilder};
use crate::perf_event::abi::PERF_RECORD_MISC_SWITCH_OUT;
use crate::helpers::callstack::{CallstackHelp, CallstackReader};

use ruwind::elf::*;
use ruwind::ModuleAccessor;
use symbols::ElfSymbolReader;
use self::symbols::PerfMapSymbolReader;

/* OS Specific Session Type */
pub type Session = PerfSession;

/* OS Specific Session Builder Type */
pub type SessionBuilder = RingBufSessionBuilder;

#[derive(Clone)]
pub(crate) struct OSExportProcess {
    root_fs: Option<OpenAt>,
}

impl OSExportProcess {
    pub fn new() -> Self {
        Self {
            root_fs: None,
        }
    }
}

impl ExportProcess {
    pub fn add_ns_pid(
        &mut self,
        path_buf: &mut PathBuf) {
        *self.ns_pid_mut() = procfs::ns_pid(path_buf, self.pid());
    }

    pub fn add_root_fs(
        &mut self,
        path_buf: &mut PathBuf) -> anyhow::Result<()> {
        path_buf.clear();
        path_buf.push("/proc");
        path_buf.push_u32(self.pid());
        path_buf.push("root");
        path_buf.push(".");

        if let Ok(root) = File::open(path_buf) {
            self.os.root_fs = Some(OpenAt::new(root));
        }

        Ok(())
    }

    pub fn open_file(
        &self,
        path: &Path) -> anyhow::Result<File> {
        match &self.os.root_fs {
            None => {
                anyhow::bail!("Root fs is not set or had an error.");
            },
            Some(root_fs) => {
                root_fs.open_file(path)
            }
        }
    }

    pub fn add_matching_elf_symbols(
        &mut self,
        elf_metadata: &ElfBinaryMetadataLookup,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks,
        strings: &mut InternedStrings) {
        addrs.clear();
        frames.clear();

        if self.os.root_fs.is_none() {
            return;
        }

        for map_index in 0..self.mappings().len() {
            let map = self.mappings().get(map_index).unwrap();
            if map.anon() {
                continue;
            }

            Self::get_unique_user_ips(
                &self.samples(),
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

                // Find matching symbol files.
                let sym_files = self.find_symbol_files(
                    filename,
                    metadata,
                    SYMBOL_TYPE_ELF_SYMTAB | SYMBOL_TYPE_ELF_DYNSYM);

                for sym_file in sym_files {
                    let mut sym_reader = ElfSymbolReader::new(sym_file);
                    let map_mut = self.mappings_mut().get_mut(map_index).unwrap();

                    map_mut.add_matching_symbols(
                        frames,
                        &mut sym_reader,
                        strings);
                }
            }
        }
    }

    fn find_symbol_files(
        &self,
        bin_path: &str,
        metadata: &ElfBinaryMetadata,
        sym_types_requested: u32) -> Vec<File> {
        let mut symbol_files = Vec::new();
        let mut sym_types_found = 0u32;

        // Keep evaluating symbol files until we find a matching one with a symtab.
        let mut path_buf = PathBuf::new();

        // Look at the binary itself.
        path_buf.push(bin_path);
        if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            symbol_files.push(sym_file);
            sym_types_found |= types_found;
            if sym_types_found == sym_types_requested {
                return symbol_files
            }
        }

        // Look next to the binary.
        path_buf.clear();
        path_buf.push(format!("{}.dbg", bin_path));
        if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            symbol_files.push(sym_file);
            sym_types_found |= types_found;
            if sym_types_found == sym_types_requested {
                return symbol_files
            }
        }

        path_buf.clear();
        path_buf.push(format!("{}.debug", bin_path));
        if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            symbol_files.push(sym_file);
            sym_types_found |= types_found;
            if sym_types_found == sym_types_requested {
                return symbol_files
            }
        }

        // Debug link.
        if let Some(debug_link) = metadata.debug_link() {

            // Directly open debug_link.
            path_buf.clear();
            path_buf.push(debug_link);
            if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
                metadata.build_id(),
                &path_buf) {
                symbol_files.push(sym_file);
                sym_types_found |= types_found;
                if sym_types_found == sym_types_requested {
                    return symbol_files
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
                if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
                    metadata.build_id(),
                    &path_buf) {
                    symbol_files.push(sym_file);
                    sym_types_found |= types_found;
                    if sym_types_found == sym_types_requested {
                        return symbol_files
                    }
                }

                // Open /path/to/binary/.debug/debug_link.
                path_buf.clear();
                path_buf.push(bin_dir_path);
                path_buf.push(".debug");
                path_buf.push(debug_link);
                if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
                    metadata.build_id(),
                    &path_buf) {
                    symbol_files.push(sym_file);
                    sym_types_found |= types_found;
                    if sym_types_found == sym_types_requested {
                        return symbol_files
                    }
                }

                // Open /usr/lib/debug/path/to/binary/debug_link.
                path_buf.clear();
                path_buf.push("/usr/lib/debug");
                path_buf.push(&bin_dir_path.to_str().unwrap()[1..]);
                path_buf.push(debug_link);
                if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
                    metadata.build_id(),
                    &path_buf) {
                    symbol_files.push(sym_file);
                    sym_types_found |= types_found;
                    if sym_types_found == sym_types_requested {
                        return symbol_files
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
                if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
                metadata.build_id(),
                &path_buf) {
                symbol_files.push(sym_file);
                sym_types_found |= types_found;
                if sym_types_found == sym_types_requested {
                    return symbol_files
                }
            }
        }

        // Fedora-specific path-based lookup.
        // Example path: /usr/lib/debug/path/to/binary/binaryname.so.debug
        path_buf.clear();
        path_buf.push("/usr/lib/debug");
        path_buf.push(format!("{}{}", &bin_path[1..], ".debug"));
        if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            symbol_files.push(sym_file);
            sym_types_found |= types_found;
            if sym_types_found == sym_types_requested {
                return symbol_files
            }
        }

        // Ubuntu-specific path-based lookup.
        // Example path: /usr/lib/debug/path/to/binary/binaryname.so
        path_buf.clear();
        path_buf.push("/usr/lib/debug");
        path_buf.push(&bin_path[1..]);
        if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            symbol_files.push(sym_file);
            sym_types_found |= types_found;
            if sym_types_found == sym_types_requested {
                return symbol_files
            }
        }

        // In some cases, Ubuntu puts symbols that should be in /usr/lib/debug/usr/lib/... into
        // /usr/lib/debug/lib/...
        if bin_path.len() > 9 && &bin_path[0..9] == "/usr/lib/" {
            path_buf.clear();
            path_buf.push("/usr/lib/debug/lib/");
            path_buf.push(&bin_path[9..]);
            if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
                metadata.build_id(),
                &path_buf) {
                symbol_files.push(sym_file);
                sym_types_found |= types_found;
                if sym_types_found == sym_types_requested {
                    return symbol_files
                }
            }
        }

        symbol_files
    }

    fn check_candidate_symbol_file(
        &self,
        binary_build_id: Option<&[u8; 20]>,
        filename: &PathBuf) -> Option<(File, u32)> {
        let mut matching_sym_file = None;
        if let Ok(mut reader) = self.open_file(filename) {

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
            let mut sections = Vec::new();
            let mut sym_flags = 0;
            if get_section_metadata(&mut reader, None, SHT_SYMTAB, &mut sections).is_err() {
                return None;
            }
            if !sections.is_empty() {
                sym_flags |= SYMBOL_TYPE_ELF_SYMTAB;
            }

            sections.clear();
            if get_section_metadata(&mut reader, None, SHT_DYNSYM, &mut sections).is_err() {
                return None;
            }
            if !sections.is_empty() {
                sym_flags |= SYMBOL_TYPE_ELF_DYNSYM;
            }

            if sym_flags != 0 {
                return Some((reader, sym_flags));
            }
        }

        // If the symbol file cannot be opened, does not match, or does not contain any symbols.
        None
    }
}

pub(crate) struct OSExportSettings {
    process_fs: bool,
}

impl OSExportSettings {
    pub fn new() -> Self {
        Self {
            process_fs: true,
        }
    }
}

impl ExportSettings {
    pub fn without_process_fs(self) -> Self {
        let mut clone = self;
        clone.os.process_fs = false;
        clone
    }
}

pub struct ExportSampler {
    /* Common */
    pub(crate) exporter: Writable<ExportMachine>,
    pub(crate) frames: Vec<u64>,

    /* OS Specific */
    ancillary: ReadOnly<AncillaryData>,
    reader: CallstackReader,
    time_field: DataFieldRef,
    pid_field: DataFieldRef,
    tid_field: DataFieldRef,
}

impl ExportSampler {
    pub(crate) fn new(
        exporter: &Writable<ExportMachine>,
        reader: &CallstackReader,
        session: &PerfSession) -> Self {
        Self {
            exporter: exporter.clone(),
            ancillary: session.ancillary_data(),
            reader: reader.clone(),
            time_field: session.time_data_ref(),
            pid_field: session.pid_field_ref(),
            tid_field: session.tid_data_ref(),
            frames: Vec::new(),
        }
    }

    pub(crate) fn time(
        &self,
        data: &EventData) -> anyhow::Result<u64> {
        self.time_field.get_u64(data.full_data())
    }

    pub(crate) fn pid(
        &self,
        data: &EventData) -> anyhow::Result<u32> {
        self.pid_field.get_u32(data.full_data())
    }

    pub(crate) fn tid(
        &self,
        data: &EventData) -> anyhow::Result<u32> {
        self.tid_field.get_u32(data.full_data())
    }

    pub(crate) fn cpu(&self) -> u16 {
        self.ancillary.borrow().cpu() as u16
    }

    pub(crate) fn callstack(
        &mut self,
        data: &EventData) -> anyhow::Result<()> {
        Ok(self.reader.read_frames(
            data.full_data(),
            &mut self.frames))
    }
}

pub(crate) struct OSExportMachine {
    dev_nodes: ExportDevNodeLookup,
    binary_metadata: ElfBinaryMetadataLookup,
    path_buf: Writable<PathBuf>,
}

impl OSExportMachine {
    pub fn new() -> Self {
        Self {
            dev_nodes: ExportDevNodeLookup::new(),
            binary_metadata: ElfBinaryMetadataLookup::new(),
            path_buf: Writable::new(PathBuf::new()),
        }
    }
}

struct ExportDevNodeLookup {
    fds: HashMap<ExportDevNode, DupFd>,
}

impl ExportDevNodeLookup {
    pub fn new() -> Self {
        Self {
            fds: HashMap::new(),
        }
    }

    fn contains(
        &self,
        key: &ExportDevNode) -> bool {
        self.fds.contains_key(key)
    }

    fn entry(
        &mut self,
        key: ExportDevNode) -> Entry<'_, ExportDevNode, DupFd> {
        self.fds.entry(key)
    }

    pub fn open(
        &self,
        node: &ExportDevNode) -> Option<File> {
        match self.fds.get(node) {
            Some(fd) => { fd.open() },
            None => { None },
        }
    }
}

impl ModuleAccessor for ExportDevNodeLookup {
    fn open(
        &self,
        key: &ExportDevNode) -> Option<File> {
        self.open(key)
    }
}

pub struct ElfBinaryMetadata {
    build_id: Option<[u8; 20]>,
    debug_link: Option<String>,
}

impl ElfBinaryMetadata {
    pub fn new() -> Self {
        Self {
            build_id: None,
            debug_link: None,
        }
    }

    pub fn build_id(&self) -> Option<&[u8; 20]> {
        self.build_id.as_ref()
    }

    pub fn debug_link(&self) -> Option<&str> {
        match &self.debug_link {
            Some(link) => Some(link.as_str()),
            None => None,
        }
    }
}

pub struct ElfBinaryMetadataLookup {
    metadata: HashMap<ExportDevNode, ElfBinaryMetadata>
}

impl ElfBinaryMetadataLookup {
    pub fn new() -> Self {
        Self {
            metadata: HashMap::new()
        }
    }

    pub fn contains(
        &self,
        key: &ExportDevNode) -> bool {
        self.metadata.contains_key(key)
    }

    fn entry(
        &mut self,
        key: ExportDevNode) -> Entry<'_, ExportDevNode, ElfBinaryMetadata> {
        self.metadata.entry(key)
    }

    pub fn get(
        &self,
        key: &ExportDevNode) -> Option<&ElfBinaryMetadata> {
        self.metadata.get(key)
    }
}

impl ExportMachine {
    pub fn resolve_perf_map_symbols(
        &mut self) {
        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        let mut path_buf = self.os.path_buf.borrow_mut();
        path_buf.clear();
        path_buf.push("/tmp");

        for proc in self.procs.values_mut() {
            if !proc.has_anon_mappings() {
                continue;
            }

            let ns_pid = proc.ns_pid();

            if ns_pid.is_none() {
                continue;
            }

            path_buf.push(format!("perf-{}.map", ns_pid.unwrap()));
            let file = proc.open_file(&path_buf);
            path_buf.pop();

            if file.is_err() {
                continue;
            }

            let mut sym_reader = PerfMapSymbolReader::new(file.unwrap());

            proc.add_matching_anon_symbols(
                &mut addrs,
                &mut frames,
                &mut sym_reader,
                &self.callstacks,
                &mut self.strings);
        }
    }

    pub(crate) fn os_add_kernel_mappings_with(
        &mut self,
        kernel_symbols: &mut impl ExportSymbolReader) {
        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        for proc in self.procs.values_mut() {
            proc.get_unique_kernel_ips(
                &mut addrs,
                &mut frames,
                &self.callstacks);

            if addrs.is_empty() {
                continue;
            }

            let mut kernel = ExportMapping::new(
                0,
                self.strings.to_id("vmlinux"),
                KERNEL_START,
                KERNEL_END,
                0,
                false,
                self.map_index);

            self.map_index += 1;

            frames.clear();

            for addr in &addrs {
                frames.push(*addr);
            }

            kernel.add_matching_symbols(
                &mut frames,
                kernel_symbols,
                &mut self.strings);

            proc.add_mapping(kernel);
        }
    }

    pub fn resolve_elf_symbols(
        &mut self) {
        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        for proc in self.procs.values_mut() {
            proc.add_matching_elf_symbols(
                &self.os.binary_metadata,
                &mut addrs,
                &mut frames,
                &self.callstacks,
                &mut self.strings);
        }
    }

    pub fn load_elf_metadata(
        &mut self) {

        for proc in self.procs.values() {
            for map in proc.mappings() {
                if let Some(key) = map.node() {

                    // Handle each binary exactly once, regardless of of it's loaded into multiple processes.
                    if self.os.binary_metadata.contains(key) {
                        continue;
                    }

                    let elf_metadata = self.os.binary_metadata.entry(*key)
                        .or_insert(ElfBinaryMetadata::new());

                    if let Ok(filename) = self.strings.from_id(map.filename_id()) {
                        if let Ok(file) = proc.open_file(Path::new(filename)) {
                            let mut reader = BufReader::new(file);
                            let mut sections = Vec::new();
                            let mut section_offsets = Vec::new();
                            
                            if get_section_offsets(&mut reader, None, &mut section_offsets).is_err() {
                                continue;
                            }

                            if get_section_metadata(&mut reader, None, SHT_NOTE, &mut sections).is_err() {
                                continue;
                            }

                            let mut build_id: [u8; 20] = [0; 20];
                            if let Ok(id) = read_build_id(&mut reader, &sections, &section_offsets, &mut build_id) {
                                elf_metadata.build_id = id.copied();
                            }

                            sections.clear();
                            if get_section_metadata(&mut reader, None, SHT_PROGBITS, &mut sections).is_err() {
                                continue;
                            }

                            let mut debug_link_buf: [u8; 1024] = [0; 1024];
                            if let Ok(Some(debug_link)) = read_debug_link(&mut reader, &sections, &section_offsets, &mut debug_link_buf) {
                                let str_val = get_str(debug_link);
                                if let Ok(string_val) = String::from_str(str_val) {
                                    elf_metadata.debug_link = Some(string_val);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn os_add_mmap_exec(
        &mut self,
        pid: u32,
        mapping: &mut ExportMapping,
        filename: &str) -> anyhow::Result<()> {
        match mapping.node() {
            Some(node) => {
                if !self.os.dev_nodes.contains(node) {
                    if let Some(process) = self.find_process(pid) {
                        if let Ok(file) = process.open_file(Path::new(filename)) {
                            if let Vacant(entry) = self.os.dev_nodes.entry(*node) {
                                entry.insert(DupFd::new(file));
                            }
                        }
                    }
                }
            },
            None => {}
        }

        Ok(())
    }

    pub(crate) fn os_add_comm_exec(
        &mut self,
        pid: u32,
        _comm: &str) -> anyhow::Result<()> {
        let path_buf = self.os.path_buf.clone();
        let fs = self.settings.os.process_fs;

        let proc = self.process_mut(pid);
        proc.add_ns_pid(&mut path_buf.borrow_mut());

        if fs {
            proc.add_root_fs(&mut path_buf.borrow_mut())?;
        }

        Ok(())
    }

    fn fork_exec(
        &mut self,
        pid: u32,
        ppid: u32) -> anyhow::Result<()> {
        let fork = self.process_mut(ppid).fork(pid);
        self.procs.insert(pid, fork);

        Ok(())
    }

    pub fn hook_to_session(
        mut self,
        session: &mut PerfSession) -> anyhow::Result<Writable<ExportMachine>> {
        let cpu_profiling = self.settings.cpu_profiling;
        let cswitches = self.settings.cswitches;
        let events = self.settings.events.take();

        let callstack_reader = match self.settings.callstack_helper.take() {
            Some(callstack_helper) => { callstack_helper.to_reader() },
            None => { anyhow::bail!("No callstack reader specified."); }
        };

        let machine = Writable::new(self);

        let callstack_machine = machine.clone();

        let callstack_reader = callstack_reader.with_unwind(
            move |request| {
                let machine = callstack_machine.borrow_mut();

                if let Some(process) = machine.find_process(request.pid()) {
                    request.unwind_process(
                        process,
                        &machine.os.dev_nodes);
                }
            });

        if let Some(events) = events {
            let shared_sampler = Writable::new(
                ExportSampler::new(
                    &machine,
                    &callstack_reader,
                    session));

            for mut callback in events {
                if callback.event.is_none() {
                    continue;
                }

                let mut event = callback.event.take().unwrap();
                let mut event_machine = machine.borrow_mut();

                let mut builder = ExportBuiltContext::new(
                    &mut event_machine,
                    session);

                /* Invoke built callback for setup, etc */
                (callback.built)(&mut builder)?;

                let sample_kind = match builder.take_sample_kind() {
                    /* If the builder has a sample kind pre-defined, use that */
                    Some(kind) => { kind },
                    /* Otherwise, use the event name */
                    None => { event_machine.sample_kind(event.name()) }
                };

                /* Re-use sampler for all events */
                let event_sampler = shared_sampler.clone();

                /* Trampoline between event callback and exporter callback */
                event.add_callback(move |data| {
                    (callback.trace)(
                        &mut ExportTraceContext::new(
                            &mut event_sampler.borrow_mut(),
                            sample_kind,
                            data))
                });

                /* Add event to session */
                session.add_event(event)?;
            }
        }

        if cpu_profiling {
            let ancillary = session.ancillary_data();
            let time_field = session.time_data_ref();
            let pid_field = session.pid_field_ref();
            let tid_field = session.tid_data_ref();
            let reader = callstack_reader.clone();

            /* Get sample kind for CPU */
            let kind = machine.borrow_mut().sample_kind("cpu");

            /* Hook cpu profile event */
            let event = session.cpu_profile_event();
            let event_machine = machine.clone();
            let mut frames: Vec<u64> = Vec::new();

            event.add_callback(move |data| {
                let full_data = data.full_data();

                let ancillary = ancillary.borrow();

                let cpu = ancillary.cpu() as u16;
                let time = time_field.get_u64(full_data)?;
                let pid = pid_field.get_u32(full_data)?;
                let tid = tid_field.get_u32(full_data)?;

                frames.clear();

                reader.read_frames(
                    full_data,
                    &mut frames);

                event_machine.borrow_mut().add_sample(
                    time,
                    1,
                    pid,
                    tid,
                    cpu,
                    kind,
                    &frames)
            });
        }

        if cswitches {
            let ancillary = session.ancillary_data();
            let time_field = session.time_data_ref();
            let pid_field = session.pid_field_ref();
            let tid_field = session.tid_data_ref();
            let reader = callstack_reader.clone();

            /* Get sample kind for cswitch */
            let kind = machine.borrow_mut().sample_kind("cswitch");

            /* Hook cswitch profile event */
            let event = session.cswitch_profile_event();
            let event_machine = machine.clone();
            let mut frames: Vec<u64> = Vec::new();

            event.add_callback(move |data| {
                let full_data = data.full_data();

                let ancillary = ancillary.borrow();

                let cpu = ancillary.cpu() as u16;
                let time = time_field.get_u64(full_data)?;
                let pid = pid_field.get_u32(full_data)?;
                let tid = tid_field.get_u32(full_data)?;

                /* Ignore scheduler switches */
                if pid == 0 || tid == 0 {
                    return Ok(());
                }

                frames.clear();

                reader.read_frames(
                    full_data,
                    &mut frames);

                let mut machine = event_machine.borrow_mut();

                let sample = machine.make_sample(
                    time,
                    0,
                    tid,
                    cpu,
                    kind,
                    &frames);

                /* Stash away the sample until switch-in */
                machine.cswitches.entry(tid).or_default().sample = Some(sample);

                Ok(())
            });

            let misc_field = session.misc_data_ref();
            let time_field = session.time_data_ref();
            let pid_field = session.pid_field_ref();
            let tid_field = session.tid_data_ref();

            /* Hook cswitch swap event */
            let event = session.cswitch_event();
            let event_machine = machine.clone();

            event.add_callback(move |data| {
                let full_data = data.full_data();

                let misc = misc_field.get_u16(full_data)?;
                let time = time_field.get_u64(full_data)?;
                let pid = pid_field.get_u32(full_data)?;
                let tid = tid_field.get_u32(full_data)?;

                /* Ignore scheduler switches */
                if pid == 0 || tid == 0 {
                    return Ok(());
                }

                let mut machine = event_machine.borrow_mut();

                match machine.cswitches.entry(tid) {
                    Occupied(mut entry) => {
                        let entry = entry.get_mut();

                        if misc & PERF_RECORD_MISC_SWITCH_OUT == 0 {
                            /* Switch in */

                            /* Sanity check time duration */
                            if entry.start_time == 0 {
                                /* Unexpected, clear and don't record. */
                                let _ = entry.sample.take();
                                return Ok(());
                            }

                            let start_time = entry.start_time;
                            let duration = time - start_time;

                            /* Reset time as a precaution */
                            entry.start_time = 0;

                            /* Record sample if we got callchain data */
                            if let Some(mut sample) = entry.sample.take() {
                                /*
                                 * Record cswitch sample for duration of wait
                                 * We have to modify these values since the
                                 * callchain can be delayed from the actual
                                 * cswitch time, and we don't know the full
                                 * delay period (value) until now.
                                 */
                                *sample.time_mut() = start_time;
                                *sample.value_mut() = duration;

                                machine.process_mut(pid).add_sample(sample);
                            }
                        } else {
                            /* Switch out */

                            /* Keep track of switch out time */
                            entry.start_time = time;
                        }
                    },
                    _ => { }
                }

                Ok(())
            });
        }

        /* Hook mmap records */
        let time_field = session.time_data_ref();
        let event = session.mmap_event();
        let event_machine = machine.clone();
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("pid");
        let addr = fmt.get_field_ref_unchecked("addr");
        let len = fmt.get_field_ref_unchecked("len");
        let pgoffset = fmt.get_field_ref_unchecked("pgoffset");
        let maj = fmt.get_field_ref_unchecked("maj");
        let min = fmt.get_field_ref_unchecked("min");
        let ino = fmt.get_field_ref_unchecked("ino");
        let prot = fmt.get_field_ref_unchecked("prot");
        let filename = fmt.get_field_ref_unchecked("filename[]");

        const PROT_EXEC: u32 = 4;
        event.add_callback(move |data| {
            let fmt = data.format();
            let full_data = data.full_data();
            let data = data.event_data();

            let prot = fmt.get_u32(prot, data)?;

            /* Skip non-executable mmaps */
            if prot & PROT_EXEC != PROT_EXEC {
                return Ok(());
            }

            event_machine.borrow_mut().add_mmap_exec(
                time_field.get_u64(full_data)?,
                fmt.get_u32(pid, data)?,
                fmt.get_u64(addr, data)?,
                fmt.get_u64(len, data)?,
                fmt.get_u64(pgoffset, data)?,
                fmt.get_u32(maj, data)?,
                fmt.get_u32(min, data)?,
                fmt.get_u64(ino, data)?,
                fmt.get_str(filename, data)?)
        });

        /* Hook comm records */
        let event = session.comm_event();
        let event_machine = machine.clone();
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("pid");
        let tid = fmt.get_field_ref_unchecked("tid");
        let comm = fmt.get_field_ref_unchecked("comm[]");

        event.add_callback(move |data| {
            let fmt = data.format();
            let data = data.event_data();

            let pid = fmt.get_u32(pid, data)?;
            let tid = fmt.get_u32(tid, data)?;

            if pid != tid {
                return Ok(())
            }

            event_machine.borrow_mut().add_comm_exec(
                pid,
                fmt.get_str(comm, data)?)
        });

        /* Hook fork records */
        let event = session.fork_event();
        let event_machine = machine.clone();
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("pid");
        let ppid = fmt.get_field_ref_unchecked("ppid");
        let tid = fmt.get_field_ref_unchecked("tid");

        event.add_callback(move |data| {
            let fmt = data.format();
            let data = data.event_data();

            let pid = fmt.get_u32(pid, data)?;
            let tid = fmt.get_u32(tid, data)?;

            if pid != tid {
                return Ok(());
            }

            event_machine.borrow_mut().fork_exec(
                pid,
                fmt.get_u32(ppid, data)?)
        });

        Ok(machine)
    }
}

impl ExportBuilderHelp for RingBufSessionBuilder {
    fn with_exporter_events(
        self,
        settings: &ExportSettings) -> Self {
        let mut builder = self;

        let mut kernel = RingBufBuilder::for_kernel()
            .with_mmap_records()
            .with_comm_records()
            .with_task_records();

        if settings.cpu_profiling {
            let profiling = RingBufBuilder::for_profiling(settings.cpu_freq);

            builder = builder.with_profiling_events(profiling);
        }

        if settings.cswitches {
            let cswitches = RingBufBuilder::for_cswitches();

            builder = builder.with_cswitch_events(cswitches);
            kernel = kernel.with_cswitch_records();
        }

        if settings.events.is_some() {
            let tracepoint = RingBufBuilder::for_tracepoint();

            builder = builder.with_tracepoint_events(tracepoint);
        }

        builder = builder.with_kernel_events(kernel);

        match &settings.callstack_helper {
            Some(callstack_helper) => {
                builder.with_callstack_help(callstack_helper)
            },
            None => { builder },
        }
    }
}

impl ExportSessionHelp for PerfSession {
    fn build_exporter(
        &mut self,
        settings: ExportSettings) -> anyhow::Result<Writable<ExportMachine>> {
        let exporter = ExportMachine::new(settings);

        exporter.hook_to_session(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::os::linux::fs::MetadataExt;
    use std::str::FromStr;

    use crate::tracefs::TraceFS;
    use crate::perf_event::RingBufSessionBuilder;
    use crate::helpers::callstack::CallstackHelper;

    #[test]
    #[ignore]
    fn it_works() {
        let helper = CallstackHelper::new()
            .with_dwarf_unwinding();

        let mut settings = ExportSettings::new(helper);

        /* Hookup page_fault as a new event sample */
        let tracefs = TraceFS::open().unwrap();
        let user_fault = tracefs.find_event("exceptions", "page_fault_user").unwrap();
        let kernel_fault = tracefs.find_event("exceptions", "page_fault_kernel").unwrap();

        settings = settings.with_event(
            user_fault,
            move |builder| {
                /* Set default sample kind */
                builder.set_sample_kind("page_fault_user");
                Ok(())
            },
            move |tracer| {
                /* Create default sample */
                tracer.add_sample(1)
            });

        settings = settings.with_event(
            kernel_fault,
            move |builder| {
                /* Set default sample kind */
                builder.set_sample_kind("page_fault_kernel");
                Ok(())
            },
            move |tracer| {
                /* Create default sample */
                tracer.add_sample(1)
            });

        let mut builder = RingBufSessionBuilder::new()
            .with_page_count(256)
            .with_exporter_events(&settings);

        let mut session = builder.build().unwrap();

        let exporter = session.build_exporter(settings).unwrap();

        let duration = std::time::Duration::from_secs(1);

        session.lost_event().add_callback(|_| {
            println!("WARN: Lost event data");

            Ok(())
        });

        session.lost_samples_event().add_callback(|_| {
            println!("WARN: Lost samples data");

            Ok(())
        });

        session.capture_environment();
        session.enable().unwrap();
        session.parse_for_duration(duration).unwrap();
        session.disable().unwrap();

        let mut exporter = exporter.borrow_mut();

        /* Pull in more data, if wanted */
        exporter.add_kernel_mappings();

        /* Dump state */
        let strings = exporter.strings();

        println!("File roots:");
        for process in exporter.processes() {
            let mut comm = "Unknown";

            if let Some(comm_id) = process.comm_id() {
                if let Ok(value) = strings.from_id(comm_id) {
                    comm = value;
                }
            }

            let file = process.open_file(Path::new("."));

            match file {
                Ok(file) => {
                    match file.metadata() {
                        Ok(meta) => {
                            println!("{}: ino: {}, dev: {}", comm, meta.st_ino(), meta.st_dev());
                        },
                        Err(error) => {
                            println!("Error({}): {:?}", comm, error);
                        }
                    }
                },
                Err(error) => {
                    println!("Error({}): {:?}", comm, error);
                }
            }
        }

        let kinds = exporter.sample_kinds();

        for process in exporter.processes() {
            let mut comm = "Unknown";

            if let Some(comm_id) = process.comm_id() {
                if let Ok(value) = strings.from_id(comm_id) {
                    comm = value;
                }
            }

            println!(
                "{}: {} ({} Samples)",
                process.pid(),
                comm,
                process.samples().len());

            for sample in process.samples() {
                println!(
                    "{}: {:x} ({}) TID={},Kind={},Value={}",
                    sample.time(),
                    sample.ip(),
                    sample.callstack_id(),
                    sample.tid(),
                    kinds[sample.kind() as usize],
                    sample.value());
            }

            if process.samples().len() > 0 {
                println!();
            }
        }
    }

    #[test]
    #[ignore]
    fn kernel_symbols() {
        let mut reader = KernelSymbolReader::new();
        let mut count = 0;

        reader.reset();

        while reader.next() {
            println!(
                "{:x} - {:x}: {}",
                reader.start(),
                reader.end(),
                reader.name());

            count += 1;
        }

        assert!(count > 0);
    }

    #[test]
    fn binary_metadata_lookup() {
        let mut metadata_lookup = ElfBinaryMetadataLookup::new();

        let dev_node_1 = ExportDevNode::new(1,2);
        assert!(!metadata_lookup.contains(&dev_node_1));
        let entry = metadata_lookup.entry(dev_node_1)
            .or_insert(ElfBinaryMetadata::new());

        let symbol_file_path = "/path/to/symbol/file";
        entry.debug_link = Some(String::from_str(symbol_file_path).unwrap());

        assert!(metadata_lookup.contains(&dev_node_1));
        let result = metadata_lookup.get(&dev_node_1).unwrap();
        match &result.debug_link {
            Some(path) => assert_eq!(path.as_str(), symbol_file_path),
            None => assert!(false)
        }

        let dev_node_2 = ExportDevNode::new(2, 3);
        assert!(!metadata_lookup.contains(&dev_node_2));
        assert!(metadata_lookup.contains(&dev_node_1));
    }
}
