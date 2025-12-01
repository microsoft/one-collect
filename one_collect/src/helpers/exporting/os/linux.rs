// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::hash_map::Entry;
use std::collections::hash_map::Entry::{Vacant, Occupied};
use std::path::{Path, PathBuf};

use std::fs::File;
use std::fmt::Write;
use std::io::BufReader;
use tracing::{debug};

use crate::{ReadOnly, Writable};
use crate::event::DataFieldRef;
use crate::PathBufInteger;
use crate::openat::{OpenAt, DupFd};
use crate::procfs;
use crate::perf_event::{AncillaryData, PerfSession};
use crate::perf_event::{RingBufSessionBuilder, RingBufBuilder};
use crate::perf_event::abi::PERF_RECORD_MISC_SWITCH_OUT;
use crate::helpers::callstack::{CallstackHelp, CallstackReader};
use crate::helpers::exporting::*;
use crate::helpers::exporting::process::{ExportProcessOSHooks, MetricValue};
use crate::helpers::exporting::universal::*;
use crate::helpers::exporting::modulemetadata::{ModuleMetadata, ElfModuleMetadata};
use crate::page_size_to_mask;
use crate::os::system_page_size;

use ruwind::elf::*;
use ruwind::{ModuleAccessor, UnwindType};
use symbols::{ElfSymbolReader, R2RLoadedLayoutSymbolTransformer, R2RMapSymbolReader};
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

trait ExportProcessLinuxExt {
    fn add_root_fs(
        &mut self,
        path_buf: &mut PathBuf) -> anyhow::Result<()>;

    fn add_matching_elf_symbols(
        &mut self,
        elf_metadata: &ModuleMetadataLookup,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks,
        strings: &mut InternedStrings);

    fn find_symbol_files(
        &self,
        bin_path: &str,
        metadata: &ElfModuleMetadata,
        sym_types_requested: u32,
        strings: &InternedStrings) -> Vec<File>;

    fn check_candidate_symbol_file(
        &self,
        binary_build_id: Option<&[u8; 20]>,
        filename: &PathBuf) -> Option<(File, u32)>;

    fn add_matching_readytorun_symbols(
        &mut self,
        pe_metadata: &ModuleMetadataLookup,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks,
        strings: &mut InternedStrings);

    fn find_readytorun_map_file(
        &self,
        bin_path: &str,
        metadata: &PEModuleMetadata,
        strings: &InternedStrings) -> Option<R2RMapSymbolReader>;
}

impl ExportProcessLinuxExt for ExportProcess {
    fn add_root_fs(
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

    fn add_matching_elf_symbols(
        &mut self,
        elf_metadata: &ModuleMetadataLookup,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks,
        strings: &mut InternedStrings) {
        addrs.clear();
        frames.clear();

        if self.os.root_fs.is_none() {
            return;
        }

        let page_size = self.system_page_size();
        let page_mask = self.system_page_mask();

        for map_index in 0..self.mappings().len() {
            let map = self.mappings().get(map_index).unwrap();
            if map.anon() {
                continue;
            }

            ExportProcess::get_unique_user_ips(
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
            if let Some(ModuleMetadata::Elf(metadata)) = elf_metadata.get(dev_node) {

                // Find matching symbol files.
                let sym_files = self.find_symbol_files(
                    filename,
                    metadata,
                    SYMBOL_TYPE_ELF_SYMTAB | SYMBOL_TYPE_ELF_DYNSYM,
                    strings);

                for sym_file in sym_files {

                    // Page align the values from the load header.
                    let p_offset = metadata.p_offset() & page_mask;
                    let p_vaddr = metadata.p_vaddr() & page_mask;

                    let load_header = ElfLoadHeader::new(p_offset, p_vaddr);
                    let mut sym_reader = ElfSymbolReader::new(sym_file, load_header, page_size);
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
        metadata: &ElfModuleMetadata,
        sym_types_requested: u32,
        strings: &InternedStrings) -> Vec<File> {
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
        if let Some(debug_link) = metadata.debug_link(strings) {
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

    fn add_matching_readytorun_symbols(
        &mut self,
        pe_metadata: &ModuleMetadataLookup,
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
            if let Some(ModuleMetadata::PE(metadata)) = pe_metadata.get(dev_node) {
                // Find the matching r2rmap file.
                if let Some(sym_reader) = self.find_readytorun_map_file(filename, metadata, strings) {
                    let mut transform_sym_reader = R2RLoadedLayoutSymbolTransformer::new(sym_reader, metadata.text_loaded_layout_offset());
                    // NOTE: Safe to call unwrap here because map_index represents the index into the currently borrowed Vec<ExportMapping>.
                    // This is simply done to avoid having an immutably-borrowed ExportMapping when we need a mutably-borrowed ExportMapping here.
                    let map_mut = self.mappings_mut().get_mut(map_index).unwrap();
                    map_mut.add_matching_symbols(
                        frames,
                        &mut transform_sym_reader,
                        strings);
                }
            }
        }
    }

    fn find_readytorun_map_file(
        &self,
        bin_path: &str,
        metadata: &PEModuleMetadata,
        strings: &InternedStrings) -> Option<R2RMapSymbolReader> {
        let mut path_buf = PathBuf::new();

        // Get the directory containing the binary.
        path_buf.push(bin_path);
        path_buf.pop();

        // Concatenate the r2rmap file name onto the binary directory to look for the file next to the binary.
        if let Some(filename) = metadata.perfmap_name(strings) {
            path_buf.push(filename);

            if let Ok(file) = self.open_file(&path_buf) {
                let mut reader = R2RMapSymbolReader::new(file);
                reader.reset();

                // The signature must be non-zero and match.
                if *metadata.perfmap_sig() != [0; 16] && metadata.perfmap_sig() == reader.signature() {
                    return Some(reader);
                }
            }
        }

        // The file could not be opened or the signature does not match.
        None
    }
}

#[cfg(target_os = "linux")]
impl ExportProcessOSHooks for ExportProcess {
    fn os_open_file(
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

    fn system_page_mask(&self) -> u64 {
        let page_size = self.system_page_size();
        page_size_to_mask(page_size)
    }

    fn system_page_size(&self) -> u64 {
        system_page_size()
    }
}

pub(crate) fn default_export_settings() -> ExportSettings {
        let helper = if cfg!(target_arch="x86_64") {
            /* X64 Linux */

            /*
             * TODO:
             * When SFRAME is supported, we should query to see
             * if SFRAME is being supported. If so, we don't need
             * to use DWARF anymore.
             */
            CallstackHelper::new().with_dwarf_unwinding()
        } else {
            /* Non-X64 Linux */
            CallstackHelper::new()
        };

        ExportSettings::new(helper)
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

pub trait ExportSettingsLinuxExt {
    fn without_process_fs(self) -> Self;
}

impl ExportSettingsLinuxExt for ExportSettings {
    fn without_process_fs(self) -> Self {
        let mut clone = self;
        clone.os.process_fs = false;
        clone
    }
}

pub(crate) struct OSExportSampler {
    reader: CallstackReader,
    ancillary: ReadOnly<AncillaryData>,
    time_field: DataFieldRef,
    pid_field: DataFieldRef,
    tid_field: DataFieldRef,
}

impl OSExportSampler {
    fn new(
        session: &PerfSession,
        reader: &CallstackReader) -> Self {
        Self {
            reader: reader.clone(),
            ancillary: session.ancillary_data(),
            time_field: session.time_data_ref(),
            pid_field: session.pid_field_ref(),
            tid_field: session.tid_data_ref(),
        }
    }
}

#[cfg(target_os = "linux")]
impl ExportSamplerOSHooks for ExportSampler {
    fn os_event_time(
        &self,
        data: &EventData) -> anyhow::Result<u64> {
        self.os.time_field.get_u64(data.full_data())
    }

    fn os_event_pid(
        &self,
        data: &EventData) -> anyhow::Result<u32> {
        self.os.pid_field.get_u32(data.full_data())
    }

    fn os_event_tid(
        &self,
        data: &EventData) -> anyhow::Result<u32> {
        self.os.tid_field.get_u32(data.full_data())
    }

    fn os_event_cpu(
        &self,
        _data: &EventData) -> anyhow::Result<u16> {
        Ok(self.os.ancillary.borrow().cpu() as u16)
    }

    fn os_event_version(
        &self,
        _data: &EventData) -> anyhow::Result<Option<u16>> {
        Ok(None)
    }

    fn os_event_op_code(
        &self,
        _data: &EventData) -> anyhow::Result<Option<u16>> {
        Ok(None)
    }

    fn os_event_span_id(
        &self,
        _data: &EventData) -> anyhow::Result<Option<[u8; 8]>> {
        Ok(None)
    }

    fn os_event_trace_id(
        &self,
        _data: &EventData) -> anyhow::Result<Option<[u8; 16]>> {
        Ok(None)
    }

    fn os_event_activity_id(
        &self,
        _data: &EventData) -> anyhow::Result<Option<[u8; 16]>> {
        Ok(None)
    }

    fn os_event_related_activity_id(
        &self,
        _data: &EventData) -> anyhow::Result<Option<[u8; 16]>> {
        Ok(None)
    }

    fn os_event_callstack(
        &mut self,
        data: &EventData) -> anyhow::Result<()> {
        Ok(self.os.reader.read_frames(
            data.full_data(),
            &mut self.frames))
    }
}

pub(crate) struct OSExportMachine {
    cswitches: HashMap<u32, ExportCSwitch>,
    dev_nodes: ExportDevNodeLookup,
    path_buf: Writable<PathBuf>,
}

impl OSExportMachine {
    pub fn new() -> Self {
        Self {
            cswitches: HashMap::new(),
            dev_nodes: ExportDevNodeLookup::new(),
            path_buf: Writable::new(PathBuf::new()),
        }
    }

    fn fork_exec(
        machine: &mut ExportMachine,
        pid: u32,
        ppid: u32) -> anyhow::Result<()> {
        let fork = machine.process_mut(ppid).fork(pid);
        machine.procs.insert(pid, fork);

        Ok(())
    }

    fn event_sampled_count_closure(
        machine: &Writable<ExportMachine>,
        session: &PerfSession,
        callstack_reader: &CallstackReader,
        kind: &str) -> impl FnMut(&EventData) -> anyhow::Result<()> + 'static {
        let ancillary = session.ancillary_data();
        let time_field = session.time_data_ref();
        let pid_field = session.pid_field_ref();
        let tid_field = session.tid_data_ref();
        let reader = callstack_reader.clone();

        /* Get sample kind for event */
        let kind = machine.borrow_mut().sample_kind(kind);

        /* Hook event to counted sample with stack */
        let event_machine = machine.clone();
        let mut frames: Vec<u64> = Vec::new();

        move |data| {
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
                MetricValue::Count(1),
                pid,
                tid,
                cpu,
                kind,
                &frames)
        }
    }

    fn hook_to_perf_session(
        mut machine: ExportMachine,
        session: &mut PerfSession) -> anyhow::Result<Writable<ExportMachine>> {
        let cpu_profiling = machine.settings.cpu_profiling;
        let cswitches = machine.settings.cswitches;
        let soft_page_faults = machine.settings.soft_page_faults;
        let hard_page_faults = machine.settings.hard_page_faults;
        let events = machine.settings.events.take();

        let callstack_reader = match machine.settings.callstack_helper.take() {
            Some(callstack_helper) => { callstack_helper.to_reader() },
            None => { anyhow::bail!("No callstack reader specified."); }
        };

        let empty_record_type = machine.record_type(ExportRecordType::default());

        let machine = Writable::new(machine);

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
                    OSExportSampler::new(
                        session,
                        &callstack_reader)));

            let shared_proxy = Writable::new(ExportProxy::default());

            for mut callback in events {
                if callback.event.is_none() {
                    continue;
                }

                let mut event = callback.event.take().unwrap();
                let mut event_machine = machine.borrow_mut();

                let mut builder = ExportBuiltContext::new(
                    &mut event_machine,
                    &event,
                    session);

                /* Invoke built callback for setup, etc */
                (callback.built)(&mut builder)?;

                /* Must take these to allow builder to drop */
                let sample_kind = builder.take_sample_kind();
                let record_type = builder.take_record_type();

                let sample_kind = match sample_kind {
                    /* If the builder has a sample kind pre-defined, use that */
                    Some(kind) => { kind },
                    /* Otherwise, use the event name */
                    None => { event_machine.sample_kind(event.name()) }
                };

                let record_type = match record_type {
                    /* If the builder has a record type defined, use that */
                    Some(record_type) => { record_type },
                    /* Otherwise, use an empty record type */
                    None => { empty_record_type },
                };

                /* Re-use sampler for all events */
                let event_sampler = shared_sampler.clone();
                let event_proxy = shared_proxy.clone();

                /* Trampoline between event callback and exporter callback */
                event.add_callback(move |data| {
                    (callback.trace)(
                        &mut ExportTraceContext::new(
                            event_sampler.clone(),
                            event_proxy.clone(),
                            sample_kind,
                            record_type,
                            data))
                });

                if event.get_proxy_id().is_some() {
                    shared_proxy.borrow_mut().add_event(event);
                } else {
                    /* Add event to session */
                    session.add_event(event)?;
                }
            }
        }

        if cpu_profiling {
            let closure = Self::event_sampled_count_closure(
                &machine,
                session,
                &callstack_reader,
                "cpu");

            session.cpu_profile_event().add_callback(closure);
        }

        if soft_page_faults {
            let closure = Self::event_sampled_count_closure(
                &machine,
                session,
                &callstack_reader,
                "soft_page_fault");

            session.soft_page_fault_event().add_callback(closure);
        }

        if hard_page_faults {
            let closure = Self::event_sampled_count_closure(
                &machine,
                session,
                &callstack_reader,
                "hard_page_fault");

            session.hard_page_fault_event().add_callback(closure);
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
                    MetricValue::Duration(0),
                    tid,
                    cpu,
                    kind,
                    &frames);

                /* Stash away the sample until switch-in */
                machine.os.cswitches.entry(tid).or_default().sample = Some(sample);

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

                match machine.os.cswitches.entry(tid) {
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
                                *sample.value_mut() = MetricValue::Duration(duration);

                                let _ = machine.add_process_sample(pid, sample);
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
        let time_field = session.time_data_ref();
        let event = session.comm_event();
        let event_machine = machine.clone();
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("pid");
        let tid = fmt.get_field_ref_unchecked("tid");
        let comm = fmt.get_field_ref_unchecked("comm[]");

        event.add_callback(move |data| {
            let fmt = data.format();
            let full_data = data.full_data();
            let data = data.event_data();

            let pid = fmt.get_u32(pid, data)?;
            let tid = fmt.get_u32(tid, data)?;

            if pid != tid {
                return Ok(())
            }

            event_machine.borrow_mut().add_comm_exec(
                pid,
                fmt.get_str(comm, data)?,
                time_field.get_u64(full_data)?)
        });

        /* Hook exit records */
        let time_field = session.time_data_ref();
        let event = session.exit_event();
        let event_machine = machine.clone();
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("pid");

        event.add_callback(move |data| {
            let fmt = data.format();
            let full_data = data.full_data();
            let data = data.event_data();

            let pid = fmt.get_u32(pid, data)?;

            event_machine.borrow_mut().add_comm_exit(
                pid,
                time_field.get_u64(full_data)?)
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

            Self::fork_exec(
                &mut event_machine.borrow_mut(),
                pid,
                fmt.get_u32(ppid, data)?)
        });

        Ok(machine)
    }

    fn resolve_perf_map_symbols(
        machine: &mut ExportMachine) {
        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        let mut path_buf = machine.os.path_buf.borrow_mut();
        path_buf.clear();
        path_buf.push("/tmp");

        for proc in machine.procs.values_mut() {
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
                &machine.callstacks,
                &mut machine.strings);
        }
    }

    fn resolve_readytorun_symbols(
        machine: &mut ExportMachine) {
        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        for proc in machine.procs.values_mut() {
            proc.add_matching_readytorun_symbols(
                &machine.module_metadata,
                &mut addrs,
                &mut frames,
                &machine.callstacks,
                &mut machine.strings);
        }
    }

    fn resolve_elf_symbols(
        machine: &mut ExportMachine) {
        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        for proc in machine.procs.values_mut() {
            proc.add_matching_elf_symbols(
                &machine.module_metadata,
                &mut addrs,
                &mut frames,
                &machine.callstacks,
                &mut machine.strings);
        }
    }

    fn load_elf_metadata(
        machine: &mut ExportMachine) {
        let mut package_buf = Vec::new();

        for proc in machine.procs.values() {
            for map in proc.mappings() {
                if let Some(key) = map.node() {

                    // Handle each binary exactly once, regardless of of it's loaded into multiple processes.
                    if machine.module_metadata.contains(key) {
                        continue;
                    }

                    // Skip anonymous mappings.
                    if map.anon() {
                        continue;
                    }

                    if let Ok(filename) = machine.strings.from_id(map.filename_id()) {
                        if let Ok(file) = proc.open_file(Path::new(filename)) {
                            let mut reader = BufReader::new(file);
                            let mut sections = Vec::new();
                            let mut section_offsets = Vec::new();

                            if is_elf_file(&mut reader).unwrap_or(false) {
                                if let ModuleMetadata::Elf(elf_metadata) = machine.module_metadata.entry(*key)
                                    .or_insert(ModuleMetadata::Elf(ElfModuleMetadata::new())) {

                                    if get_section_offsets(&mut reader, None, &mut section_offsets).is_err() {
                                        continue;
                                    }

                                    if get_section_metadata(&mut reader, None, SHT_NOTE, &mut sections).is_err() {
                                        continue;
                                    }

                                    let mut build_id: [u8; 20] = [0; 20];
                                    if let Ok(id) = read_build_id(&mut reader, &sections, &section_offsets, &mut build_id) {
                                        elf_metadata.set_build_id(id);
                                    }

                                    // Read the load header from the binary to get p_vaddr and p_offset
                                    if let Ok(load_header) = get_load_header(&mut reader) {
                                        elf_metadata.set_p_offset(load_header.p_offset());
                                        elf_metadata.set_p_vaddr(load_header.p_vaddr());
                                    }

                                    if read_package_metadata(&mut reader, &sections, &section_offsets, &mut package_buf).is_ok() {
                                        if let Ok(metadata) = std::str::from_utf8(&package_buf) {
                                            elf_metadata.set_version_metadata(metadata, &mut machine.strings);
                                        }
                                    }

                                    sections.clear();
                                    if get_section_metadata(&mut reader, None, SHT_PROGBITS, &mut sections).is_err() {
                                        continue;
                                    }

                                    let mut debug_link_buf: [u8; 1024] = [0; 1024];
                                    if let Ok(Some(debug_link)) = read_debug_link(&mut reader, &sections, &section_offsets, &mut debug_link_buf) {
                                        let str_val = get_str(debug_link);
                                        debug!("ELF debug link: link={}", str_val);
                                        elf_metadata.set_debug_link(Some(str_val.to_owned()), &mut machine.strings);
                                    }
                                }
                            }
                        }
                    }
                }
            }
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

#[cfg(target_os = "linux")]
impl ExportMachineOSHooks for ExportMachine {
    fn os_add_kernel_mappings_with(
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
                self.map_index,
                UnwindType::DWARF);

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

    fn os_add_dynamic_symbol(
        &mut self,
        symbol: &DynamicSymbol) -> anyhow::Result<()> {
        let pid = symbol.pid();

        if let Some(proc) = self.find_process(pid) {
            if proc.needs_dynamic_symbol(symbol, &self.callstacks) {
                let symbol = symbol.to_export_time_symbol(self);

                self.process_mut(pid).add_dynamic_symbol(symbol);
            }
        }

        Ok(())
    }

    fn os_add_mmap_exec(
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

    fn os_add_comm_exec(
        &mut self,
        pid: u32,
        _comm: &str) -> anyhow::Result<()> {
        let path_buf = self.os.path_buf.clone();
        let fs = self.settings.os.process_fs;

        let proc = self.process_mut(pid);
        let mut path_buf = path_buf.borrow_mut();

        *proc.ns_pid_mut() = procfs::ns_pid(&mut path_buf, pid);

        if fs {
            proc.add_root_fs(&mut path_buf)?;
        }

        Ok(())
    }

    fn os_capture_file_symbol_metadata(&mut self) {
        OSExportMachine::load_elf_metadata(self);
        self.load_pe_metadata();
    }

    fn os_resolve_local_file_symbols(&mut self) {
        OSExportMachine::resolve_elf_symbols(self);
        OSExportMachine::resolve_readytorun_symbols(self);
    }

    fn os_resolve_local_anon_symbols(&mut self) {
        OSExportMachine::resolve_perf_map_symbols(self);
    }

    fn os_qpc_time() -> u64 {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };

        unsafe {
            libc::clock_gettime(
                libc::CLOCK_MONOTONIC_RAW,
                &mut t);
        }

        ((t.tv_sec * 1000000000) + t.tv_nsec) as u64
    }

    fn os_qpc_freq() -> u64 {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };

        unsafe {
            libc::clock_getres(
                libc::CLOCK_MONOTONIC_RAW,
                &mut t);
        }

        (1000000000 / t.tv_nsec) as u64
    }

    fn os_cpu_count() -> u32 {
        unsafe {
            libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as u32
        }
    }

    fn os_system_page_size() -> u64 {
        system_page_size()
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

        if settings.soft_page_faults {
            let faults = RingBufBuilder::for_soft_page_faults();

            builder = builder.with_soft_page_faults_events(faults);
        }

        if settings.hard_page_faults {
            let faults = RingBufBuilder::for_hard_page_faults();

            builder = builder.with_hard_page_faults_events(faults);
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
        OSExportMachine::hook_to_perf_session(
            ExportMachine::new(settings),
            self)
    }
}

#[cfg(target_os = "linux")]
impl UniversalExporterOSHooks for UniversalExporter {
    fn os_parse_until(
        mut self,
        _name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>> {
        let settings = self.settings()?;

        let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) as usize };

        let page_count = self.cpu_buf_bytes() / page_size;

        let mut builder = RingBufSessionBuilder::new()
            .with_page_count(page_count)
            .with_exporter_events(&settings);

        if let Some(target_pids) = &settings.target_pids {
            for pid in target_pids {
                builder = builder.with_target_pid(*pid);
            }
        }

        let mut builder = self.run_build_hooks(builder)?;

        let mut session = builder.build()?;

        let exporter = session.build_exporter(settings)?;

        /* Put in closure so we can contain errors */
        let os_parse_loop = || {
            self.run_export_hooks(&exporter)?;

            session.capture_environment();

            exporter.borrow_mut().mark_start();
            session.enable()?;
            session.parse_until(until)?;
            session.disable()?;
            exporter.borrow_mut().mark_end();

            self.run_parsed_hooks(&exporter)?;

            Ok(())
        };

        /* Ensure we always cleanup exporter upon failure */
        match os_parse_loop() {
            Ok(()) => Ok(exporter),
            Err(err) => {
                exporter.borrow_mut().cleanup();

                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::os::linux::fs::MetadataExt;

    use crate::tracefs::TraceFS;
    use crate::perf_event::RingBufSessionBuilder;
    use crate::helpers::callstack::CallstackHelper;

    use graph::{DefaultExportGraphMetricValueConverter, ExportGraphMetricValueConverter};

    #[test]
    #[ignore]
    fn it_works() {
        let helper = CallstackHelper::new()
            .with_dwarf_unwinding();

        let mut settings = ExportSettings::new(helper)
            .with_cpu_profiling(1000)
            .with_cswitches();

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
                tracer.sample_builder().save_value(MetricValue::Count(1))
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
                tracer.sample_builder().save_value(MetricValue::Count(1))
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

            let converter = DefaultExportGraphMetricValueConverter::default();

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
                    converter.convert(&exporter, sample.value()));
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
}
