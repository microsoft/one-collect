// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::hash_map::Entry;
use std::collections::hash_map::Entry::{Vacant, Occupied};
use std::path::{Path, PathBuf};

use std::fs::File;
use std::fmt::Write;
use std::io::BufReader;
#[cfg(target_os = "linux")]
use std::io::{BufRead, Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use tracing::{debug, info, trace, warn};

use crate::{ReadOnly, Writable};
use crate::event::DataFieldRef;
use crate::PathBufInteger;
use crate::openat::{OpenAt, DupFd};
use crate::procfs;
use crate::perf_event::{AncillaryData, PerfSession};
use crate::perf_event::{RingBufSessionBuilder, RingBufBuilder};
use crate::perf_event::rb::{RingBufOptions, cgroup_sample_supported, ksymbol_records_supported};
use crate::perf_event::abi::PERF_RECORD_MISC_SWITCH_OUT;
use crate::helpers::callstack::{CallstackHelp, CallstackReader};
use crate::helpers::exporting::*;
use crate::helpers::exporting::process::{ExportProcessOSHooks, MetricValue};
use crate::helpers::exporting::universal::*;
use crate::helpers::exporting::modulemetadata::{ModuleMetadata, ElfModuleMetadata};
use crate::page_size_to_mask;
use crate::os::system_page_size;

use crate::ruwind::elf::*;
use crate::ruwind::{ModuleAccessor, UnwindType};
use symbols::{ElfSymbolReader, GoPclnTabSymbolReader, R2RLoadedLayoutSymbolTransformer, R2RMapSymbolReader};
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
    pub(crate) fn new() -> Self {
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
        strings: &InternedStrings) -> Vec<(File, u32)>;

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
            warn!("add_matching_elf_symbols: skipped, pid={}, no root_fs available", self.pid());
            return;
        }

        let page_size = self.system_page_size();
        let page_mask = self.system_page_mask();

        for map_index in 0..self.mappings().len() {
            let map = self.mappings().get(map_index).unwrap();
            if map.anon() {
                continue;
            }

            addrs.clear();
            addrs.extend(self.cached_user_ips(callstacks, Some(map)));

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

            info!("Resolving symbols for file: {}", filename);

            // Get the dev node or continue.
            let dev_node = match map.node() {
                Some(key) => key,
                None => {
                    debug!("add_matching_elf_symbols: no dev_node for file={}, skipping", filename);
                    continue
                }
            };

            // If there is no metadata, then we can't load symbols.
            // It's possible that metadata fields are empty, but if there is no metadata entry,
            // then we should not proceed.
            if let Some(ModuleMetadata::Elf(metadata)) = elf_metadata.get(dev_node) {

                // Find matching symbol files.
                let sym_files = self.find_symbol_files(
                    filename,
                    metadata,
                    SYMBOL_TYPE_ELF_SYMTAB | SYMBOL_TYPE_ELF_DYNSYM | SYMBOL_TYPE_GO_PCLNTAB,
                    strings);

                if sym_files.is_empty() {
                    debug!("add_matching_elf_symbols: no symbol files found for file={}", filename);
                }

                // De-duplication across the ELF and Go passes below is handled
                // transparently by add_matching_symbols (a function already added
                // from one source is not re-added from another).
                for (sym_file, sym_types) in sym_files {

                    // Page align the values from the load header.
                    let p_offset = metadata.p_offset() & page_mask;
                    let p_vaddr = metadata.p_vaddr() & page_mask;

                    let has_elf = sym_types & (SYMBOL_TYPE_ELF_SYMTAB | SYMBOL_TYPE_ELF_DYNSYM) != 0;
                    let has_go = sym_types & SYMBOL_TYPE_GO_PCLNTAB != 0;

                    // Give each reader its own independent file handle. Only clone
                    // when both passes will run; otherwise move the handle directly.
                    let (elf_file, go_file): (Option<File>, Option<File>) = match (has_elf, has_go) {
                        (true, true) => match sym_file.try_clone() {
                            Ok(clone) => (Some(sym_file), Some(clone)),
                            Err(_) => (Some(sym_file), None),
                        },
                        (true, false) => (Some(sym_file), None),
                        (false, true) => (None, Some(sym_file)),
                        (false, false) => (None, None),
                    };

                    let map_mut = self.mappings_mut().get_mut(map_index).unwrap();

                    // ELF symtab/dynsym pass.
                    if let Some(elf_file) = elf_file {
                        let load_header = ElfLoadHeader::new(p_offset, p_vaddr);
                        let mut sym_reader = ElfSymbolReader::new(elf_file, load_header, page_size);
                        map_mut.add_matching_symbols(frames, &mut sym_reader, strings);
                    }

                    // Go pclntab pass. Unioned with the ELF symbols above; pclntab
                    // fills functions the ELF symbol table lacks (or is the only
                    // source when the symbol table has been stripped). Functions
                    // shared with the ELF pass are dropped automatically.
                    if let Some(go_file) = go_file {
                        let load_header = ElfLoadHeader::new(p_offset, p_vaddr);
                        if let Some(mut go_reader) = GoPclnTabSymbolReader::new(go_file, load_header, page_size) {
                            map_mut.add_matching_symbols(frames, &mut go_reader, strings);
                        }
                    }
                }
            }
        }
    }

    fn find_symbol_files(
        &self,
        bin_path: &str,
        metadata: &ElfModuleMetadata,
        sym_types_requested: u32,
        strings: &InternedStrings) -> Vec<(File, u32)> {
        let mut symbol_files = Vec::new();
        let mut sym_types_found = 0u32;

        // ELF symbol tables (symtab/dynsym) can be split into separate debug
        // files, so a still-missing ELF type justifies continuing to walk the
        // .dbg/.debug/debug-link chain. The Go pclntab is only ever carried in
        // the binary itself (the first candidate), so it never justifies
        // continuing — this keeps non-Go binaries from incurring extra
        // symbol-file lookups.
        let searchable_requested = sym_types_requested
            & (SYMBOL_TYPE_ELF_SYMTAB | SYMBOL_TYPE_ELF_DYNSYM);

        // The search is complete once everything requested is found, or once
        // every *searchable* requested type is found (any remaining requested
        // type can't appear in a later file). The `searchable_requested != 0`
        // guard prevents a request with no searchable types (e.g. Go-only) from
        // stopping after an arbitrary first hit — it then stops only when the
        // requested type is actually found.
        let search_complete = |found: u32| -> bool {
            (found & sym_types_requested) == sym_types_requested
                || (searchable_requested != 0
                    && (found & searchable_requested) == searchable_requested)
        };

        // Keep evaluating symbol files until we find a matching one with a symtab.
        let mut path_buf = PathBuf::new();

        // Look at the binary itself.
        path_buf.push(bin_path);
        if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            symbol_files.push((sym_file, types_found));
            sym_types_found |= types_found;
            if search_complete(sym_types_found) {
                return symbol_files
            }
        }

        // Look next to the binary.
        path_buf.clear();
        path_buf.push(format!("{}.dbg", bin_path));

        if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            symbol_files.push((sym_file, types_found));
            sym_types_found |= types_found;

            if search_complete(sym_types_found) {
                return symbol_files
            }
        }

        path_buf.clear();
        path_buf.push(format!("{}.debug", bin_path));

        if let Some((sym_file, types_found)) = self.check_candidate_symbol_file(
            metadata.build_id(),
            &path_buf) {
            symbol_files.push((sym_file, types_found));
            sym_types_found |= types_found;
            if search_complete(sym_types_found) {
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
                symbol_files.push((sym_file, types_found));
                sym_types_found |= types_found;
                if search_complete(sym_types_found) {
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
                    symbol_files.push((sym_file, types_found));
                    sym_types_found |= types_found;
                    if search_complete(sym_types_found) {
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
                    symbol_files.push((sym_file, types_found));
                    sym_types_found |= types_found;
                    if search_complete(sym_types_found) {
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
                    symbol_files.push((sym_file, types_found));
                    sym_types_found |= types_found;
                    if search_complete(sym_types_found) {
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
                symbol_files.push((sym_file, types_found));
                sym_types_found |= types_found;
                if search_complete(sym_types_found) {
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
            symbol_files.push((sym_file, types_found));
            sym_types_found |= types_found;
            if search_complete(sym_types_found) {
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
            symbol_files.push((sym_file, types_found));
            sym_types_found |= types_found;
            if search_complete(sym_types_found) {
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
                symbol_files.push((sym_file, types_found));
                sym_types_found |= types_found;
                if search_complete(sym_types_found) {
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
            info!("Checking candidate symbol file: {:?}", filename);

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
                                    info!("Symbol file accepted: {:?} (build_id matches)", filename);
                                    matching_sym_file = Some(reader);
                                } else {
                                    info!("Symbol file rejected: {:?} (build_id mismatch)", filename);
                                }
                            }
                            None => {
                                info!("Symbol file rejected: {:?} (symbol file has build_id but binary does not)", filename);
                                return None;
                            }
                        }
                    },
                    None => {
                        match binary_build_id {
                            Some(_) => {
                                info!("Symbol file rejected: {:?} (binary has build_id but symbol file does not)", filename);
                                return None;
                            }
                            None => {
                                info!("Symbol file accepted: {:?} (neither has build_id)", filename);
                                matching_sym_file = Some(reader);
                            }
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

            if has_go_pclntab(&mut reader) || has_go_build_info(&mut reader) {
                sym_flags |= SYMBOL_TYPE_GO_PCLNTAB;
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

            addrs.clear();
            addrs.extend(self.cached_user_ips(callstacks, Some(map)));

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

            info!("Resolving ReadyToRun symbols for file: {}", filename);

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
            } else {
                info!("Skipping ReadyToRun symbols for {}: not a PE file", filename);
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
            info!("Checking ReadyToRun map file: {:?}", path_buf);

            if let Ok(file) = self.open_file(&path_buf) {
                let mut reader = R2RMapSymbolReader::new(file);
                reader.reset();

                // The signature must be non-zero and match.
                if *metadata.perfmap_sig() != [0; 16] && metadata.perfmap_sig() == reader.signature() {
                    info!("ReadyToRun map file accepted: {:?} (signature matches)", path_buf);
                    return Some(reader);
                } else {
                    info!("ReadyToRun map file rejected: {:?} (signature mismatch or invalid)", path_buf);
                }
            } else {
                info!("ReadyToRun map file rejected: {:?} (could not open file)", path_buf);
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
    pub(crate) fn new() -> Self {
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
    cgroup_field: DataFieldRef,
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
            cgroup_field: session.cgroup_data_ref(),
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

    fn os_event_id(
        &self,
        _data: &EventData) -> anyhow::Result<Option<usize>> {
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

    fn os_event_cgroup(
        &self,
        data: &EventData) -> anyhow::Result<Option<u64>> {
        Ok(self.os.cgroup_field.try_get_u64(data.full_data()))
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
    va_offsets: HashMap<ExportDevNode, u64>,
    path_buf: Writable<PathBuf>,
    bpf_lifecycle_unavailable: bool,
}

impl OSExportMachine {
    pub(crate) fn new() -> Self {
        Self {
            cswitches: HashMap::new(),
            dev_nodes: ExportDevNodeLookup::new(),
            va_offsets: HashMap::new(),
            path_buf: Writable::new(PathBuf::new()),
            bpf_lifecycle_unavailable: false,
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

        /*
         * PERF_RECORD_LOST and PERF_RECORD_LOST_SAMPLES describe different
         * kernel loss paths, but nettrace can represent only a sequence gap.
         * Preserve the low-level callbacks while also combining both counts
         * into the exporter's trace-wide loss total.
         */
        let loss_machine = machine.clone();
        let event = session.lost_event();
        let lost_field = event.format().get_field_ref_unchecked("lost");

        event.add_callback(move |data| {
            let lost = data.format().get_u64(
                lost_field,
                data.event_data())?;

            loss_machine.borrow().add_lost_events(lost);

            Ok(())
        });

        let loss_machine = machine.clone();
        let event = session.lost_samples_event();
        let lost_field = event.format().get_field_ref_unchecked("lost");

        event.add_callback(move |data| {
            let lost = data.format().get_u64(
                lost_field,
                data.event_data())?;

            loss_machine.borrow().add_lost_events(lost);

            Ok(())
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

        /* Hook kernel dynamic symbol (BPF JIT, trampoline) records */
        let time_field = session.time_data_ref();
        let event = session.ksymbol_event();
        let event_machine = machine.clone();
        let fmt = event.format();
        let addr = fmt.get_field_ref_unchecked("addr");
        let len = fmt.get_field_ref_unchecked("len");
        let ksym_type = fmt.get_field_ref_unchecked("ksym_type");
        let flags = fmt.get_field_ref_unchecked("flags");
        let name = fmt.get_field_ref_unchecked("name[]");

        event.add_callback(move |data| {
            let fmt = data.format();
            let full_data = data.full_data();
            let data = data.event_data();

            let flags = fmt.get_u16(flags, data)?;
            let unregister = flags & crate::perf_event::abi::PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER != 0;

            /*
             * Match the "<module> <name>" format KernelSymbolReader uses
             * for these symbols in /proc/kallsyms.
             */
            let name = format!("[bpf] {}", fmt.get_str(name, data)?);

            event_machine.borrow_mut().queue_kernel_dynamic_symbol(
                time_field.get_u64(full_data)?,
                fmt.get_u64(addr, data)?,
                fmt.get_u32(len, data)? as u64,
                KernelDynamicSymbolKind::from_ksym_type(
                    fmt.get_u16(ksym_type, data)?),
                unregister,
                &name);

            Ok(())
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
            info!("Checking perf-map file: {:?}", path_buf);
            let file = proc.open_file(&path_buf);
            path_buf.pop();

            let file = match file {
                Ok(f) => f,
                Err(e) => {
                    warn!("Unable to open perf-map file: pid={}, ns_pid={:?}, error={}", proc.pid(), ns_pid, e);
                    continue;
                }
            };

            info!("Perf-map file accepted: file opened successfully");
            let mut sym_reader = PerfMapSymbolReader::new(file);

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

                    // Handle each binary exactly once, regardless of whether it's loaded into multiple processes.
                    if machine.module_metadata.contains(key) {
                        continue;
                    }

                    // Skip anonymous mappings.
                    if map.anon() {
                        continue;
                    }

                    if let Ok(filename) = machine.strings.from_id(map.filename_id()) {
                        info!("Loading ELF metadata from file: {}", filename);
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
    pub(crate) fn new() -> Self {
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

    pub(crate) fn open(
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
fn mark_live_kernel_samples(
    ip_times: &[(u64, u64)],
    states: &mut [Option<usize>],
    generation: &KernelDynamicSymbol,
    gen_index: usize) -> bool {
    let mut first = ip_times.partition_point(|(addr, _)| *addr < generation.start());
    let last = ip_times.partition_point(|(addr, _)| *addr <= generation.end());
    let mut live = false;

    while first < last {
        let address = ip_times[first].0;
        let end = first + ip_times[first..last].partition_point(|(addr, _)| *addr == address);
        let times = &ip_times[first..end];
        let from = times.partition_point(|(_, time)| *time < generation.load_time());
        let to = match generation.unload_time() {
            Some(unload) => times.partition_point(|(_, time)| *time < unload),
            None => times.len(),
        };
        if from < to {
            states[first + from..first + to].fill(Some(gen_index));
            live = true;
        }
        first = end;
    }

    live
}

#[cfg(target_os = "linux")]
fn count_ambiguous_kernel_addresses(
    ip_times: &[(u64, u64)],
    states: &[Option<usize>],
    generations: &[&KernelDynamicSymbol],
    emitted: &[usize]) -> u64 {
    let mut starts: Vec<_> = emitted.iter().map(|index| generations[*index].start()).collect();
    let mut ends: Vec<_> = emitted.iter().map(|index| generations[*index].end()).collect();
    starts.sort_unstable();
    ends.sort_unstable();

    let mut count = 0;
    let mut index = 0;
    while index < ip_times.len() {
        let addr = ip_times[index].0;
        let state = states[index];
        let end = index + ip_times[index..].partition_point(|(other, _)| *other == addr);
        let covering = starts.partition_point(|start| *start <= addr) -
            ends.partition_point(|end| *end < addr);
        /* A resolved state already accounts for one emitted covering range. */
        if states[index..end].iter().any(|other| *other != state) ||
            covering > usize::from(state.is_some()) {
            count += 1;
        }
        index = end;
    }
    count
}

#[cfg(target_os = "linux")]
fn bpf_identity_tag(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("[bpf] bpf_prog_")?;
    let tag = rest.get(..16)?;
    if tag.bytes().all(|byte| byte.is_ascii_hexdigit()) &&
        (rest.len() == 16 || rest.as_bytes()[16] == b'_') {
        Some(tag)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
impl ExportMachineOSHooks for ExportMachine {
    fn os_add_kernel_mappings_with(
        &mut self,
        kernel_symbols: &mut impl ExportSymbolReader) {
        self.apply_pending_kernel_dynamic_symbols();

        // Cached kernel symbol for in-memory matching.
        // name_id is interned once in Phase 2 so Phase 3 does not pay the
        // hash + bucket-walk + memcmp cost of strings.to_id for every
        // (process, symbol) pair.
        struct CachedKernelSymbol {
            start: u64,
            end: u64,
            name_id: usize,
            /*
             * Whether the symbol lies in an address range used by tracked
             * kernel dynamic code. Such symbols describe what was loaded at
             * finalization, so they are only valid after that code unloaded.
             */
            in_dynamic_range: bool,
        }

        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        // Phase 1: Collect all unique kernel IPs across all processes.
        let mut all_addrs_set: HashSet<u64> = HashSet::new();

        for proc in self.procs.values() {
            proc.get_unique_kernel_ips(
                &mut addrs,
                &mut frames,
                &self.callstacks);

            for addr in &addrs {
                all_addrs_set.insert(*addr);
            }
        }

        if all_addrs_set.is_empty() {
            return;
        }

        let mut all_addrs: Vec<u64> = all_addrs_set.into_iter().collect();
        all_addrs.sort();

        let strings = &self.strings;
        self.kernel_dynamic_symbols.apply_snapshots_with(|left, right| {
            match (strings.from_id(left), strings.from_id(right)) {
                (Ok(left), Ok(right)) => bpf_identity_tag(left).zip(bpf_identity_tag(right))
                    .is_some_and(|(left, right)| left == right),
                _ => false,
            }
        });

        let dynamic = &self.kernel_dynamic_symbols;
        let dynamic_ranges = dynamic.range_index();

        if !dynamic.is_empty() {
            let stats = dynamic.stats();

            info!("Kernel dynamic symbols: generations={}, registers={}, unregisters={}, \
                unmatched_unregisters={}, implicit_unloads={}, mismatched_unregisters={}, \
                duplicates={}, invalid={}, snapshot_symbols={}",
                dynamic.symbols().len(), stats.registers, stats.unregisters,
                stats.unmatched_unregisters, stats.implicit_unloads,
                stats.mismatched_unregisters, stats.duplicates, stats.invalid,
                stats.snapshot_symbols);

            if stats.implicit_unloads != 0 || stats.mismatched_unregisters != 0 {
                warn!("Kernel dynamic symbol records were lost or inconsistent, \
                    some BPF frames may be attributed with approximate lifetimes");
            }

            let lost = self.lost_events();

            if lost != 0 {
                warn!("{} events were lost, kernel dynamic symbol records may be missing \
                    so some BPF frames may be unknown or have approximate lifetimes", lost);
            }
        }

        // Phase 2: Read kernel symbols once, keeping only those that match
        // a collected IP. This avoids re-reading /proc/kallsyms per-process.
        kernel_symbols.reset();
        let mut matched_symbols: Vec<CachedKernelSymbol> = Vec::new();

        while kernel_symbols.next() {
            let start = kernel_symbols.start();
            let mut end = kernel_symbols.end();
            let mut in_dynamic_range = false;

            if self.os.bpf_lifecycle_unavailable &&
                kernel_symbols.name().starts_with("[bpf]") {
                continue;
            }

            /* An unbounded or invalid kallsyms extent is represented by
             * end == start. Do not turn that sentinel into a range. */
            if end <= start {
                continue;
            }

            /* Clipping can only shrink the original extent. */
            let first = all_addrs.partition_point(|addr| *addr < start);
            if first == all_addrs.len() || all_addrs[first] > end {
                continue;
            }

            if !dynamic.is_empty() {
                /*
                 * Code still loaded that we saw register is described by
                 * its generation, which has an exact extent and lifetime.
                 */
                if dynamic_ranges.open_contains(start) {
                    continue;
                }

                /*
                 * Never let an inferred kallsyms extent run into code that
                 * was loaded or unloaded during tracking.
                 */
                end = dynamic_ranges.clip_end(start, end);
                in_dynamic_range = dynamic_ranges.any_contains(start);
            }

            let has_match = all_addrs[first] <= end;

            if has_match {
                let name_id = self.strings.to_id(kernel_symbols.name());
                matched_symbols.push(CachedKernelSymbol {
                    start,
                    end,
                    name_id,
                    in_dynamic_range,
                });
            }
        }
        // matched_symbols is sorted by start (kallsyms is sorted).

        // Kernel dynamic code generations that any sample touched, ordered
        // by start so they can be matched against sorted process IPs.
        let mut generations: Vec<&KernelDynamicSymbol> = dynamic
            .symbols()
            .iter()
            .filter(|symbol| {
                match all_addrs.binary_search(&symbol.start()) {
                    Ok(_) => true,
                    Err(i) => i < all_addrs.len() && all_addrs[i] <= symbol.end(),
                }
            })
            .collect();

        generations.sort_by_key(|symbol| (symbol.load_time(), symbol.start()));

        /* Sampled addresses inside any generation, which need time scoping */
        let mut dynamic_addrs: HashSet<u64> = HashSet::new();

        for generation in &generations {
            let first = all_addrs.partition_point(|addr| *addr < generation.start());
            let last = all_addrs.partition_point(|addr| *addr <= generation.end());

            dynamic_addrs.extend(all_addrs[first..last].iter().copied());
        }

        let vmlinux_id = self.strings.to_id("vmlinux");
        let bpf_id = self.strings.to_id("[bpf]");
        let mut ip_times: Vec<(u64, u64)> = Vec::new();
        let mut states: Vec<Option<usize>> = Vec::new();
        let mut emitted: Vec<usize> = Vec::new();
        let mut time_ambiguous = 0u64;

        // Phase 3: For each process, assign symbols from the matched set.
        let mut seen = vec![false; matched_symbols.len()];

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
                vmlinux_id,
                KERNEL_START,
                KERNEL_END,
                0,
                false,
                self.map_index,
                UnwindType::DWARF);

            self.map_index += 1;
            seen.fill(false);

            let mut added = 0usize;

            for addr in &addrs {
                // Binary search for the symbol whose start is <= addr.
                let idx = match matched_symbols.binary_search_by_key(addr, |s| s.start) {
                    Ok(i) => i,
                    Err(0) => continue,
                    Err(i) => i - 1,
                };

                let sym = &matched_symbols[idx];
                if *addr >= sym.start && *addr <= sym.end && !seen[idx] &&
                   !sym.in_dynamic_range {
                    seen[idx] = true;
                    added += 1;

                    let symbol = ExportSymbol::new(sym.name_id, sym.start, sym.end);

                    trace!("Adding symbol to mapping: mapping_id={}, name={}, start={:#x}, end={:#x}",
                        kernel.id(),
                        self.strings.from_id(sym.name_id).unwrap_or(""),
                        sym.start, sym.end);
                    kernel.add_symbol(symbol);
                }
            }

            if added > 0 {
                info!("Added symbols to mapping: mapping_id={}, start={:#x}, added_count={}",
                    kernel.id(), kernel.start(), added);
            }

            proc.add_mapping(kernel);

            if generations.is_empty() {
                continue;
            }

            proc.get_kernel_ip_times(
                |addr| dynamic_addrs.contains(&addr),
                &mut ip_times,
                &mut frames,
                &self.callstacks);

            if ip_times.is_empty() {
                continue;
            }

            states.clear();
            states.resize(ip_times.len(), None);
            emitted.clear();

            /*
             * Each generation becomes a mapping scoped to its load time.
             * Its unload event ends that mapping's lifetime without
             * synthesizing a replacement mapping over the address range.
             *
             * Only generations this process sampled while they were live
             * are added, so readers that resolve by address without time
             * do not see code the process never ran.
             */
            for (gen_index, generation) in generations.iter().enumerate() {
                let unload_time = generation.unload_time();
                if mark_live_kernel_samples(&ip_times, &mut states, generation, gen_index) {
                    let mapping_id = self.map_index;
                    let mut mapping = ExportMapping::new(
                        generation.load_time(),
                        bpf_id,
                        generation.start(),
                        generation.end(),
                        0,
                        false,
                        self.map_index,
                        UnwindType::DWARF);

                    self.map_index += 1;

                    mapping.add_symbol(
                        ExportSymbol::new(
                            generation.name_id(),
                            generation.start(),
                            generation.end()));

                    proc.add_mapping(mapping);
                    emitted.push(gen_index);

                    if let Some(unload_time) = unload_time {
                        proc.add_mapping_unload(
                            ExportMappingUnload::new(
                                unload_time,
                                mapping_id,
                                generation.start(),
                                generation.end()));
                    }
                }
            }

            /*
             * Count addresses that only resolve correctly with time: their
             * samples span generations or gaps, or another emitted
             * generation's symbol also covers them.
             */
            time_ambiguous += count_ambiguous_kernel_addresses(
                &ip_times, &states, &generations, &emitted);
        }

        if time_ambiguous != 0 {
            warn!("{} sampled kernel dynamic code addresses need time to resolve: \
                within the same process they ran under more than one code generation \
                (or while nothing was loaded there), or overlap another generation's \
                symbol. Exported symbols are time scoped, but readers that resolve \
                symbols by address alone (e.g. TraceEvent universal symbols) may \
                attribute these frames to the wrong generation", time_ambiguous);
        }

        self.kernel_dynamic_symbols.stats_mut().time_ambiguous_addresses = time_ambiguous;
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
                let node = *node;

                if !self.os.dev_nodes.contains(&node) {
                    let mut va_offset = 0u64;
                    if let Some(process) = self.find_process(pid) {
                        if let Ok(file) = process.open_file(Path::new(filename)) {
                            if let Vacant(entry) = self.os.dev_nodes.entry(node) {
                                let dup_fd = entry.insert(DupFd::new(file));
                                if let Some(file) = dup_fd.open() {
                                    let mut reader = BufReader::new(file);
                                    if let Ok(load_header) = get_load_header(&mut reader) {
                                        va_offset = load_header
                                            .p_vaddr()
                                            .saturating_sub(load_header.p_offset());
                                    }
                                }
                            }
                        }
                    }
                    self.os.va_offsets.insert(node, va_offset);
                }

                let va_offset = *self.os.va_offsets.get(&node).unwrap_or(&0);
                if va_offset != 0 {
                    mapping.set_va_offset(va_offset);
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
            .with_executable_mmap_records()
            .with_comm_records()
            .with_task_records();

        if ksymbol_records_supported() {
            kernel = kernel.with_ksymbol_records();
        }

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
            let mut tracepoint = RingBufBuilder::for_tracepoint();

            if cgroup_sample_supported() {
                tracepoint = tracepoint.with_cgroup_data();
            }

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

/* Loaded BPF program function as seen by snapshot_bpf_programs */
struct LoadedBpfFunction {
    time: u64,
    start: u64,
    len: u64,
    name: String,
    name_is_exact: bool,
    tag_is_known: bool,
}

#[cfg(target_os = "linux")]
struct BpfSnapshotFunction {
    time: u64,
    start: u64,
    len: u64,
    tag: [u8; 8],
    tag_is_known: bool,
    prog_name: String,
}

#[cfg(target_os = "linux")]
struct PinnedBpfProgram {
    _fd: OwnedFd,
    functions: Vec<BpfSnapshotFunction>,
}

#[cfg(target_os = "linux")]
struct BpfSnapshotCancellation(Arc<AtomicBool>);

#[cfg(target_os = "linux")]
impl Drop for BpfSnapshotCancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
fn bpf_snapshot_name(
    kallsyms_name: Option<&String>,
    tag: &[u8],
    prog_name: &str) -> (String, bool) {
    let mut tag_string = String::new();
    for byte in tag {
        let _ = write!(tag_string, "{:02x}", byte);
    }

    let prefix = format!("bpf_prog_{}", tag_string);
    match kallsyms_name {
        Some(name) if name == &prefix || name.starts_with(&format!("{}_", prefix)) => (name.clone(), true),
        _ => (format!("{}_{}", prefix, prog_name), false),
    }
}

#[cfg(target_os = "linux")]
fn bpf_kallsyms_names(
    reader: &mut (impl BufRead + Seek),
    addresses: &HashSet<u64>,
    cancelled: &AtomicBool) -> std::io::Result<Option<HashMap<u64, String>>> {
    if cancelled.load(Ordering::Relaxed) {
        return Ok(None);
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut names = HashMap::new();
    let mut line = String::new();

    while names.len() < addresses.len() {
        if cancelled.load(Ordering::Relaxed) {
            return Ok(None);
        }
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if !line.trim_end().ends_with("[bpf]") {
            continue;
        }

        let mut parts = line.split_whitespace();
        if let (Some(addr), Some(_), Some(name)) = (parts.next(), parts.next(), parts.next()) {
            if let Ok(addr) = u64::from_str_radix(addr, 16) {
                if addresses.contains(&addr) {
                    names.insert(addr, name.to_string());
                }
            }
        }
    }

    if cancelled.load(Ordering::Relaxed) {
        return Ok(None);
    }
    Ok(Some(names))
}

#[cfg(target_os = "linux")]
fn finish_bpf_snapshot_batch(
    programs: Vec<PinnedBpfProgram>,
    cancelled: &AtomicBool,
    read_names: impl FnOnce(&HashSet<u64>) -> Option<HashMap<u64, String>>) -> Option<Vec<LoadedBpfFunction>> {
    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    let mut addresses = HashSet::new();
    for program in &programs {
        for function in &program.functions {
            if cancelled.load(Ordering::Relaxed) {
                return None;
            }
            addresses.insert(function.start);
        }
    }

    /* Each program remains pinned until all of these names have been read. */
    let names = read_names(&addresses)?;
    let mut functions = Vec::new();

    for program in programs {
        for function in program.functions {
            if cancelled.load(Ordering::Relaxed) {
                return None;
            }
            let kallsyms_name = names.get(&function.start);
            let (name, name_is_exact) = match kallsyms_name {
                Some(name) if !function.tag_is_known && name.starts_with("bpf_prog_") => {
                    (name.clone(), true)
                },
                _ => bpf_snapshot_name(kallsyms_name, &function.tag, &function.prog_name),
            };
            functions.push(LoadedBpfFunction {
                time: function.time,
                start: function.start,
                len: function.len,
                name,
                name_is_exact,
                tag_is_known: function.tag_is_known,
            });
        }
    }

    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    Some(functions)
}

/*
 * Enumerates loaded BPF programs and returns the extent and name of each JIT
 * compiled function. This requires CAP_SYS_ADMIN; on failure what was found
 * so far is returned. Cancellation discards all results.
 */
#[cfg(target_os = "linux")]
fn loaded_bpf_functions(cancelled: &AtomicBool) -> Option<Vec<LoadedBpfFunction>> {
    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    let kallsyms = match File::open("/proc/kallsyms") {
        Ok(file) => Some(BufReader::new(file)),
        Err(err) => {
            warn!("Unable to open kallsyms for the BPF snapshot ({}); \
                using program names where possible", err);
            None
        },
    };
    loaded_bpf_functions_with(cancelled, |cmd, attr, size| unsafe {
        libc::syscall(libc::SYS_bpf, cmd, attr, size as libc::c_uint)
    }, kallsyms)
}

#[cfg(target_os = "linux")]
fn loaded_bpf_functions_with(
    cancelled: &AtomicBool,
    mut syscall: impl FnMut(libc::c_long, *mut libc::c_void, usize) -> libc::c_long,
    mut kallsyms: Option<BufReader<File>>) -> Option<Vec<LoadedBpfFunction>> {
    const BPF_PROG_GET_NEXT_ID: libc::c_long = 11;
    const BPF_PROG_GET_FD_BY_ID: libc::c_long = 13;
    const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;
    const BATCH_SIZE: usize = 32;

    /* Offsets within struct bpf_prog_info (linux/bpf.h) */
    const INFO_TAG: usize = 8;
    const INFO_NAME: usize = 64;
    const INFO_NR_JITED_KSYMS: usize = 104;
    const INFO_NR_JITED_FUNC_LENS: usize = 108;
    const INFO_JITED_KSYMS: usize = 112;
    const INFO_JITED_FUNC_LENS: usize = 120;
    const INFO_NR_PROG_TAGS: usize = 180;
    const INFO_PROG_TAGS: usize = 184;
    const INFO_LEN: usize = 192;

    #[repr(C)]
    #[derive(Default)]
    struct NextIdAttr { start_id: u32, next_id: u32, open_flags: u32 }

    #[repr(C)]
    #[derive(Default)]
    struct FdByIdAttr { prog_id: u32, next_id: u32, open_flags: u32 }

    #[repr(C)]
    #[derive(Default)]
    struct InfoAttr { bpf_fd: u32, info_len: u32, info: u64 }

    fn bpf<T>(
        syscall: &mut impl FnMut(libc::c_long, *mut libc::c_void, usize) -> libc::c_long,
        cmd: libc::c_long,
        attr: &mut T) -> libc::c_long {
        syscall(cmd, (attr as *mut T).cast(), std::mem::size_of::<T>())
    }

    fn get_info(
        syscall: &mut impl FnMut(libc::c_long, *mut libc::c_void, usize) -> libc::c_long,
        fd: i32,
        info: &mut [u8; INFO_LEN]) -> bool {
        let mut attr = InfoAttr {
            bpf_fd: fd as u32,
            info_len: INFO_LEN as u32,
            info: info.as_mut_ptr() as u64,
        };

        bpf(syscall, BPF_OBJ_GET_INFO_BY_FD, &mut attr) == 0
    }

    fn u32_at(info: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes(info[offset..offset + 4].try_into().unwrap())
    }

    fn finish_batch(
        batch: &mut Vec<PinnedBpfProgram>,
        kallsyms: &mut Option<BufReader<File>>,
        functions: &mut Vec<LoadedBpfFunction>,
        cancelled: &AtomicBool) -> Option<()> {
        if batch.is_empty() {
            return if cancelled.load(Ordering::Relaxed) { None } else { Some(()) };
        }

        functions.extend(finish_bpf_snapshot_batch(
            std::mem::take(batch),
            cancelled,
            |addresses| {
                match kallsyms.as_mut() {
                    Some(reader) => match bpf_kallsyms_names(reader, addresses, cancelled) {
                        Ok(names) => names,
                        Err(err) => {
                            warn!("Unable to read BPF names from kallsyms ({}); \
                                using program names where possible", err);
                            *kallsyms = None;
                            Some(HashMap::new())
                        },
                    },
                    None => Some(HashMap::new()),
                }
            })?);
        Some(())
    }

    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    let mut functions = Vec::new();
    let mut batch = Vec::new();
    let mut id = 0u32;

    loop {
        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        let mut next = NextIdAttr { start_id: id, ..Default::default() };

        if bpf(&mut syscall, BPF_PROG_GET_NEXT_ID, &mut next) != 0 {
            let err = std::io::Error::last_os_error();

            if err.raw_os_error() != Some(libc::ENOENT) {
                warn!("Unable to enumerate loaded BPF programs ({}); samples in BPF \
                    programs loaded before tracing began whose unload is not recorded \
                    (they unload after recording stops but before trace finalization, \
                    or their unload record is lost) will be unknown", err);
            }

            break;
        }

        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        id = next.next_id;

        let mut by_id = FdByIdAttr { prog_id: id, ..Default::default() };
        let mut fd = bpf(&mut syscall, BPF_PROG_GET_FD_BY_ID, &mut by_id);
        if fd < 0 &&
            matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) &&
            !batch.is_empty() {
            finish_batch(&mut batch, &mut kallsyms, &mut functions, cancelled)?;
            fd = bpf(&mut syscall, BPF_PROG_GET_FD_BY_ID, &mut by_id);
        }
        if fd < 0 &&
            matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) &&
            kallsyms.is_some() {
            warn!("Unable to open a BPF program while kallsyms is open; \
                using program names where possible");
            kallsyms = None;
            fd = bpf(&mut syscall, BPF_PROG_GET_FD_BY_ID, &mut by_id);
        }
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                /* Unloaded since it was enumerated. */
                continue;
            }
            warn!("Unable to open BPF program {} for the snapshot ({}); \
                its symbols may be unknown", id, err);
            if matches!(err.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) {
                break;
            }
            continue;
        }

        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        let mut info = [0u8; INFO_LEN];

        if get_info(&mut syscall, fd.as_raw_fd(), &mut info) {
            if cancelled.load(Ordering::Relaxed) {
                return None;
            }
            let count = u32_at(&info, INFO_NR_JITED_KSYMS)
                .min(u32_at(&info, INFO_NR_JITED_FUNC_LENS)) as usize;

            if count != 0 {
                let mut ksyms = vec![0u64; count];
                let mut lens = vec![0u32; count];
                let tag_count = (u32_at(&info, INFO_NR_PROG_TAGS) as usize).min(count);
                let mut tags = vec![[0u8; 8]; tag_count];

                info = [0u8; INFO_LEN];
                info[INFO_NR_JITED_KSYMS..INFO_NR_JITED_KSYMS + 4]
                    .copy_from_slice(&(count as u32).to_ne_bytes());
                info[INFO_NR_JITED_FUNC_LENS..INFO_NR_JITED_FUNC_LENS + 4]
                    .copy_from_slice(&(count as u32).to_ne_bytes());
                info[INFO_JITED_KSYMS..INFO_JITED_KSYMS + 8]
                    .copy_from_slice(&(ksyms.as_mut_ptr() as u64).to_ne_bytes());
                info[INFO_JITED_FUNC_LENS..INFO_JITED_FUNC_LENS + 8]
                    .copy_from_slice(&(lens.as_mut_ptr() as u64).to_ne_bytes());
                info[INFO_NR_PROG_TAGS..INFO_NR_PROG_TAGS + 4]
                    .copy_from_slice(&(tag_count as u32).to_ne_bytes());
                info[INFO_PROG_TAGS..INFO_PROG_TAGS + 8]
                    .copy_from_slice(&(tags.as_mut_ptr() as u64).to_ne_bytes());

                if get_info(&mut syscall, fd.as_raw_fd(), &mut info) {
                    /* The open fd pins this program at the observation time. */
                    let time = ExportMachine::qpc_time();

                    let prog_name = &info[INFO_NAME..INFO_NAME + 16];
                    let prog_name_len = prog_name.iter().position(|b| *b == 0).unwrap_or(16);
                    let prog_name = String::from_utf8_lossy(&prog_name[..prog_name_len]);

                    let mut program_functions = Vec::new();
                    for (index, (start, len)) in ksyms.iter().zip(lens.iter()).enumerate() {
                        if cancelled.load(Ordering::Relaxed) {
                            return None;
                        }
                        if *start == 0 || *len == 0 {
                            continue;
                        }

                        let tag_is_known = index == 0 ||
                            index < tag_count.min(u32_at(&info, INFO_NR_PROG_TAGS) as usize);
                        let tag = if index == 0 {
                            &info[INFO_TAG..INFO_TAG + 8]
                        } else {
                            tags.get(index).map_or(&info[INFO_TAG..INFO_TAG + 8], |tag| tag.as_slice())
                        };
                        program_functions.push(
                            BpfSnapshotFunction {
                                time,
                                start: *start,
                                len: *len as u64,
                                tag: tag.try_into().unwrap(),
                                tag_is_known,
                                prog_name: prog_name.to_string(),
                            });
                    }

                    if !program_functions.is_empty() {
                        batch.push(PinnedBpfProgram { _fd: fd, functions: program_functions });
                        if batch.len() == BATCH_SIZE {
                            finish_batch(&mut batch, &mut kallsyms, &mut functions, cancelled)?;
                        }
                    }
                } else {
                    warn!("Unable to read BPF JIT details for program {} ({}); \
                        its symbols may be unknown", id, std::io::Error::last_os_error());
                }
            }
        } else {
            warn!("Unable to read BPF program {} for the snapshot ({}); \
                its symbols may be unknown", id, std::io::Error::last_os_error());
        }
    }

    finish_batch(&mut batch, &mut kallsyms, &mut functions, cancelled)?;
    Some(functions)
}

/*
 * Records BPF programs that are already loaded so that samples in them can
 * be resolved even if they unload before the trace is finalized, when no
 * register record was seen for them.
 */
#[cfg(target_os = "linux")]
fn snapshot_bpf_programs(
    machine: &mut ExportMachine,
    functions: Vec<LoadedBpfFunction>,
    completed_before_stop: bool,
    system_wide_ksymbols: bool) {
    if !system_wide_ksymbols {
        warn!("BPF snapshot discarded because system-wide kernel symbol lifecycle \
            collection was unavailable");
        return;
    }
    if !completed_before_stop {
        warn!("BPF snapshot did not complete before recording stopped; discarding it \
            to avoid attributing programs observed after the recording");
        return;
    }

    debug!("Snapshot of loaded BPF programs: functions={}", functions.len());

    for function in functions {
        machine.add_kernel_dynamic_snapshot_with_name_certainty(
            function.time,
            function.start,
            function.len,
            KernelDynamicSymbolKind::Bpf,
            &format!("[bpf] {}", function.name),
            function.name_is_exact,
            function.tag_is_known);
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

        if let Some(target_cpus) = &settings.target_cpus {
            for cpu in target_cpus {
                builder = builder.with_target_cpu(*cpu);
            }
        }

        let mut builder = self.run_build_hooks(builder)?;

        let mut session = builder.build()?;

        let exporter = session.build_exporter(settings)?;

        /* Put in closure so we can contain errors */
        let os_parse_loop = || {
            self.run_export_hooks(&exporter)?;

            exporter.borrow_mut().mark_start();
            session.enable()?;

            std::thread::scope(|scope| -> anyhow::Result<()> {
                let cancellation = BpfSnapshotCancellation(Arc::new(AtomicBool::new(false)));
                let system_wide_ksymbols = session.has_system_wide_ksymbols();
                exporter.borrow_mut().os.bpf_lifecycle_unavailable =
                    ksymbol_records_supported() && !system_wide_ksymbols;
                let snapshot = if system_wide_ksymbols {
                    let cancelled = Arc::clone(&cancellation.0);
                    Some(scope.spawn(move || loaded_bpf_functions(&cancelled)))
                } else {
                    if ksymbol_records_supported() {
                        warn!("Skipping BPF snapshot because system-wide kernel symbol \
                            lifecycle collection was unavailable");
                    }
                    None
                };

                /* Capture environment while perf rings are being consumed. */
                let env_handle = session.spawn_capture_environment();
                let result = session.parse_until(until);
                let snapshot_completed = snapshot.as_ref().is_some_and(|handle| handle.is_finished());
                cancellation.0.store(true, Ordering::Relaxed);
                result?;
                session.disable()?;
                exporter.borrow_mut().mark_end();

                while !env_handle.is_finished() ||
                    snapshot.as_ref().is_some_and(|handle| !handle.is_finished()) {
                    session.parse_all()?;
                }

                let _ = env_handle.join();
                if let Some(handle) = snapshot {
                    let functions = handle.join().map_err(|_| {
                        anyhow::anyhow!("BPF snapshot thread panicked")
                    })?;
                    if let Some(functions) = functions {
                        snapshot_bpf_programs(
                            &mut exporter.borrow_mut(), functions, snapshot_completed, system_wide_ksymbols);
                    } else {
                        warn!("BPF snapshot did not complete before recording stopped; discarding it");
                    }
                }
                session.parse_all()?;
                Ok(())
            })?;

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
    use crate::helpers::exporting::graph::ExportGraph;
    use std::io::{Error, ErrorKind};
    use std::path::Path;
    use std::os::linux::fs::MetadataExt;

    use crate::tracefs::TraceFS;
    use crate::perf_event::{
        PerfData,
        PerfDataFile,
        PerfDataSource,
        RingBufSessionBuilder,
    };
    use crate::perf_event::abi::{
        Header,
        PERF_RECORD_LOST,
        PERF_RECORD_LOST_SAMPLES,
    };
    use crate::helpers::callstack::CallstackHelper;

    use graph::{DefaultExportGraphMetricValueConverter, ExportGraphMetricValueConverter};

    struct LostDataSource {
        records: Vec<Vec<u8>>,
        index: usize,
    }

    impl LostDataSource {
        fn new(
            records: Vec<Vec<u8>>) -> Self {
            Self {
                records,
                index: 0,
            }
        }
    }

    impl PerfDataSource for LostDataSource {
        fn enable(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn disable(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn target_pids(&self) -> Option<&[i32]> {
            None
        }

        fn create_bpf_files(
            &mut self,
            _event: Option<&Event>) -> std::io::Result<Vec<PerfDataFile>> {
            Err(Error::new(
                ErrorKind::Unsupported,
                "BPF is not supported"))
        }

        fn add_event(
            &mut self,
            _event: &Event) -> std::io::Result<()> {
            Ok(())
        }

        fn begin_reading(&mut self) {
        }

        fn read(
            &mut self,
            _timeout: std::time::Duration) -> Option<PerfData<'_>> {
            if self.index == self.records.len() {
                return None;
            }

            let index = self.index;
            self.index += 1;

            Some(PerfData {
                ancillary: Default::default(),
                raw_data: &self.records[index],
            })
        }

        fn end_reading(&mut self) {
        }

        fn more(&self) -> bool {
            self.index < self.records.len()
        }
    }

    fn lost_record(
        entry_type: u32,
        values: &[u64]) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut record = Vec::new();

        for value in values {
            payload.extend_from_slice(&value.to_ne_bytes());
        }

        Header::write(
            entry_type,
            0,
            &payload,
            &mut record);

        record
    }

    #[test]
    fn exporter_aggregates_both_perf_loss_records() {
        let source = LostDataSource::new(vec![
            lost_record(PERF_RECORD_LOST, &[1, 3]),
            lost_record(PERF_RECORD_LOST_SAMPLES, &[5]),
        ]);
        let mut session = PerfSession::new(Box::new(source));
        let settings = ExportSettings::new(CallstackHelper::new());
        let exporter = session.build_exporter(settings).unwrap();

        session.parse_all().unwrap();

        assert_eq!(8, exporter.borrow().lost_events());
    }

    struct KallsymsMock {
        symbols: Vec<(u64, u64, &'static str)>,
        index: usize,
    }

    impl KallsymsMock {
        fn new(symbols: Vec<(u64, u64, &'static str)>) -> Self {
            Self {
                symbols,
                index: 0,
            }
        }
    }

    impl ExportSymbolReader for KallsymsMock {
        fn reset(&mut self) { self.index = 0; }

        fn next(&mut self) -> bool {
            if self.index < self.symbols.len() {
                self.index += 1;
                true
            } else {
                false
            }
        }

        fn start(&self) -> u64 { self.symbols[self.index - 1].0 }

        fn end(&self) -> u64 { self.symbols[self.index - 1].1 }

        fn name(&self) -> &str { self.symbols[self.index - 1].2 }

        fn demangle(&mut self) -> Option<String> { None }
    }

    const SEC: u64 = 1_000_000_000;
    const BPF_X: u64 = 0xffffffffc0001000;

    fn kernel_test_machine() -> ExportMachine {
        let settings = ExportSettings::new(CallstackHelper::new())
            .without_process_fs();

        ExportMachine::new(settings)
    }

    #[test]
    fn incomplete_snapshot_is_discarded_after_shutdown() {
        let mut machine = kernel_test_machine();
        let functions = vec![LoadedBpfFunction {
            time: 3 * SEC, start: BPF_X, len: 64, name: "replacement".to_string(),
            name_is_exact: true,
            tag_is_known: true,
        }];
        snapshot_bpf_programs(&mut machine, functions, false, true);
        machine.kernel_dynamic_symbols.apply_snapshots();
        assert!(machine.kernel_dynamic_symbols().is_empty());
    }

    #[test]
    fn cancellation_during_bpf_enumeration_releases_pins() {
        use std::io::{ErrorKind, Read};
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;

        #[repr(C)]
        struct InfoAttr { fd: u32, len: u32, info: u64 }

        let cancelled = AtomicBool::new(false);
        let mut pins = std::collections::VecDeque::new();
        let mut observers = Vec::new();
        for _ in 0..33 {
            let (pin, observer) = UnixStream::pair().unwrap();
            observer.set_nonblocking(true).unwrap();
            pins.push_back(pin);
            observers.push(observer);
        }
        let mut next_count = 0;
        let mut info_count = 0;
        let result = loaded_bpf_functions_with(&cancelled, |cmd, attr, _| {
            match cmd {
                11 => {
                    next_count += 1;
                    if next_count == 34 {
                        assert_eq!(0, observers[0].read(&mut [0]).unwrap());
                        assert_eq!(ErrorKind::WouldBlock, observers[32].read(&mut [0]).unwrap_err().kind());
                        cancelled.store(true, Ordering::Relaxed);
                    }
                    unsafe { *(attr.cast::<u32>().add(1)) = next_count; }
                },
                13 => return pins.pop_front().unwrap().into_raw_fd() as libc::c_long,
                15 => unsafe {
                    info_count += 1;
                    let info = &mut *((*attr.cast::<InfoAttr>()).info as *mut [u8; 192]);
                    if info_count % 2 == 1 {
                        info[104..108].copy_from_slice(&1u32.to_ne_bytes());
                        info[108..112].copy_from_slice(&1u32.to_ne_bytes());
                    } else {
                        let ksyms = u64::from_ne_bytes(info[112..120].try_into().unwrap());
                        let lens = u64::from_ne_bytes(info[120..128].try_into().unwrap());
                        *(ksyms as *mut u64) = BPF_X + u64::from(next_count - 1) * 128;
                        *(lens as *mut u32) = 64;
                    }
                },
                _ => panic!("unexpected BPF command {cmd}"),
            }
            0
        }, None);
        assert!(result.is_none());
        assert_eq!(34, next_count);
        assert_eq!(66, info_count);
        assert_eq!(0, observers[32].read(&mut [0]).unwrap());
    }

    #[test]
    fn cancellation_during_kallsyms_scan_discards_batch_and_releases_pins() {
        use std::io::{Cursor, ErrorKind, Read};
        use std::os::unix::net::UnixStream;

        struct CancellingReader<'a> {
            input: Cursor<Vec<u8>>,
            cancelled: &'a AtomicBool,
            lines: usize,
        }
        impl Read for CancellingReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.input.read(buf)
            }
        }
        impl Seek for CancellingReader<'_> {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                self.input.seek(pos)
            }
        }
        impl BufRead for CancellingReader<'_> {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> { self.input.fill_buf() }
            fn consume(&mut self, amount: usize) { self.input.consume(amount); }
            fn read_line(&mut self, line: &mut String) -> std::io::Result<usize> {
                self.lines += 1;
                let result = self.input.read_line(line);
                self.cancelled.store(true, Ordering::Relaxed);
                result
            }
        }

        let cancelled = AtomicBool::new(false);
        let mut reader = CancellingReader {
            input: Cursor::new(format!(
                "{:016x} t bpf_prog_0000000000000000_first [bpf]\n{:016x} t bpf_prog_0000000000000000_second [bpf]\n",
                BPF_X, BPF_X + 128).into_bytes()),
            cancelled: &cancelled,
            lines: 0,
        };
        let (pin, mut observer) = UnixStream::pair().unwrap();
        observer.set_nonblocking(true).unwrap();
        let program = PinnedBpfProgram {
            _fd: pin.into(),
            functions: [BPF_X, BPF_X + 128].into_iter().map(|start| BpfSnapshotFunction {
                time: SEC, start, len: 64, tag: [0; 8],
                tag_is_known: true, prog_name: "test".to_string(),
            }).collect(),
        };
        let result = finish_bpf_snapshot_batch(vec![program], &cancelled, |addresses| {
            assert_eq!(ErrorKind::WouldBlock, observer.read(&mut [0]).unwrap_err().kind());
            bpf_kallsyms_names(&mut reader, addresses, &cancelled).unwrap()
        });
        assert!(result.is_none());
        assert_eq!(1, reader.lines);
        assert_eq!(0, observer.read(&mut [0]).unwrap());
    }

    #[test]
    fn snapshot_cancellation_guard_signals_on_error() {
        fn run(flag: &Arc<AtomicBool>, done: std::sync::mpsc::Sender<bool>) -> Result<(), ()> {
            std::thread::scope(|scope| {
                let _guard = BpfSnapshotCancellation(Arc::clone(flag));
                let (started, ready) = std::sync::mpsc::channel();
                scope.spawn(move || {
                    started.send(()).unwrap();
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                    while !flag.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
                        std::thread::yield_now();
                    }
                    done.send(flag.load(Ordering::Relaxed)).unwrap();
                });
                ready.recv().unwrap();
                Err(())
            })
        }

        let flag = Arc::new(AtomicBool::new(false));
        let (done, completed) = std::sync::mpsc::channel();
        assert!(run(&flag, done).is_err());
        assert!(completed.recv().unwrap());
    }

    #[test]
    fn missing_system_wide_lifecycle_does_not_backdate_reused_bpf_address() {
        let mut machine = kernel_test_machine();
        machine.os.bpf_lifecycle_unavailable = true;
        snapshot_bpf_programs(&mut machine, vec![LoadedBpfFunction {
            time: 3 * SEC, start: BPF_X, len: 64,
            name: "bpf_prog_replacement".to_string(),
            name_is_exact: true, tag_is_known: true,
        }], true, false);
        add_kernel_sample(&mut machine, 10, SEC, &[BPF_X]);
        add_kernel_sample(&mut machine, 10, 4 * SEC, &[BPF_X]);
        machine.add_kernel_mappings_with(&mut KallsymsMock::new(vec![
            (BPF_X, BPF_X + 63, "[bpf] bpf_prog_replacement"),
        ]));
        assert_eq!(None, resolve_kernel(&machine, 10, BPF_X, SEC));
        assert_eq!(None, resolve_kernel(&machine, 10, BPF_X, 4 * SEC));
    }

    #[test]
    fn snapshot_symbol_uses_matching_function_tag() {
        let tag = [0x9e, 0xfe, 0x88, 0x73, 0x12, 0x07, 0x41, 0xb3];
        let subprogram = "bpf_prog_9efe8873120741b3_F".to_string();
        let stale = "bpf_prog_9683c4e123f7f629_old".to_string();
        let unnamed = "bpf_prog_9efe8873120741b3".to_string();
        assert_eq!((subprogram.clone(), true), bpf_snapshot_name(Some(&subprogram), &tag, "main"));
        assert_eq!(("bpf_prog_9efe8873120741b3_main".to_string(), false), bpf_snapshot_name(Some(&stale), &tag, "main"));
        assert_eq!((unnamed.clone(), true), bpf_snapshot_name(Some(&unnamed), &tag, "main"));
    }

    #[test]
    fn snapshot_reads_reused_address_while_replacement_is_pinned() {
        use std::io::{Cursor, ErrorKind, Read};
        use std::os::unix::net::UnixStream;

        let tag = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let old = "bpf_prog_1234567890abcdef_old";
        let new = "bpf_prog_1234567890abcdef_new";
        let subprogram = "bpf_prog_0123456789abcdef_sub";
        let mut kallsyms = Cursor::new(format!("{:016x} t {} [bpf]\n", BPF_X, old).into_bytes());
        let cancelled = AtomicBool::new(false);
        let old_names = bpf_kallsyms_names(&mut kallsyms, &HashSet::from([BPF_X]), &cancelled).unwrap().unwrap();
        assert_eq!(Some(&old.to_string()), old_names.get(&BPF_X));

        let (pin, mut observer) = UnixStream::pair().unwrap();
        observer.set_nonblocking(true).unwrap();
        let programs = vec![PinnedBpfProgram {
            _fd: pin.into(),
            functions: vec![
                BpfSnapshotFunction {
                    time: 2 * SEC, start: BPF_X, len: 64, tag,
                    tag_is_known: true, prog_name: "new".to_string(),
                },
                BpfSnapshotFunction {
                    time: 2 * SEC, start: BPF_X + 128, len: 64, tag,
                    tag_is_known: false, prog_name: "new".to_string(),
                },
            ],
        }];
        *kallsyms.get_mut() = format!(
            "{:016x} t {} [bpf]\n{:016x} t {} [bpf]\n",
            BPF_X, new, BPF_X + 128, subprogram).into_bytes();

        let functions = finish_bpf_snapshot_batch(programs, &cancelled, |addresses| {
            assert_eq!(ErrorKind::WouldBlock, observer.read(&mut [0]).unwrap_err().kind());
            bpf_kallsyms_names(&mut kallsyms, addresses, &cancelled).unwrap()
        }).unwrap();
        assert_eq!(0, observer.read(&mut [0]).unwrap());
        assert_eq!(new, functions[0].name);
        assert!(functions[0].name_is_exact);
        assert_eq!(subprogram, functions[1].name);
        assert!(functions[1].name_is_exact);

        let mut machine = kernel_test_machine();
        let expected = format!("[bpf] {}", new);
        add_bpf(&mut machine, SEC, BPF_X, 64, false, &expected);
        add_bpf(&mut machine, 4 * SEC, BPF_X, 64, true, &expected);
        snapshot_bpf_programs(&mut machine, functions, true, true);
        add_kernel_sample(&mut machine, 10, 3 * SEC, &[BPF_X]);
        add_kernel_sample(&mut machine, 10, 5 * SEC, &[BPF_X]);
        machine.add_kernel_mappings_with(&mut KallsymsMock::new(vec![]));
        assert_eq!(Some(expected), resolve_kernel(&machine, 10, BPF_X, 3 * SEC));
        assert_eq!(None, resolve_kernel(&machine, 10, BPF_X, 5 * SEC));
    }

    #[test]
    fn completed_snapshot_uses_each_function_observation_time() {
        let mut machine = kernel_test_machine();
        machine.add_kernel_dynamic_symbol(2 * SEC, BPF_X, 64,
            KernelDynamicSymbolKind::Bpf, false, "[bpf] replacement");
        snapshot_bpf_programs(&mut machine, vec![LoadedBpfFunction {
            time: 3 * SEC, start: BPF_X, len: 64, name: "replacement".to_string(),
            name_is_exact: true,
            tag_is_known: true,
        }], true, true);
        machine.kernel_dynamic_symbols.apply_snapshots();
        assert_eq!(None, machine.kernel_dynamic_symbols().find(BPF_X, SEC));
        assert_eq!(2 * SEC, machine.kernel_dynamic_symbols().find(BPF_X, 3 * SEC).unwrap().load_time());
        assert_eq!(0, machine.kernel_dynamic_symbols().stats().snapshot_symbols);
    }

    #[test]
    fn synthesized_snapshot_preserves_observed_bpf_name_and_unload() {
        let mut machine = kernel_test_machine();
        let exact = "[bpf] bpf_prog_1234567890abcdef_btf_function";
        add_bpf(&mut machine, SEC, BPF_X, 64, false, exact);
        add_bpf(&mut machine, 4 * SEC, BPF_X, 64, true, exact);
        snapshot_bpf_programs(&mut machine, vec![LoadedBpfFunction {
            time: 2 * SEC, start: BPF_X, len: 64,
            name: "bpf_prog_1234567890abcdef_program".to_string(),
            name_is_exact: false,
            tag_is_known: true,
        }], true, true);
        add_kernel_sample(&mut machine, 10, 3 * SEC, &[BPF_X]);
        add_kernel_sample(&mut machine, 10, 5 * SEC, &[BPF_X]);
        machine.add_kernel_mappings_with(&mut KallsymsMock::new(vec![]));
        assert_eq!(Some(exact.to_string()), resolve_kernel(&machine, 10, BPF_X, 3 * SEC));
        assert_eq!(None, resolve_kernel(&machine, 10, BPF_X, 5 * SEC));
        assert_eq!(0, machine.kernel_dynamic_symbols().stats().snapshot_symbols);
    }

    #[test]
    fn synthesized_snapshot_with_different_tag_still_replaces_conflict() {
        let mut machine = kernel_test_machine();
        add_bpf(&mut machine, SEC, BPF_X, 64, false, "[bpf] bpf_prog_1234567890abcdef_old");
        snapshot_bpf_programs(&mut machine, vec![LoadedBpfFunction {
            time: 2 * SEC, start: BPF_X, len: 64,
            name: "bpf_prog_fedcba0987654321_new".to_string(),
            name_is_exact: false,
            tag_is_known: true,
        }], true, true);
        add_kernel_sample(&mut machine, 10, 3 * SEC, &[BPF_X]);
        machine.add_kernel_mappings_with(&mut KallsymsMock::new(vec![]));
        assert_eq!(
            Some("[bpf] bpf_prog_fedcba0987654321_new".to_string()),
            resolve_kernel(&machine, 10, BPF_X, 3 * SEC));
    }

    #[test]
    fn synthesized_subprogram_without_tag_preserves_observed_lifetime() {
        let mut machine = kernel_test_machine();
        let exact = "[bpf] bpf_prog_1234567890abcdef_subprogram";
        add_bpf(&mut machine, SEC, BPF_X, 64, false, exact);
        add_bpf(&mut machine, 4 * SEC, BPF_X, 64, true, exact);
        snapshot_bpf_programs(&mut machine, vec![LoadedBpfFunction {
            time: 2 * SEC, start: BPF_X, len: 64,
            name: "bpf_prog_fedcba0987654321_program".to_string(),
            name_is_exact: false,
            tag_is_known: false,
        }], true, true);
        add_kernel_sample(&mut machine, 10, 3 * SEC, &[BPF_X]);
        add_kernel_sample(&mut machine, 10, 5 * SEC, &[BPF_X]);
        machine.add_kernel_mappings_with(&mut KallsymsMock::new(vec![]));
        assert_eq!(Some(exact.to_string()), resolve_kernel(&machine, 10, BPF_X, 3 * SEC));
        assert_eq!(None, resolve_kernel(&machine, 10, BPF_X, 5 * SEC));
    }

    fn add_kernel_sample(
        machine: &mut ExportMachine,
        pid: u32,
        time: u64,
        frames: &[u64]) {
        let cpu = machine.sample_kind("cpu");

        machine.add_sample(
            time,
            MetricValue::Count(1),
            pid,
            pid,
            0,
            cpu,
            frames).unwrap();
    }

    fn resolve_kernel(
        machine: &ExportMachine,
        pid: u32,
        ip: u64,
        time: u64) -> Option<String> {
        let mapping = machine.find_process(pid)?.find_mapping(ip, Some(time))?;

        for symbol in mapping.symbols() {
            if ip >= symbol.start() && ip <= symbol.end() {
                return Some(
                    machine.strings().from_id(symbol.name_id()).unwrap().to_string());
            }
        }

        None
    }

    fn add_bpf(
        machine: &mut ExportMachine,
        time: u64,
        addr: u64,
        len: u64,
        unregister: bool,
        name: &str) {
        machine.add_kernel_dynamic_symbol(
            time,
            addr,
            len,
            KernelDynamicSymbolKind::Bpf,
            unregister,
            name);
    }

    #[test]
    fn kernel_mappings_order_records_from_independently_drained_cpus() {
        let mut machine = kernel_test_machine();
        machine.queue_kernel_dynamic_symbol(2 * SEC, BPF_X, 64,
            KernelDynamicSymbolKind::Bpf, true, "[bpf] a");
        machine.queue_kernel_dynamic_symbol(SEC, BPF_X, 64,
            KernelDynamicSymbolKind::Bpf, false, "[bpf] a");
        add_kernel_sample(&mut machine, 10, SEC + 1, &[BPF_X]);
        add_kernel_sample(&mut machine, 10, 2 * SEC + 1, &[BPF_X]);
        let mut kallsyms = KallsymsMock::new(vec![]);
        machine.add_kernel_mappings_with(&mut kallsyms);
        assert_eq!(Some("[bpf] a".to_string()), resolve_kernel(&machine, 10, BPF_X, SEC + 1));
        assert_eq!(None, resolve_kernel(&machine, 10, BPF_X, 2 * SEC + 1));
    }

    #[test]
    fn reused_address_matches_only_samples_in_each_lifetime() {
        let bpf = KernelDynamicSymbolKind::Bpf;
        let mut symbols = KernelDynamicSymbols::new();
        for generation in 0..1000u64 {
            symbols.register(generation * 100, BPF_X, 64, bpf, generation as usize);
            symbols.unregister(generation * 100 + 50, BPF_X, 64, bpf, generation as usize);
        }
        let ip_times: Vec<_> = (0..100_000).map(|time| (BPF_X, time)).collect();
        let mut states = vec![None; ip_times.len()];
        for (index, generation) in symbols.symbols().iter().enumerate() {
            assert!(mark_live_kernel_samples(&ip_times, &mut states, generation, index));
        }
        for (time, state) in states.iter().enumerate() {
            let expected = if time % 100 < 50 { Some(time / 100) } else { None };
            assert_eq!(expected, *state, "time {time}");
        }
    }

    #[test]
    fn ambiguous_address_count_handles_disjoint_and_overlapping_ranges() {
        let bpf = KernelDynamicSymbolKind::Bpf;
        let mut symbols = KernelDynamicSymbols::new();
        symbols.register(SEC, BPF_X, 64, bpf, 0);
        symbols.unregister(2 * SEC, BPF_X, 64, bpf, 0);
        symbols.register(3 * SEC, BPF_X + 32, 64, bpf, 1);
        symbols.register(SEC, BPF_X + 128, 64, bpf, 2);
        let generations: Vec<_> = symbols.symbols().iter().collect();
        let ips = vec![
            (BPF_X, SEC),
            (BPF_X + 32, SEC),
            (BPF_X + 64, SEC),
            (BPF_X + 128, SEC),
            (BPF_X + 129, SEC),
            (BPF_X + 129, 2 * SEC),
        ];
        let states = vec![Some(0), Some(0), None, Some(2), Some(2), None];
        assert_eq!(3, count_ambiguous_kernel_addresses(&ips, &states, &generations, &[0, 1, 2]));
    }

    #[test]
    fn graph_resolves_reused_bpf_caller_at_each_sample_time() {
        let mut machine = kernel_test_machine();
        add_bpf(&mut machine, SEC, BPF_X, 64, false, "[bpf] a");
        add_bpf(&mut machine, 2 * SEC, BPF_X, 64, true, "[bpf] a");
        add_bpf(&mut machine, 3 * SEC, BPF_X, 64, false, "[bpf] b");
        for time in [SEC + 1, 2 * SEC + 1, 3 * SEC + 1] {
            add_kernel_sample(&mut machine, 10, time, &[0xffffffff81000000, BPF_X]);
        }
        let mut kallsyms = KallsymsMock::new(vec![]);
        machine.add_kernel_mappings_with(&mut kallsyms);

        let mut graph = ExportGraph::new();
        let cpu = machine.sample_kind("cpu");
        graph.add_samples(&machine, machine.find_process(10).unwrap(), cpu, None);
        let children = graph.nodes()[graph.root_node()].children();
        assert_eq!(3, children.len());
        let methods: Vec<&str> = children.iter().map(|id| {
            graph.strings().from_id(graph.nodes()[*id].target().method()).unwrap()
        }).collect();
        assert!(methods.contains(&"[bpf] a"));
        assert!(methods.contains(&"[bpf] b"));
        assert!(methods.contains(&""));
    }

    #[test]
    fn kernel_mappings_scope_bpf_symbols_by_time() {
        let mut machine = kernel_test_machine();

        let static_fn = 0xffffffff81000000;
        let tail_fn = BPF_X - 0x100;
        let live = BPF_X + 0x4000;

        /*
         * Program A [X, X+256) lives [1s, 2s), program B [X, X+128) lives
         * [3s, 4s). Both are gone by finalization.
         */
        add_bpf(&mut machine, SEC, BPF_X, 256, false, "[bpf] bpf_prog_a");
        add_bpf(&mut machine, 2 * SEC, BPF_X, 256, true, "[bpf] bpf_prog_a");
        add_bpf(&mut machine, 3 * SEC, BPF_X, 128, false, "[bpf] bpf_prog_b");
        add_bpf(&mut machine, 4 * SEC, BPF_X, 128, true, "[bpf] bpf_prog_b");

        let at = BPF_X + 64;
        let times = [SEC / 2, SEC + SEC / 2, 2 * SEC, 2 * SEC + SEC / 2, 3 * SEC + SEC / 2, 4 * SEC];

        for time in times {
            add_kernel_sample(&mut machine, 10, time, &[at]);
        }

        /* Other processes run the programs and static code */
        add_kernel_sample(&mut machine, 20, SEC + SEC / 2, &[static_fn + 0x10, BPF_X + 0x80]);
        add_kernel_sample(&mut machine, 20, 3 * SEC + SEC / 2, &[BPF_X + 128]);
        add_kernel_sample(&mut machine, 20, 2 * SEC + SEC / 2, &[live + 8]);
        add_kernel_sample(&mut machine, 20, SEC + SEC / 2, &[tail_fn + 0x10]);
        add_kernel_sample(&mut machine, 30, SEC + SEC / 2, &[BPF_X - 1]);

        /*
         * Finalization view of kallsyms: neither program is present, so the
         * preceding symbol's inferred extent runs over their addresses. A
         * program loaded before recording is still live.
         */
        let mut kallsyms = KallsymsMock::new(vec![
            (static_fn, static_fn + 0xff, "do_work"),
            (tail_fn, live - 1, "tail_fn"),
            (live, live + 0x7f, "[bpf] bpf_prog_live"),
        ]);

        machine.add_kernel_mappings_with(&mut kallsyms);

        let expected = [
            None,
            Some("[bpf] bpf_prog_a"),
            None,
            None,
            Some("[bpf] bpf_prog_b"),
            None,
        ];

        for (time, expected) in times.iter().zip(expected) {
            assert_eq!(
                expected.map(String::from),
                resolve_kernel(&machine, 10, at, *time),
                "time {}", time);
        }

        let mapping = machine.find_process(10).unwrap()
            .find_mapping(at, Some(SEC + SEC / 2)).unwrap();
        assert_eq!("[bpf]", machine.strings().from_id(mapping.filename_id()).unwrap());
        let process = machine.find_process(10).unwrap();
        assert_eq!(2, process.mapping_unloads().len());
        for unload in process.mapping_unloads() {
            assert!(process.mappings().iter().any(|mapping| {
                mapping.id() == unload.id() &&
                    mapping.start() == unload.start() &&
                    mapping.end() == unload.end()
            }));
        }

        /* Callstack frame in another process */
        assert_eq!(
            Some("[bpf] bpf_prog_a".to_string()),
            resolve_kernel(&machine, 20, BPF_X + 0x80, SEC + SEC / 2));

        /* Exclusive end of B, still inside A's old extent */
        assert_eq!(None, resolve_kernel(&machine, 20, BPF_X + 128, 3 * SEC + SEC / 2));

        /* Static and still-live symbols keep resolving from kallsyms */
        assert_eq!(
            Some("do_work".to_string()),
            resolve_kernel(&machine, 20, static_fn + 0x10, SEC + SEC / 2));
        assert_eq!(
            Some("[bpf] bpf_prog_live".to_string()),
            resolve_kernel(&machine, 20, live + 8, 2 * SEC + SEC / 2));
        assert_eq!(
            Some("tail_fn".to_string()),
            resolve_kernel(&machine, 20, tail_fn + 0x10, SEC + SEC / 2));
        assert_eq!(
            Some("tail_fn".to_string()),
            resolve_kernel(&machine, 30, BPF_X - 1, SEC + SEC / 2));
    }

    #[test]
    fn kernel_mappings_bpf_emitted_only_when_sampled_live() {
        let mut machine = kernel_test_machine();

        add_bpf(&mut machine, SEC, BPF_X, 256, false, "[bpf] bpf_prog_a");
        add_bpf(&mut machine, 2 * SEC, BPF_X, 256, true, "[bpf] bpf_prog_a");
        add_bpf(&mut machine, 3 * SEC, BPF_X, 128, false, "[bpf] bpf_prog_b");
        add_bpf(&mut machine, 4 * SEC, BPF_X, 128, true, "[bpf] bpf_prog_b");

        let at = BPF_X + 64;

        /* Runs A, then the gap, then B at the same address */
        for time in [SEC + SEC / 2, 2 * SEC + SEC / 2, 3 * SEC + SEC / 2] {
            add_kernel_sample(&mut machine, 10, time, &[at]);
        }

        /* Only runs B */
        add_kernel_sample(&mut machine, 30, 3 * SEC + SEC / 2, &[at]);

        /* Only runs in the gap after A */
        add_kernel_sample(&mut machine, 40, 2 * SEC + SEC / 2, &[at]);

        /* Only runs A, twice */
        add_kernel_sample(&mut machine, 50, SEC + SEC / 4, &[at]);
        add_kernel_sample(&mut machine, 50, SEC + SEC / 2, &[at]);

        /* Runs A's tail, then B at an address A's extent also covers */
        add_kernel_sample(&mut machine, 60, SEC + SEC / 2, &[BPF_X + 200]);
        add_kernel_sample(&mut machine, 60, 3 * SEC + SEC / 2, &[BPF_X + 100]);

        machine.add_kernel_mappings_with(&mut KallsymsMock::new(Vec::new()));

        let names = |pid: u32| -> Vec<String> {
            let mut names: Vec<String> = machine.find_process(pid).unwrap()
                .mappings()
                .iter()
                .flat_map(|mapping| mapping.symbols())
                .map(|symbol| machine.strings().from_id(symbol.name_id()).unwrap().to_string())
                .collect();

            names.sort();
            names
        };

        assert_eq!(vec!["[bpf] bpf_prog_a", "[bpf] bpf_prog_b"], names(10));
        assert_eq!(vec!["[bpf] bpf_prog_b"], names(30));
        assert!(names(40).is_empty());
        assert_eq!(vec!["[bpf] bpf_prog_a"], names(50));

        assert_eq!(
            Some("[bpf] bpf_prog_b".to_string()),
            resolve_kernel(&machine, 30, at, 3 * SEC + SEC / 2));
        assert_eq!(None, resolve_kernel(&machine, 40, at, 2 * SEC + SEC / 2));
        assert_eq!(
            Some("[bpf] bpf_prog_a".to_string()),
            resolve_kernel(&machine, 50, at, SEC + SEC / 4));

        /*
         * Process 10 ran the same address under different generations and
         * process 60 ran B's code inside A's extent; only time can resolve
         * those. A's tail in process 60 is unambiguous.
         */
        assert_eq!(
            Some("[bpf] bpf_prog_a".to_string()),
            resolve_kernel(&machine, 60, BPF_X + 200, SEC + SEC / 2));
        assert_eq!(
            Some("[bpf] bpf_prog_b".to_string()),
            resolve_kernel(&machine, 60, BPF_X + 100, 3 * SEC + SEC / 2));
        assert_eq!(2, machine.kernel_dynamic_symbols().stats().time_ambiguous_addresses);
    }

    #[test]
    fn kernel_mappings_bpf_loaded_before_recording() {
        let mut machine = kernel_test_machine();

        /* Loaded before recording (no register seen), unloaded at 2s */
        add_bpf(&mut machine, 2 * SEC, BPF_X, 256, true, "[bpf] bpf_prog_a");

        add_kernel_sample(&mut machine, 10, SEC, &[BPF_X + 8]);
        add_kernel_sample(&mut machine, 10, 3 * SEC, &[BPF_X + 8]);
        add_kernel_sample(&mut machine, 10, 3 * SEC, &[BPF_X + 0x80]);

        /* Program C reused the address after A, but its load was not seen */
        let mut kallsyms = KallsymsMock::new(vec![
            (BPF_X, BPF_X + 0x3f, "[bpf] bpf_prog_c"),
        ]);

        machine.add_kernel_mappings_with(&mut kallsyms);

        assert_eq!(
            Some("[bpf] bpf_prog_a".to_string()),
            resolve_kernel(&machine, 10, BPF_X + 8, SEC));
        /* C's load was not observed, so it remains unknown after A unloads. */
        assert_eq!(None, resolve_kernel(&machine, 10, BPF_X + 8, 3 * SEC));
        assert_eq!(None, resolve_kernel(&machine, 10, BPF_X + 0x80, 3 * SEC));
    }

    #[test]
    fn kernel_mappings_bpf_replaced_at_same_time() {
        let mut machine = kernel_test_machine();

        add_bpf(&mut machine, SEC, BPF_X, 128, false, "[bpf] bpf_prog_a");
        add_bpf(&mut machine, 2 * SEC, BPF_X, 128, true, "[bpf] bpf_prog_a");
        add_bpf(&mut machine, 2 * SEC, BPF_X, 128, false, "[bpf] bpf_prog_b");

        add_kernel_sample(&mut machine, 10, 2 * SEC - 1, &[BPF_X + 8]);
        add_kernel_sample(&mut machine, 10, 2 * SEC, &[BPF_X + 8]);

        /* B is still loaded at finalization and in kallsyms */
        let mut kallsyms = KallsymsMock::new(vec![
            (BPF_X, BPF_X + 0x7f, "[bpf] bpf_prog_b"),
        ]);

        machine.add_kernel_mappings_with(&mut kallsyms);

        assert_eq!(
            Some("[bpf] bpf_prog_a".to_string()),
            resolve_kernel(&machine, 10, BPF_X + 8, 2 * SEC - 1));
        assert_eq!(
            Some("[bpf] bpf_prog_b".to_string()),
            resolve_kernel(&machine, 10, BPF_X + 8, 2 * SEC));

        /* B's live kallsyms entry is superseded by its generation */
        let proc = machine.find_process(10).unwrap();
        let vmlinux = proc.find_mapping(0xffffffff81000000, Some(0)).unwrap();
        assert!(vmlinux.symbols().is_empty());
    }

    #[test]
    fn kernel_mappings_bpf_snapshot_unloaded_after_recording() {
        let mut machine = kernel_test_machine();

        let tail_fn = BPF_X - 0x100;
        let other = BPF_X + 0x1000;

        /*
         * Program A was loaded before recording and found by the snapshot.
         * It unloaded after recording stopped, so no record was seen, and
         * program Q reused its address before finalization.
         */
        machine.add_kernel_dynamic_snapshot(
            SEC, BPF_X, 256, KernelDynamicSymbolKind::Bpf, "[bpf] bpf_prog_a");

        /*
         * Program B was also found by the snapshot, then unloaded during
         * recording. Its unregister record arrived before the snapshot was
         * added, and must not be duplicated or extended by it.
         */
        add_bpf(&mut machine, 3 * SEC, other, 64, true, "[bpf] bpf_prog_b");
        machine.add_kernel_dynamic_snapshot(
            SEC, other, 64, KernelDynamicSymbolKind::Bpf, "[bpf] bpf_prog_b");

        add_kernel_sample(&mut machine, 10, 2 * SEC, &[BPF_X + 8]);
        add_kernel_sample(&mut machine, 10, 2 * SEC, &[BPF_X + 0x80]);
        add_kernel_sample(&mut machine, 10, 2 * SEC, &[other + 8]);
        add_kernel_sample(&mut machine, 10, 4 * SEC, &[other + 8]);

        /*
         * Finalization view: Q occupies part of A's old extent and the
         * preceding symbol's inferred extent covers the rest.
         */
        let mut kallsyms = KallsymsMock::new(vec![
            (tail_fn, BPF_X - 1, "tail_fn"),
            (BPF_X, BPF_X + 0x3f, "[bpf] bpf_prog_q"),
            (BPF_X + 0x40, other + 0x7ff, "after_q"),
        ]);

        machine.add_kernel_mappings_with(&mut kallsyms);

        assert_eq!(
            Some("[bpf] bpf_prog_a".to_string()),
            resolve_kernel(&machine, 10, BPF_X + 8, 2 * SEC));
        assert_eq!(
            Some("[bpf] bpf_prog_a".to_string()),
            resolve_kernel(&machine, 10, BPF_X + 0x80, 2 * SEC));
        assert_eq!(
            Some("[bpf] bpf_prog_b".to_string()),
            resolve_kernel(&machine, 10, other + 8, 2 * SEC));
        assert_eq!(None, resolve_kernel(&machine, 10, other + 8, 4 * SEC));

        let stats = machine.kernel_dynamic_symbols().stats();
        assert_eq!(1, stats.snapshot_symbols);
        assert_eq!(2, machine.kernel_dynamic_symbols().symbols().len());
    }

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

        session.enable().unwrap();
        let env_handle = session.spawn_capture_environment();
        session.parse_for_duration(duration).unwrap();
        session.disable().unwrap();
        let _ = env_handle.join();

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
