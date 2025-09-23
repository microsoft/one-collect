// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::cell::OnceCell;

use crate::intern::InternedCallstacks;

use ruwind::{CodeSection, Unwindable};

use super::*;
use super::os::OSExportProcess;
use super::mappings::ExportMappingLookup;
use super::symbols::*;

#[derive(Clone, Copy, PartialEq)]
pub enum MetricValue {
    Count(u64),
    Duration(u64),
    Bytes(u64),
    Span(usize),
}

impl MetricValue {
    pub fn try_get_value_closure(
        metric_type: &str,
        data_type: &str) -> Option<Box<dyn FnMut(&[u8]) -> anyhow::Result<MetricValue>>> {
        let signed;
        let size;

        match data_type {
            "char" | "s8" | "i8" => {
                signed = true;
                size = 1;
            },

            "unsigned char" | "u8" => {
                signed = false;
                size = 1;
            },

            "short" | "s16" | "i16" => {
                signed = true;
                size = 2;
            },

            "unsigned short" | "u16" => {
                signed = false;
                size = 2;
            },

            "int" | "s32" | "i32" => {
                signed = true;
                size = 4;
            },

            "unsigned int" | "u32" => {
                signed = false;
                size = 4;
            },

            "long" | "s64" | "i64" => {
                signed = true;
                size = 8;
            },

            "unsigned long" | "u64" => {
                signed = false;
                size = 8;
            },

            _ => { return None; },
        }

        match metric_type {
            "count" => {
                match size {
                    1 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i8::from_ne_bytes(data[0..1].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Count(i as u64))
                                } else {
                                    Ok(MetricValue::Count(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Count(
                                    u8::from_ne_bytes(data[0..1].try_into()?) as u64))
                            }))
                        }
                    },

                    2 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i16::from_ne_bytes(data[0..2].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Count(i as u64))
                                } else {
                                    Ok(MetricValue::Count(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Count(
                                    u16::from_ne_bytes(data[0..2].try_into()?) as u64))
                            }))
                        }
                    },

                    4 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i32::from_ne_bytes(data[0..4].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Count(i as u64))
                                } else {
                                    Ok(MetricValue::Count(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Count(
                                    u32::from_ne_bytes(data[0..4].try_into()?) as u64))
                            }))
                        }
                    },

                    8 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i64::from_ne_bytes(data[0..8].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Count(i as u64))
                                } else {
                                    Ok(MetricValue::Count(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Count(
                                    u64::from_ne_bytes(data[0..8].try_into()?) as u64))
                            }))
                        }
                    },

                    _ => { None },
                }
            },

            "duration" => {
                match size {
                    1 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i8::from_ne_bytes(data[0..1].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Duration(i as u64))
                                } else {
                                    Ok(MetricValue::Duration(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Count(
                                    u8::from_ne_bytes(data[0..1].try_into()?) as u64))
                            }))
                        }
                    },

                    2 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i16::from_ne_bytes(data[0..2].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Duration(i as u64))
                                } else {
                                    Ok(MetricValue::Duration(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Duration(
                                    u16::from_ne_bytes(data[0..2].try_into()?) as u64))
                            }))
                        }
                    },

                    4 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i32::from_ne_bytes(data[0..4].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Duration(i as u64))
                                } else {
                                    Ok(MetricValue::Duration(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Duration(
                                    u32::from_ne_bytes(data[0..4].try_into()?) as u64))
                            }))
                        }
                    },

                    8 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i64::from_ne_bytes(data[0..8].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Duration(i as u64))
                                } else {
                                    Ok(MetricValue::Duration(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Duration(
                                    u64::from_ne_bytes(data[0..8].try_into()?) as u64))
                            }))
                        }
                    },

                    _ => { None },
                }
            },

            "bytes" => {
                match size {
                    1 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i8::from_ne_bytes(data[0..1].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Bytes(i as u64))
                                } else {
                                    Ok(MetricValue::Bytes(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Count(
                                    u8::from_ne_bytes(data[0..1].try_into()?) as u64))
                            }))
                        }
                    },

                    2 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i16::from_ne_bytes(data[0..2].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Bytes(i as u64))
                                } else {
                                    Ok(MetricValue::Bytes(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Bytes(
                                    u16::from_ne_bytes(data[0..2].try_into()?) as u64))
                            }))
                        }
                    },

                    4 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i32::from_ne_bytes(data[0..4].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Bytes(i as u64))
                                } else {
                                    Ok(MetricValue::Bytes(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Bytes(
                                    u32::from_ne_bytes(data[0..4].try_into()?) as u64))
                            }))
                        }
                    },

                    8 => {
                        if signed {
                            Some(Box::new(|data| {
                                let i = i64::from_ne_bytes(data[0..8].try_into()?);
                                if i > 0 {
                                    Ok(MetricValue::Bytes(i as u64))
                                } else {
                                    Ok(MetricValue::Bytes(0))
                                }
                            }))
                        } else {
                            Some(Box::new(|data| {
                                Ok(MetricValue::Bytes(
                                    u64::from_ne_bytes(data[0..8].try_into()?) as u64))
                            }))
                        }
                    },

                    _ => { None },
                }
            },

            _ => { None },
        }
    }
}

#[derive(Clone, Copy)]
pub struct ExportProcessSample {
    time: u64,
    value: MetricValue,
    cpu: u16,
    kind: u16,
    tid: u32,
    ip: u64,

    /*
     * Never expect more than millions of these:
     * Callers expect these to be usize for ease of use.
     * However, we never expect this to get into the billions.
     * We can save space by casting in and out of this struct
     * safely from usize to u32 and back.
     */
    callstack_id: u32,
    record_id: u32,
    attributes_id: u32,
}

impl ExportProcessSample {
    pub fn new(
        time: u64,
        value: MetricValue,
        cpu: u16,
        kind: u16,
        tid: u32,
        ip: u64,
        callstack_id: usize) -> Self {
        let callstack_id = callstack_id as u32;

        Self {
            time,
            value,
            cpu,
            kind,
            tid,
            ip,
            callstack_id,
            record_id: 0,
            attributes_id: 0,
        }
    }

    pub fn time_mut(&mut self) -> &mut u64 { &mut self.time }

    pub fn value_mut(&mut self) -> &mut MetricValue { &mut self.value }

    pub fn time(&self) -> u64 { self.time }

    pub fn value(&self) -> MetricValue { self.value }

    pub fn cpu(&self) -> u16 { self.cpu }

    pub fn kind(&self) -> u16 { self.kind }

    pub fn tid(&self) -> u32 { self.tid }

    pub fn ip(&self) -> u64 { self.ip }

    pub fn callstack_id(&self) -> usize { self.callstack_id as usize }

    pub fn record_id(&self) -> usize { self.record_id as usize }

    pub fn has_record(&self) -> bool { self.record_id != 0 }

    pub fn attach_record(
        &mut self,
        record_id: usize) {
        self.record_id = record_id as u32;
    }

    pub fn attributes_id(&self) -> usize { self.attributes_id as usize }

    pub fn has_attributes(&self) -> bool { self.attributes_id != 0 }

    pub fn attach_attributes(
        &mut self,
        attributes_id: usize) {
        self.attributes_id = attributes_id as u32;
    }
}

const EXPORT_PROCESS_FLAG_CREATED: u8 = 1 << 0;
const EXPORT_PROCESS_FLAG_EXITED: u8 = 1 << 1;

pub struct ExportProcessReplay<'a> {
    process: &'a ExportProcess,
    current_time: u64,
    sample_index: usize,
    mapping_index: usize,
    flags: u8,
}

impl<'a> ExportProcessReplay<'a> {
    fn new(process: &'a ExportProcess) -> Self {
        let mut replay = Self {
            process,
            current_time: u64::MAX,
            sample_index: 0,
            mapping_index: 0,
            flags: 0,
        };

        /* Pre-advance to ensure accurate state */
        replay.advance();

        replay
    }

    pub fn process(&self) -> &'a ExportProcess { self.process }

    pub fn time(&self) -> u64 { self.current_time }

    pub fn created_event(&self) -> bool {
        if let Some(time) = self.process.create_time_qpc {
            if time == self.current_time {
                return true;
            }
        }

        false
    }

    pub fn exited_event(&self) -> bool {
        if let Some(time) = self.process.exit_time_qpc {
            if time == self.current_time {
                return true;
            }
        }

        false
    }

    pub fn sample_event(&self) -> Option<&'a ExportProcessSample> {
        if let Some(sample) = self.try_get_sample() {
            if sample.time() == self.current_time {
                return Some(sample);
            }
        }

        None
    }

    pub fn mapping_event(&self) -> Option<&'a ExportMapping> {
        if let Some(mapping) = self.try_get_mapping() {
            if mapping.time() == self.current_time {
                return Some(mapping);
            }
        }

        None
    }

    pub(crate) fn try_get_sample(&self) -> Option<&'a ExportProcessSample> {
        self.process.samples().get(self.sample_index)
    }

    pub(crate) fn try_get_mapping(&self) -> Option<&'a ExportMapping> {
        self.process.mappings().get(self.mapping_index)
    }

    pub(crate) fn done(&self) -> bool { self.current_time == u64::MAX }

    pub(crate) fn advance(&mut self) {
        /* Advance index by time */
        if self.sample_event().is_some() {
            self.sample_index += 1;
        }

        if self.mapping_event().is_some() {
            self.mapping_index += 1;
        }

        /* Reset to find the earliest time */
        self.current_time = u64::MAX;

        /* Advance current time to earliest event */
        if let Some(sample) = self.try_get_sample() {
            if sample.time() < self.current_time {
                self.current_time = sample.time();
            }
        }

        if let Some(mapping) = self.try_get_mapping() {
            if mapping.time() < self.current_time {
                self.current_time = mapping.time();
            }
        }

        /* Take into account process states */
        if self.flags & EXPORT_PROCESS_FLAG_CREATED == 0 {
            if let Some(time) = self.process.create_time_qpc {
                if time < self.current_time {
                    self.current_time = time;
                }
            } else {
                /* No time, so just set flags */
                self.flags |= EXPORT_PROCESS_FLAG_CREATED;
            }
        }

        if self.flags & EXPORT_PROCESS_FLAG_EXITED == 0 {
            if let Some(time) = self.process.exit_time_qpc {
                if time < self.current_time {
                    self.current_time = time;
                }
            } else {
                /* No time, so just set flags */
                self.flags |= EXPORT_PROCESS_FLAG_EXITED;
            }
        }

        /* Update flags (Must be done later to allow exit/create inversion) */
        if self.created_event() {
            self.flags |= EXPORT_PROCESS_FLAG_CREATED;
        }

        if self.exited_event() {
            self.flags |= EXPORT_PROCESS_FLAG_EXITED;
        }
    }
}

pub struct ExportProcess {
    pid: u32,
    comm_id: Option<usize>,
    ns_pid: Option<u32>,
    pub(crate) os: OSExportProcess,
    samples: Vec<ExportProcessSample>,
    mappings: ExportMappingLookup,
    anon_maps: bool,
    create_time_qpc: Option<u64>,
    exit_time_qpc: Option<u64>,
    dyn_symbols: Vec<ExportTimeSymbol>,
    user_page_map: OnceCell<SymbolPageMap>,
}

pub trait ExportProcessOSHooks {
    fn os_open_file(
        &self,
        path: &Path) -> anyhow::Result<File>;

    fn system_page_mask(&self) -> u64;

    fn system_page_size(&self) -> u64;
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
            os: OSExportProcess::new(),
            samples: Vec::new(),
            mappings: ExportMappingLookup::default(),
            anon_maps: false,
            create_time_qpc: None,
            exit_time_qpc: None,
            dyn_symbols: Vec::new(),
            user_page_map: OnceCell::new(),
        }
    }

    /*
     * Need to keep this crate local, since we need to ensure things
     * are properly sorted before calling this method. Rust doesn't
     * seem to have a &mut self that can be later changed to &self
     * from within a method. We need to find a better pattern if there
     * is a need to call this directly on a single process instead
     * of using ExportMachine::replay_by_time().
     */
    pub(crate) fn to_replay(&self) -> ExportProcessReplay {
        ExportProcessReplay::new(&self)
    }

    pub fn open_file(
        &self,
        path: &Path) -> anyhow::Result<File> {
        self.os_open_file(path)
    }

    fn find_section(
        &self,
        ip: u64) -> Option<&dyn CodeSection> {
        match self.find_mapping(ip, None) {
            Some(mapping) => { Some(mapping) },
            None => { None },
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

    pub fn needs_dynamic_symbol(
        &self,
        symbol: &DynamicSymbol,
        callstacks: &InternedCallstacks) -> bool {
        if symbol.has_flag(SYM_FLAG_MUST_MATCH) {
            /* Only build the map once until new samples come in */
            let page_map = self.user_page_map.get_or_init(|| {
                let mut page_map = SymbolPageMap::new(256);
                let mut addrs = HashSet::new();
                let mut frames = Vec::new();

                Self::get_unique_user_ips(
                    &self.samples,
                    &mut addrs,
                    &mut frames,
                    callstacks,
                    None);

                for addr in addrs {
                    page_map.mark_ip(addr);
                }

                page_map
            });

            /* Check map to determine if we need the symbol */
            if !page_map.seen_range(symbol.start(), symbol.end()) {
                return false;
            }
        }

        true
    }

    pub fn add_dynamic_symbol(
        &mut self,
        symbol: ExportTimeSymbol) {
        self.dyn_symbols.push(symbol);
    }

    pub fn add_dynamic_symbol_mappings(
        &mut self,
        map_index: &mut usize) {
        /* Sort by symbol address range */
        self.dyn_symbols.sort_by(|a,b| {
            b.symbol().start().cmp(&a.symbol().start())
        });

        /* We will add dynamic mappings at a page boundary */
        let mut dyn_mappings: Vec<ExportMapping> = Vec::new();
        let page_mask = self.system_page_mask();
        let page_size = self.system_page_size();

        /* Mutably drain without references */
        while !self.dyn_symbols.is_empty() {
            /* SAFETY: Checked non-empty already */
            let dyn_symbol = self.dyn_symbols.pop().unwrap();
            let time = dyn_symbol.time();
            let symbol = dyn_symbol.symbol();

            /* Link mappings */
            match self.mappings.find_index(
                symbol.start(),
                Some(time)) {
                Some(index) => {
                    /* Already mapped region, simply add */
                    self.mappings_mut()[index].add_symbol(symbol);
                },
                None => {
                    /* Not found, check our in-progress maps */
                    let mut found = false;

                    for mapping in &mut dyn_mappings {
                        if mapping.contains_ip(symbol.start()) {
                            /* Update time and add symbol */
                            if mapping.time() > time {
                                *mapping.time_mut() = time;
                            }

                            /* Extend out to next page if needed */
                            if mapping.end() < symbol.end() {
                                let end = (symbol.end() & page_mask) + page_size - 1;

                                *mapping.end_mut() = end;
                            }

                            mapping.add_symbol(symbol.clone());

                            /* No more checking */
                            found = true;
                            break;
                        }
                    }

                    /* Add a new mapping if needed */
                    if !found {
                        /* Start at page boundary */
                        let start = symbol.start() & page_mask;

                        /* Extend to end of page boundary */
                        let end = (symbol.end() & page_mask) + page_size - 1;

                        let mut mapping = ExportMapping::new(
                            time,
                            0,
                            start,
                            end,
                            0,
                            true,
                            *map_index,
                            UnwindType::Prolog);

                        mapping.add_symbol(symbol.clone());

                        dyn_mappings.push(mapping);

                        *map_index += 1;
                    }
                }
            }
        }

        /* Add any dynamic mappings */
        self.mappings_mut().extend_from_slice(&dyn_mappings);
    }

    pub fn add_sample(
        &mut self,
        sample: ExportProcessSample) {
        self.samples.push(sample);

        /* Clear page map */
        self.user_page_map = OnceCell::new();
    }

    pub fn set_comm_id(
        &mut self,
        comm_id: usize) {
        self.comm_id = Some(comm_id);
    }

    pub fn set_create_time_qpc(
        &mut self,
        qpc: u64) {
        self.create_time_qpc = Some(qpc);
    }

    pub fn set_exit_time_qpc(
        &mut self,
        qpc: u64) {
        self.exit_time_qpc = Some(qpc);
    }

    pub fn sort_samples_by_time(&mut self) {
        self.samples.sort_by(|a, b| a.time.cmp(&b.time));
    }

    pub fn sort_mappings_by_time(&mut self) {
        self.mappings.sort_mappings_by_time();
    }

    pub fn pid(&self) -> u32 { self.pid }

    pub fn ns_pid(&self) -> Option<u32> { self.ns_pid }

    pub fn ns_pid_mut(&mut self) -> &mut Option<u32> { &mut self.ns_pid }

    pub fn comm_id(&self) -> Option<usize> { self.comm_id }

    pub fn create_time_qpc(&self) -> Option<u64> { self.create_time_qpc }

    pub fn exit_time_qpc(&self) -> Option<u64> { self.exit_time_qpc }

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
                strings);
        }
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

    pub fn fork(
        &self,
        pid: u32) -> Self { 
        let mut fork = Self::new(pid);

        fork.comm_id = self.comm_id;
        fork.mappings = self.mappings.clone();
        fork.os = self.os.clone();

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
        let mut map = ExportMapping::new(time, 0, start, end, 0, false, id, UnwindType::Prolog);
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

    #[test]
    fn sort_samples_by_time() {
        let mut proc = ExportProcess::new(1);

        let first = ExportProcessSample::new(0, MetricValue::Count(0), 0, 0, 0, 0, 0);
        let second = ExportProcessSample::new(1, MetricValue::Count(0), 0, 0, 0, 0, 0);
        let third = ExportProcessSample::new(2, MetricValue::Count(0), 0, 0, 0, 0, 0);
        let forth = ExportProcessSample::new(3, MetricValue::Count(0), 0, 0, 0, 0, 0);

        proc.add_sample(forth);
        proc.add_sample(second);
        proc.add_sample(first);
        proc.add_sample(third);

        proc.sort_samples_by_time();

        for (i,sample) in proc.samples().iter().enumerate() {
            assert_eq!(i as u64, sample.time());
        }
    }

    #[test]
    fn to_replay() {
        let mut proc = ExportProcess::new(1);

        proc.set_create_time_qpc(0);

        proc.add_mapping(new_mapping(10, 10, 19, 1));
        let first = ExportProcessSample::new(11, MetricValue::Count(0), 0, 0, 0, 0, 0);

        proc.add_mapping(new_mapping(20, 20, 29, 2));
        let second = ExportProcessSample::new(21, MetricValue::Count(0), 0, 0, 0, 0, 0);

        let third = ExportProcessSample::new(29, MetricValue::Count(0), 0, 0, 0, 0, 0);
        proc.add_mapping(new_mapping(30, 30, 39, 3));
        let forth = ExportProcessSample::new(35, MetricValue::Count(0), 0, 0, 0, 0, 0);

        proc.set_exit_time_qpc(40);

        proc.add_sample(forth);
        proc.add_sample(second);
        proc.add_sample(first);
        proc.add_sample(third);

        proc.sort_samples_by_time();
        proc.sort_mappings_by_time();

        /*
         * Perfect case: Expected order of create, etc.
         */
        let mut replay = proc.to_replay();

        /* Time: 0 */
        assert!(!replay.done());
        assert_eq!(0, replay.time());
        assert!(replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 10 */
        assert!(!replay.done());
        assert_eq!(10, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_some());
        replay.advance();

        /* Time: 11 */
        assert!(!replay.done());
        assert_eq!(11, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_some());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 20 */
        assert!(!replay.done());
        assert_eq!(20, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_some());
        replay.advance();

        /* Time: 21 */
        assert!(!replay.done());
        assert_eq!(21, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_some());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 29 */
        assert!(!replay.done());
        assert_eq!(29, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_some());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 30 */
        assert!(!replay.done());
        assert_eq!(30, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_some());
        replay.advance();

        /* Time: 35 */
        assert!(!replay.done());
        assert_eq!(35, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_some());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 40 */
        assert!(!replay.done());
        assert_eq!(40, replay.time());
        assert!(!replay.created_event());
        assert!(replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 41 + */
        assert!(replay.done());

        /*
         * Unexpected case: Samples, create, exit, mappings
         */
        let mut proc = ExportProcess::new(1);

        proc.add_mapping(new_mapping(0, 10, 19, 1));
        let first = ExportProcessSample::new(1, MetricValue::Count(0), 0, 0, 0, 0, 0);
        proc.add_sample(first);

        proc.set_create_time_qpc(10);

        let second = ExportProcessSample::new(11, MetricValue::Count(0), 0, 0, 0, 0, 0);
        proc.add_sample(second);

        proc.set_exit_time_qpc(40);

        let third = ExportProcessSample::new(41, MetricValue::Count(0), 0, 0, 0, 0, 0);
        proc.add_sample(third);

        proc.sort_samples_by_time();
        proc.sort_mappings_by_time();

        let mut replay = proc.to_replay();

        /* Time: 0 */
        assert!(!replay.done());
        assert_eq!(0, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_some());
        replay.advance();

        /* Time: 1 */
        assert!(!replay.done());
        assert_eq!(1, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_some());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 10 */
        assert!(!replay.done());
        assert_eq!(10, replay.time());
        assert!(replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 11 */
        assert!(!replay.done());
        assert_eq!(11, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_some());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 40 */
        assert!(!replay.done());
        assert_eq!(40, replay.time());
        assert!(!replay.created_event());
        assert!(replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 41 */
        assert!(!replay.done());
        assert_eq!(41, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_some());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 42 + */
        assert!(replay.done());

        /*
         * Weird case: exit, create, sample
         */
        let mut proc = ExportProcess::new(1);

        proc.set_exit_time_qpc(0);
        proc.set_create_time_qpc(10);

        let first = ExportProcessSample::new(11, MetricValue::Count(0), 0, 0, 0, 0, 0);
        proc.add_sample(first);

        proc.sort_samples_by_time();
        proc.sort_mappings_by_time();

        let mut replay = proc.to_replay();

        /* Time: 0 */
        assert!(!replay.done());
        assert_eq!(0, replay.time());
        assert!(!replay.created_event());
        assert!(replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 10 */
        assert!(!replay.done());
        assert_eq!(10, replay.time());
        assert!(replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_none());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 11 */
        assert!(!replay.done());
        assert_eq!(11, replay.time());
        assert!(!replay.created_event());
        assert!(!replay.exited_event());
        assert!(replay.sample_event().is_some());
        assert!(replay.mapping_event().is_none());
        replay.advance();

        /* Time: 12 + */
        assert!(replay.done());
    }

    fn time_symbol(
        time: u64,
        name_id: usize,
        start: u64,
        end: u64) -> ExportTimeSymbol {
        ExportTimeSymbol::new(
            time,
            ExportSymbol::new(
                name_id,
                start,
                end))
    }

    #[test]
    fn try_get_value_closure() {
        /* Valid Cases */
        let mut closure = MetricValue::try_get_value_closure("count", "i8").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i8.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i8).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "s8").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i8.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i8).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "char").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i8.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i8).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "u8").unwrap();
        assert!(MetricValue::Count(2) == closure(&2u8.to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "unsigned char").unwrap();
        assert!(MetricValue::Count(2) == closure(&2u8.to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "i16").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i16.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i16).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "s16").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i16.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i16).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "short").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i16.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i16).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "u16").unwrap();
        assert!(MetricValue::Count(2) == closure(&2u16.to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "unsigned short").unwrap();
        assert!(MetricValue::Count(2) == closure(&2u16.to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "i32").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i32.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i32).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "s32").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i32.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i32).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "int").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i32.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i32).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "u32").unwrap();
        assert!(MetricValue::Count(2) == closure(&2u32.to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "unsigned int").unwrap();
        assert!(MetricValue::Count(2) == closure(&2u32.to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "i64").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i64.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i64).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "s64").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i64.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i64).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "long").unwrap();
        assert!(MetricValue::Count(2) == closure(&2i64.to_ne_bytes()).unwrap());
        assert!(MetricValue::Count(0) == closure(&(-2i64).to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "u64").unwrap();
        assert!(MetricValue::Count(2) == closure(&2u64.to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("count", "unsigned long").unwrap();
        assert!(MetricValue::Count(2) == closure(&2u64.to_ne_bytes()).unwrap());

        /* Invalid */
        assert!(MetricValue::try_get_value_closure("invalid", "unsigned long").is_none());
        assert!(MetricValue::try_get_value_closure("count", "invalid").is_none());

        /* Sanity other types */
        let mut closure = MetricValue::try_get_value_closure("bytes", "u64").unwrap();
        assert!(MetricValue::Bytes(2) == closure(&2u64.to_ne_bytes()).unwrap());

        let mut closure = MetricValue::try_get_value_closure("duration", "u64").unwrap();
        assert!(MetricValue::Duration(2) == closure(&2u64.to_ne_bytes()).unwrap());
    }

    #[test]
    fn add_dynamic_symbol_mappings() {
        let mut proc = ExportProcess::new(1);

        /* First page */
        proc.add_dynamic_symbol(time_symbol(0, 0, 0, 1024));

        /* Second page */
        proc.add_dynamic_symbol(time_symbol(0, 1, 4096, 4097));
        proc.add_dynamic_symbol(time_symbol(0, 2, 4098, 4099));
        proc.add_dynamic_symbol(time_symbol(0, 3, 4100, 4101));

        /* Third page */
        proc.add_dynamic_symbol(time_symbol(0, 4, 8192, 8193));
        proc.add_dynamic_symbol(time_symbol(0, 5, 8194, 8195));

        let mut index = 0;
        proc.add_dynamic_symbol_mappings(&mut index);

        assert_eq!(3, proc.mappings().len());

        /* First page */
        let found = proc.find_mapping(256, None);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(0, found.start());
        assert_eq!(4095, found.end());

        assert_eq!(1, found.symbols().len());

        /* Second page */
        let found = proc.find_mapping(4097, None);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(4096, found.start());
        assert_eq!(8191, found.end());

        let found = proc.find_mapping(4098, None);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(4096, found.start());
        assert_eq!(8191, found.end());

        let found = proc.find_mapping(4100, None);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(4096, found.start());
        assert_eq!(8191, found.end());

        assert_eq!(3, found.symbols().len());

        /* Third page */
        let found = proc.find_mapping(8192, None);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(8192, found.start());
        assert_eq!(12287, found.end());

        let found = proc.find_mapping(8194, None);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(8192, found.start());
        assert_eq!(12287, found.end());

        assert_eq!(2, found.symbols().len());
    }
}
