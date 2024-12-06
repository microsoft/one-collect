use std::fs::File;

use crate::intern::InternedCallstacks;

use ruwind::{CodeSection, Unwindable};

use super::*;
use super::os::OSExportProcess;
use super::mappings::ExportMappingLookup;

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
    comm_id: Option<usize>,
    ns_pid: Option<u32>,
    pub(crate) os: OSExportProcess,
    samples: Vec<ExportProcessSample>,
    mappings: ExportMappingLookup,
    anon_maps: bool,
}

pub trait ExportProcessOSHooks {
    fn os_open_file(
        &self,
        path: &Path) -> anyhow::Result<File>;
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
        }
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

    pub fn ns_pid_mut(&mut self) -> &mut Option<u32> { &mut self.ns_pid }

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
}
