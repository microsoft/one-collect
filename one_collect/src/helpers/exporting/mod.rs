use std::collections::{HashMap, HashSet};
use std::collections::hash_map::{Values, ValuesMut};
use std::path::PathBuf;

use crate::Writable;
use crate::perf_event::PerfSession;
use crate::intern::{InternedStrings, InternedCallstacks};
use crate::helpers::callstack::CallstackReader;

const KERNEL_START:u64 = 0x800000000000;
const KERNEL_END:u64 = 0xFFFFFFFFFFFF;

pub mod symbols;
pub use symbols::{
    ExportSymbolReader,
    KernelSymbolReader,
    ExportSymbol,
};

pub mod process;
pub use process::{
    ExportProcess,
    ExportProcessSample,
};

pub mod mappings;
pub use mappings::{
    ExportMapping,
};

#[derive(Clone, PartialEq)]
pub struct ExportDevNode {
    dev: u64,
    ino: u64,
}

impl ExportDevNode {
    fn new(
        dev_maj: u32,
        dev_min: u32,
        ino: u64) -> Self {
        Self {
            dev: (dev_maj as u64) << 8 | dev_min as u64,
            ino,
        }
    }

    pub fn dev(&self) -> u64 { self.dev }

    pub fn ino(&self) -> u64 { self.ino }
}

impl From<&std::fs::Metadata> for ExportDevNode {
    fn from(meta: &std::fs::Metadata) -> Self {
        use std::os::linux::fs::MetadataExt;

        Self {
            dev: meta.st_dev(),
            ino: meta.st_ino(),
        }
    }
}

#[derive(Clone)]
pub struct ExportSettings {
    string_buckets: usize,
    callstack_buckets: usize,
    cpu_profiling: bool,
    process_fs: bool,
}

impl ExportSettings {
    pub fn new() -> Self {
        Self {
            string_buckets: 64,
            callstack_buckets: 512,
            cpu_profiling: true,
            process_fs: true,
        }
    }

    pub fn with_string_buckets(
        self,
        buckets: usize) -> Self {
        let mut clone = self.clone();
        clone.string_buckets = buckets;
        clone
    }

    pub fn with_callstack_buckets(
        self,
        buckets: usize) -> Self {
        let mut clone = self.clone();
        clone.callstack_buckets = buckets;
        clone
    }

    pub fn without_cpu_profiling(self) -> Self {
        let mut clone = self.clone();
        clone.cpu_profiling = false;
        clone
    }

    pub fn without_process_fs(self) -> Self {
        let mut clone = self.clone();
        clone.process_fs = false;
        clone
    }
}

pub struct ExportMachine {
    settings: ExportSettings,
    strings: InternedStrings,
    callstacks: InternedCallstacks,
    procs: HashMap<u32, ExportProcess>,
    path_buf: Writable<PathBuf>,
    kinds: Vec<String>,
    map_index: usize,
}

impl ExportMachine {
    pub fn new(settings: ExportSettings) -> Self {
        let strings = InternedStrings::new(settings.string_buckets);
        let callstacks = InternedCallstacks::new(settings.callstack_buckets);

        Self {
            settings,
            strings,
            callstacks,
            procs: HashMap::new(),
            path_buf: Writable::new(PathBuf::new()),
            kinds: Vec::new(),
            map_index: 0,
        }
    }

    pub fn sample_kinds(&self) -> &Vec<String> { &self.kinds }

    pub fn strings(&self) -> &InternedStrings { &self.strings }

    pub fn callstacks(&self) -> &InternedCallstacks { &self.callstacks }

    pub fn processes(&self) -> Values<u32, ExportProcess> { self.procs.values() }

    pub fn processes_mut(&mut self) -> ValuesMut<u32, ExportProcess> {
        self.procs.values_mut()
    }

    pub fn sample_kind(
        &mut self,
        name: &str) -> u16 {
        for (i, kind_name) in self.kinds.iter().enumerate() {
            if kind_name == name {
                return i as u16;
            }
        }

        let count = self.kinds.len() as u16;
        self.kinds.push(name.to_owned());
        count
    }

    pub fn intern(
        &mut self,
        value: &str) -> usize {
        self.strings.to_id(value)
    }

    pub fn add_kernel_mappings(
        &mut self) {
        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        let mut kernel_symbols = KernelSymbolReader::new();

        for proc in self.procs.values_mut() {
            proc.get_unique_kernel_ips(
                &mut addrs,
                &mut frames,
                &self.callstacks);

            if addrs.is_empty() {
                continue;
            }

            let mut kernel = ExportMapping::new(
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
                &mut kernel_symbols,
                &mut self.strings);

            proc.add_mapping(kernel);
        }
    }

    fn process_mut(
        &mut self,
        pid: u32) -> &mut ExportProcess {
        self.procs.entry(pid).or_insert_with(|| ExportProcess::new(pid))
    }

    fn add_mmap_exec(
        &mut self,
        pid: u32,
        addr: u64,
        len: u64,
        pgoffset: u64,
        maj: u32,
        min: u32,
        ino: u64,
        filename: &str) -> anyhow::Result<()> {
        let anon = filename.starts_with('[') ||
           filename.starts_with("/memfd:") ||
           filename.starts_with("//anon");

        let mut mapping = ExportMapping::new(
            self.intern(filename),
            addr,
            addr + len - 1,
            pgoffset,
            anon,
            self.map_index);

        if !anon {
            let node = ExportDevNode::new(maj, min, ino);

            mapping.set_node(node);
        }

        self.map_index += 1;

        self.process_mut(pid).add_mapping(mapping);

        Ok(())
    }

    fn add_comm_exec(
        &mut self,
        pid: u32,
        comm: &str) -> anyhow::Result<()> {
        let comm_id = self.intern(comm);
        let mut path_buf: Option<Writable<PathBuf>> = None;

        if self.settings.process_fs {
            path_buf = Some(self.path_buf.clone());
        }

        let proc = self.process_mut(pid);

        proc.set_comm_id(comm_id);

        if let Some(path_buf) = path_buf {
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

    pub fn add_sample(
        &mut self,
        time: u64,
        value: u64,
        pid: u32,
        tid: u32,
        cpu: u16,
        kind: u16,
        frames: &Vec<u64>) -> anyhow::Result<()> {
        let ip = frames[0];
        let callstack_id = self.callstacks.to_id(&frames[1..]);
        let sample = ExportProcessSample::new(
            time,
            value,
            cpu,
            kind,
            tid,
            ip,
            callstack_id);

        self.process_mut(pid).add_sample(sample);

        Ok(())
    }

    pub fn hook_to_session(
        self,
        session: &mut PerfSession,
        callstack_reader: CallstackReader) -> Writable<ExportMachine> {
        let cpu_profiling = self.settings.cpu_profiling;

        let machine = Writable::new(self);

        let ancillary = session.ancillary_data();
        let time_field = session.time_data_ref();
        let pid_field = session.pid_field_ref();
        let tid_field = session.tid_data_ref();

        if cpu_profiling {
            /* Get sample kind for CPU */
            let kind = machine.borrow_mut().sample_kind("cpu");

            /* Hook cpu profile event */
            let event = session.cpu_profile_event();
            let event_machine = machine.clone();
            let mut frames: Vec<u64> = Vec::new();

            event.add_callback(move |full_data,_fmt,_data| {
                let mut machine = event_machine.borrow_mut();
                let ancillary = ancillary.borrow();

                let cpu = ancillary.cpu() as u16;
                let time = time_field.get_u64(full_data)?;
                let pid = pid_field.get_u32(full_data)?;
                let tid = tid_field.get_u32(full_data)?;

                frames.clear();

                callstack_reader.read_frames(
                    full_data,
                    &mut frames);

                machine.add_sample(
                    time,
                    1,
                    pid,
                    tid,
                    cpu,
                    kind,
                    &frames)
            });
        }

        /* Hook mmap records */
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
        event.add_callback(move |_full_data,fmt,data| {
            let prot = fmt.get_u32(prot, data)?;

            /* Skip non-executable mmaps */
            if prot & PROT_EXEC != PROT_EXEC {
                return Ok(());
            }

            event_machine.borrow_mut().add_mmap_exec(
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

        event.add_callback(move |_full_data,fmt,data| {
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

        event.add_callback(move |_full_data,fmt,data| {
            let pid = fmt.get_u32(pid, data)?;
            let tid = fmt.get_u32(tid, data)?;

            if pid != tid {
                return Ok(());
            }

            event_machine.borrow_mut().fork_exec(
                pid,
                fmt.get_u32(ppid, data)?)
        });

        machine
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::os::linux::fs::MetadataExt;

    use crate::perf_event::*;
    use crate::helpers::callstack::{CallstackHelper, CallstackHelp};

    #[test]
    #[ignore]
    fn it_works() {
        let helper = CallstackHelper::new()
            .with_dwarf_unwinding();

        let freq = 1000;

        let profiling = RingBufBuilder::for_profiling(freq)
            .with_callchain_data();

        let mut builder = RingBufSessionBuilder::new()
            .with_page_count(256)
            .with_profiling_events(profiling)
            .with_callstack_help(&helper);

        let settings = ExportSettings::new();
        let exporter = ExportMachine::new(settings);

        let mut session = builder.build().unwrap();

        let exporter = exporter.hook_to_session(
            &mut session,
            helper.to_reader());

        let duration = std::time::Duration::from_secs(1);

        session.lost_event().add_callback(|_,_,_| {
            println!("WARN: Lost event data");

            Ok(())
        });

        session.lost_samples_event().add_callback(|_,_,_| {
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
                    "{}: {:x} ({}) TID={}",
                    sample.time(),
                    sample.ip(),
                    sample.callstack_id(),
                    sample.tid());
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
