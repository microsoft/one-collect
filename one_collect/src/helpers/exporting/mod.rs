use std::collections::{HashMap, HashSet};
use std::collections::hash_map::{Values, ValuesMut};
use std::collections::hash_map::Entry::Occupied;
use std::path::PathBuf;

use crate::{ReadOnly, Writable};
use crate::event::{Event, EventFormat, DataFieldRef};
use crate::perf_event::{AncillaryData, PerfSession};
use crate::intern::{InternedStrings, InternedCallstacks};
use crate::helpers::callstack::CallstackReader;
use crate::perf_event::{RingBufSessionBuilder, RingBufBuilder};
use crate::perf_event::abi::PERF_RECORD_MISC_SWITCH_OUT;

const KERNEL_START:u64 = 0x800000000000;
const KERNEL_END:u64 = 0xFFFFFFFFFFFFFFFF;

pub mod graph;
pub mod formats;

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

use self::symbols::PerfMapSymbolReader;

#[derive(Default)]
struct ExportCSwitch {
    start_time: u64,
    sample: Option<ExportProcessSample>,
}

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

struct ExportSampler {
    exporter: Writable<ExportMachine>,
    ancillary: ReadOnly<AncillaryData>,
    reader: CallstackReader,
    time_field: DataFieldRef,
    pid_field: DataFieldRef,
    tid_field: DataFieldRef,
    frames: Vec<u64>,
}

impl ExportSampler {
    fn new(
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

    fn time(
        &self,
        full_data: &[u8]) -> anyhow::Result<u64> {
        self.time_field.get_u64(full_data)
    }

    fn pid(
        &self,
        full_data: &[u8]) -> anyhow::Result<u32> {
        self.pid_field.get_u32(full_data)
    }

    fn tid(
        &self,
        full_data: &[u8]) -> anyhow::Result<u32> {
        self.tid_field.get_u32(full_data)
    }

    fn cpu(&self) -> u16 {
        self.ancillary.borrow().cpu() as u16
    }

    fn make_sample(
        &mut self,
        full_data: &[u8],
        value: u64,
        kind: u16) -> anyhow::Result<ExportProcessSample> {
        self.frames.clear();

        self.reader.read_frames(
            full_data,
            &mut self.frames);

        Ok(self.exporter.borrow_mut().make_sample(
            self.time(full_data)?,
            value,
            self.tid(full_data)?,
            self.cpu(),
            kind,
            &self.frames))
    }

    fn add_custom_sample(
        &mut self,
        pid: u32,
        sample: ExportProcessSample) -> anyhow::Result<()> {
        self.exporter.borrow_mut().process_mut(pid).add_sample(sample);
        Ok(())
    }

    fn add_sample(
        &mut self,
        full_data: &[u8],
        value: u64,
        kind: u16) -> anyhow::Result<()> {
        self.frames.clear();

        self.reader.read_frames(
            full_data,
            &mut self.frames);

        self.exporter.borrow_mut().add_sample(
            self.time(full_data)?,
            value,
            self.pid(full_data)?,
            self.tid(full_data)?,
            self.cpu(),
            kind,
            &self.frames)
    }
}

pub struct ExportBuiltContext<'a> {
    exporter: &'a mut ExportMachine,
    session: &'a mut PerfSession,
    sample_kind: Option<u16>,
}

impl<'a> ExportBuiltContext<'a> {
    fn new(
        exporter: &'a mut ExportMachine,
        session: &'a mut PerfSession) -> Self {
        Self {
            exporter,
            session,
            sample_kind: None,
        }
    }

    fn take_sample_kind(&mut self) -> Option<u16> { self.sample_kind.take() }

    pub fn exporter_mut(&mut self) -> &mut ExportMachine { self.exporter }

    pub fn session_mut(&mut self) -> &mut PerfSession { self.session }

    pub fn set_sample_kind(
        &mut self,
        kind: &str) {
        let kind = self.exporter.sample_kind(kind);

        self.sample_kind = Some(kind);
    }
}

pub struct ExportTraceContext<'a> {
    sampler: &'a mut ExportSampler,
    sample_kind: u16,
    full_data: &'a [u8],
    event_data: &'a [u8],
    format: &'a EventFormat,
}

impl<'a> ExportTraceContext<'a> {
    fn new(
        sampler: &'a mut ExportSampler,
        sample_kind: u16,
        full_data: &'a [u8],
        event_data: &'a [u8],
        format: &'a EventFormat) -> Self {
        Self {
            sampler,
            sample_kind,
            full_data,
            event_data,
            format,
        }
    }

    pub fn full_data(&self) -> &'a [u8] { self.full_data }

    pub fn event_data(&self) -> &'a [u8] { self.event_data }

    pub fn format(&self) -> &'a EventFormat { self.format }

    pub fn cpu(&self) -> u16 { self.sampler.cpu() }

    pub fn time(&self) -> anyhow::Result<u64> {
        self.sampler.time(self.full_data)
    }

    pub fn pid(&self) -> anyhow::Result<u32> {
        self.sampler.pid(self.full_data)
    }

    pub fn tid(&self) -> anyhow::Result<u32> {
        self.sampler.tid(self.full_data)
    }

    pub fn add_sample_with_kind(
        &mut self,
        value: u64,
        kind: u16) -> anyhow::Result<()> {
        self.sampler.add_sample(
            self.full_data,
            value,
            kind)
    }

    pub fn make_sample_with_kind(
        &mut self,
        value: u64,
        kind: u16) -> anyhow::Result<ExportProcessSample> {
        self.sampler.make_sample(
            self.full_data,
            value,
            kind)
    }

    pub fn make_sample(
        &mut self,
        value: u64) -> anyhow::Result<ExportProcessSample> {
        self.make_sample_with_kind(
            value,
            self.sample_kind)
    }

    pub fn add_custom_sample(
        &mut self,
        pid: u32,
        sample: ExportProcessSample) -> anyhow::Result<()> {
        self.sampler.add_custom_sample(
            pid,
            sample)
    }

    pub fn add_sample(
        &mut self,
        value: u64) -> anyhow::Result<()> {
        self.add_sample_with_kind(
            value,
            self.sample_kind)
    }
}

type BoxedBuiltCallback = Box<dyn FnMut(&mut ExportBuiltContext) -> anyhow::Result<()>>;
type BoxedTraceCallback = Box<dyn FnMut(&mut ExportTraceContext) -> anyhow::Result<()>>;

struct ExportEventCallback {
    event: Option<Event>,
    built: BoxedBuiltCallback,
    trace: BoxedTraceCallback,
}

impl ExportEventCallback {
    fn new(
        event: Event,
        built: impl FnMut(&mut ExportBuiltContext) -> anyhow::Result<()> + 'static,
        trace: impl FnMut(&mut ExportTraceContext) -> anyhow::Result<()> + 'static) -> Self {
        Self {
            event: Some(event),
            built: Box::new(built),
            trace: Box::new(trace),
        }
    }
}

pub struct ExportSettings {
    string_buckets: usize,
    callstack_buckets: usize,
    cpu_profiling: bool,
    cpu_freq: u64,
    process_fs: bool,
    cswitches: bool,
    events: Option<Vec<ExportEventCallback>>,
}

impl ExportSettings {
    pub fn new() -> Self {
        Self {
            string_buckets: 64,
            callstack_buckets: 512,
            cpu_profiling: true,
            cpu_freq: 1000,
            process_fs: true,
            cswitches: true,
            events: None,
        }
    }

    pub fn with_event(
        self,
        event: Event,
        built: impl FnMut(&mut ExportBuiltContext) -> anyhow::Result<()> + 'static,
        trace: impl FnMut(&mut ExportTraceContext) -> anyhow::Result<()> + 'static) -> Self {

        let mut clone = self;

        let callback = ExportEventCallback::new(
            event,
            built,
            trace);

        match clone.events.as_mut() {
            Some(events) => { events.push(callback); },
            None => { clone.events = Some(vec![callback]); }
        }

        clone
    }

    pub fn with_string_buckets(
        self,
        buckets: usize) -> Self {
        let mut clone = self;
        clone.string_buckets = buckets;
        clone
    }

    pub fn with_cpu_profile_freq(
        self,
        freq: u64) -> Self {
        let mut clone = self;
        clone.cpu_freq = freq;
        clone
    }

    pub fn with_callstack_buckets(
        self,
        buckets: usize) -> Self {
        let mut clone = self;
        clone.callstack_buckets = buckets;
        clone
    }

    pub fn without_cswitches(self) -> Self {
        let mut clone = self;
        clone.cswitches = false;
        clone
    }

    pub fn without_cpu_profiling(self) -> Self {
        let mut clone = self;
        clone.cpu_profiling = false;
        clone
    }

    pub fn without_process_fs(self) -> Self {
        let mut clone = self;
        clone.process_fs = false;
        clone
    }
}

pub struct ExportMachine {
    settings: ExportSettings,
    strings: InternedStrings,
    callstacks: InternedCallstacks,
    procs: HashMap<u32, ExportProcess>,
    cswitches: HashMap<u32, ExportCSwitch>,
    path_buf: Writable<PathBuf>,
    kinds: Vec<String>,
    map_index: usize,
}

pub type CommMap = HashMap<Option<usize>, Vec<u32>>;

impl ExportMachine {
    pub fn new(settings: ExportSettings) -> Self {
        let strings = InternedStrings::new(settings.string_buckets);
        let callstacks = InternedCallstacks::new(settings.callstack_buckets);

        Self {
            settings,
            strings,
            callstacks,
            procs: HashMap::new(),
            cswitches: HashMap::new(),
            path_buf: Writable::new(PathBuf::new()),
            kinds: Vec::new(),
            map_index: 0,
        }
    }

    pub fn sample_kinds(&self) -> &Vec<String> { &self.kinds }

    pub fn strings(&self) -> &InternedStrings { &self.strings }

    pub fn callstacks(&self) -> &InternedCallstacks { &self.callstacks }

    pub fn processes(&self) -> Values<u32, ExportProcess> { self.procs.values() }

    pub fn find_sample_kind(
        &self,
        target_kind: &str) -> Option<u16> {
        for (i, kind) in self.kinds.iter().enumerate() {
            if kind == target_kind {
                return Some(i as u16);
            }
        }

        None
    }

    pub fn find_process(
        &self,
        pid: u32) -> Option<&ExportProcess> {
        self.procs.get(&pid)
    }

    pub fn split_processes_by_comm(
        &self) -> CommMap {
        let mut map = CommMap::new();

        for (pid, process) in &self.procs {
            map.entry(process.comm_id())
               .and_modify(|e| { e.push(*pid) })
               .or_insert_with(|| { vec![*pid] });
        }

        map
    }

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

    pub fn resolve_perf_map_symbols(
        &mut self) {
        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        let mut path_buf = PathBuf::new();
        path_buf.push("tmp");

        for proc in self.procs.values_mut() {
            if !proc.has_anon_mappings() {
                continue;
            }

            path_buf.push(format!("perf-{}.map", proc.pid()));
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

    fn process_mut(
        &mut self,
        pid: u32) -> &mut ExportProcess {
        self.procs.entry(pid).or_insert_with(|| ExportProcess::new(pid))
    }

    pub(crate) fn add_mmap_exec(
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

    pub(crate) fn add_comm_exec(
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

    pub fn make_sample(
        &mut self,
        time: u64,
        value: u64,
        tid: u32,
        cpu: u16,
        kind: u16,
        frames: &[u64]) -> ExportProcessSample {
        let ip = frames[0];
        let callstack_id = self.callstacks.to_id(&frames[1..]);

        ExportProcessSample::new(
            time,
            value,
            cpu,
            kind,
            tid,
            ip,
            callstack_id)
    }

    pub fn add_sample(
        &mut self,
        time: u64,
        value: u64,
        pid: u32,
        tid: u32,
        cpu: u16,
        kind: u16,
        frames: &[u64]) -> anyhow::Result<()> {
        let sample = self.make_sample(
            time,
            value,
            tid,
            cpu,
            kind,
            frames);

        self.process_mut(pid).add_sample(sample);

        Ok(())
    }

    pub fn hook_to_session(
        mut self,
        session: &mut PerfSession,
        callstack_reader: CallstackReader) -> anyhow::Result<Writable<ExportMachine>> {
        let cpu_profiling = self.settings.cpu_profiling;
        let cswitches = self.settings.cswitches;
        let events = self.settings.events.take();

        let machine = Writable::new(self);

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
                event.add_callback(move |full_data, format, event_data| {
                    (callback.trace)(
                        &mut ExportTraceContext::new(
                            &mut event_sampler.borrow_mut(),
                            sample_kind,
                            full_data,
                            event_data,
                            format))
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

            event.add_callback(move |full_data,_fmt,_data| {
                let mut machine = event_machine.borrow_mut();
                let ancillary = ancillary.borrow();

                let cpu = ancillary.cpu() as u16;
                let time = time_field.get_u64(full_data)?;
                let pid = pid_field.get_u32(full_data)?;
                let tid = tid_field.get_u32(full_data)?;

                frames.clear();

                reader.read_frames(
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

            event.add_callback(move |full_data,_fmt,_data| {
                let mut machine = event_machine.borrow_mut();
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

            event.add_callback(move |full_data,_fmt,_data| {
                let mut machine = event_machine.borrow_mut();

                let misc = misc_field.get_u16(full_data)?;
                let time = time_field.get_u64(full_data)?;
                let pid = pid_field.get_u32(full_data)?;
                let tid = tid_field.get_u32(full_data)?;

                /* Ignore scheduler switches */
                if pid == 0 || tid == 0 {
                    return Ok(());
                }

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

        Ok(machine)
    }
}

pub trait ExportBuilderHelp {
    fn with_exporter_events(
        self,
        settings: &ExportSettings) -> Self;
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

        builder.with_kernel_events(kernel)
    }
}

pub trait ExportSessionHelp {
    fn build_exporter(
        &mut self,
        settings: ExportSettings,
        reader: CallstackReader) -> anyhow::Result<Writable<ExportMachine>>;
}

impl ExportSessionHelp for PerfSession {
    fn build_exporter(
        &mut self,
        settings: ExportSettings,
        reader: CallstackReader) -> anyhow::Result<Writable<ExportMachine>> {
        let exporter = ExportMachine::new(settings);

        exporter.hook_to_session(
            self,
            reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::os::linux::fs::MetadataExt;

    use crate::tracefs::TraceFS;
    use crate::helpers::callstack::{CallstackHelper, CallstackHelp};

    #[test]
    #[ignore]
    fn it_works() {
        let helper = CallstackHelper::new()
            .with_dwarf_unwinding();

        let mut settings = ExportSettings::new();

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
            .with_exporter_events(&settings)
            .with_callstack_help(&helper);

        let mut session = builder.build().unwrap();

        let exporter = session.build_exporter(
            settings,
            helper.to_reader()).unwrap();

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
}
