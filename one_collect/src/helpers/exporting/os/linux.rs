use super::*;
use std::collections::hash_map::{Entry};
use std::collections::hash_map::Entry::{Vacant, Occupied};
use std::path::Path;
use std::fs::File;

use crate::{ReadOnly, Writable};
use crate::event::DataFieldRef;

use crate::openat::DupFd;
use crate::perf_event::{AncillaryData, PerfSession};
use crate::perf_event::{RingBufSessionBuilder, RingBufBuilder};
use crate::perf_event::abi::PERF_RECORD_MISC_SWITCH_OUT;
use crate::helpers::callstack::{CallstackHelp, CallstackReader};

use ruwind::ModuleAccessor;
use self::symbols::PerfMapSymbolReader;

/* OS Specific Session Type */
pub type Session = PerfSession;

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
}

impl OSExportMachine {
    pub fn new() -> Self {
        Self {
            dev_nodes: ExportDevNodeLookup::new(),
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

impl ExportMachine {
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
        let path_buf = self.path_buf.clone();
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
            let data = data.event_data();

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
}
