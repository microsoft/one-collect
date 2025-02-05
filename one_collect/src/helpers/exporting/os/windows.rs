use std::collections::hash_map::Entry::Occupied;

use std::fs::File;

use crate::{ReadOnly, Writable};
use crate::etw::*;
use crate::helpers::exporting::*;
use crate::helpers::exporting::process::ExportProcessOSHooks;
use crate::helpers::exporting::universal::*;

/* OS Specific Session Type */
pub type Session = EtwSession;

/* OS Specific Session Builder Type */
pub type SessionBuilder = EtwSession;

trait PushWide {
    fn push_wide_str(
        &mut self,
        data: &[u8]);
}

impl PushWide for String {
    fn push_wide_str(
        &mut self,
        data: &[u8]) {
        for chunk in data.chunks_exact(2) {
            let val = u16::from_ne_bytes(
                chunk[..2].try_into().unwrap());

            if let Some(c) = char::from_u32(val as u32) {
                self.push(c);
            } else {
                self.push('?');
            }
        }
    }
}

pub(crate) struct OSExportSettings {
    /* Placeholder */
}

impl OSExportSettings {
    pub fn new() -> Self {
        Self {
        }
    }
}

#[derive(Clone)]
pub(crate) struct OSExportProcess {
    /* Placeholder */
}

impl OSExportProcess {
    pub fn new() -> Self {
        Self {
        }
    }
}

#[cfg(target_os = "windows")]
impl ExportProcessOSHooks for ExportProcess {
    fn os_open_file(
        &self,
        path: &Path) -> anyhow::Result<File> {
        let file = File::open(path)?;
        Ok(file)
    }
}

pub(crate) struct OSExportSampler {
    ancillary: ReadOnly<AncillaryData>,
}

impl OSExportSampler {
    pub(crate) fn new(
        session: &EtwSession) -> Self {
        Self {
            ancillary: session.ancillary_data(),
        }
    }
}

#[cfg(target_os = "windows")]
impl ExportSamplerOSHooks for ExportSampler {
    fn os_event_time(
        &self,
        _data: &EventData) -> anyhow::Result<u64> {
        Ok(self.os.ancillary.borrow().time())
    }

    fn os_event_pid(
        &self,
        _data: &EventData) -> anyhow::Result<u32> {
        let local_pid = self.os.ancillary.borrow().pid();

        /*
         * We need to convert from local to global PID.
         * This allows us to seamlessly handle when the
         * PID gets reused. We have global PIDs, that are
         * unique. And then we have local PIDs that likely
         * are not. The local PID is stored in the ns_pid
         * property of the ExportProcess like on Linux.
         */
        Ok(self.exporter
            .borrow_mut()
            .os
            .get_or_alloc_global_pid(local_pid))
    }

    fn os_event_tid(
        &self,
        _data: &EventData) -> anyhow::Result<u32> {
        Ok(self.os.ancillary.borrow().tid())
    }

    fn os_event_cpu(
        &self,
        _data: &EventData) -> anyhow::Result<u16> {
        Ok(self.os.ancillary.borrow().cpu() as u16)
    }

    fn os_event_callstack(
        &mut self,
        _data: &EventData) -> anyhow::Result<()> {
        let mut _match_id = 0u64;

        self.os.ancillary.borrow().callstack(
            &mut self.frames,
            &mut _match_id);

        Ok(())
    }
}

struct CpuProfile {
    cpu: u32,
    ip: u64,
}

impl CpuProfile {
    pub fn new(
        cpu: u32,
        ip: u64) -> Self {
        Self {
            cpu,
            ip,
        }
    }
}

#[derive(Eq, Hash, PartialEq)]
struct CpuProfileKey {
    time: u64,
    tid: u32,
}

impl CpuProfileKey {
    pub fn new(
        time: u64,
        tid: u32) -> Self {
        Self {
            time,
            tid,
        }
    }
}

#[derive(Default)]
struct WinCSwitch {
    cpu: u32,
    start_time: u64,
    end_time: u64,
}

pub(crate) struct OSExportMachine {
    cswitches: HashMap<u32, WinCSwitch>,
    pid_mapping: HashMap<u32, u32>,
    cpu_samples: Option<HashMap<CpuProfileKey, CpuProfile>>,
    pid_index: u32,
}

impl OSExportMachine {
    pub fn new() -> Self {
        Self {
            cswitches: HashMap::new(),
            pid_mapping: HashMap::new(),
            cpu_samples: Some(HashMap::new()),
            pid_index: 0,
        }
    }

    pub fn get_or_alloc_global_pid(
        &mut self,
        local_pid: u32) -> u32 {
        match self.get_global_pid(local_pid) {
            Some(global_pid) => { global_pid },
            None => { self.alloc_global_pid(local_pid) },
        }
    }

    pub fn get_global_pid(
        &self,
        local_pid: u32) -> Option<u32> {
        match self.pid_mapping.get(&local_pid) {
            Some(pid) => { Some(*pid) },
            None => { None },
        }
    }

    pub fn alloc_global_pid(
        &mut self,
        local_pid: u32) -> u32 {
        let global_pid = self.new_global_pid();

        *self.pid_mapping
            .entry(local_pid)
            .and_modify(|e| { *e = global_pid })
            .or_insert(global_pid)
    }

    pub fn new_global_pid(
        &mut self) -> u32 {
        let global_pid = self.pid_index;

        self.pid_index += 1;

        global_pid
    }

    fn sid_length(data: &[u8]) -> anyhow::Result<usize> {
        const PTR_SIZE: usize = std::mem::size_of::<usize>();
        let mut sid_size: usize = PTR_SIZE;

        if data.len() < 8 {
            anyhow::bail!("Invalid SID length");
        }

        let sid = u64::from_ne_bytes(data[..8].try_into()?);

        if sid != 0 {
            let offset = PTR_SIZE * 2;
            let start = offset + 1;

            if data.len() < start {
                anyhow::bail!("Invalid SID length");
            }

            let auth_count = data[start..][0] as usize;
            sid_size = offset + 8 + (auth_count * 4);
        }

        Ok(sid_size)
    }

    fn hook_mmap_event(
        ancillary: ReadOnly<AncillaryData>,
        event: &mut Event,
        event_machine: Writable<ExportMachine>) {
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("ProcessId");
        let addr = fmt.get_field_ref_unchecked("ImageBase");
        let len = fmt.get_field_ref_unchecked("ImageSize");
        let filename = fmt.get_field_ref_unchecked("FileName");

        let mut path_buf = String::new();

        event.add_callback(move |data| {
            let fmt = data.format();
            let data = data.event_data();

            let mut event_machine = event_machine.borrow_mut();

            let local_pid = fmt.get_u32(pid, data)?;
            let global_pid = event_machine.os.get_or_alloc_global_pid(local_pid);

            /*
             * Paths are logged in the global root namespace.
             * So we must use a path that can be used via
             * CreateFile vs NtOpenFile. Insert the GlobalRoot
             * in front of the path to ensure this can happen.
             * This way std::fs::File::open() will work.
             */
            path_buf.clear();
            path_buf.push_str("\\\\?\\GlobalRoot");
            path_buf.push_wide_str(fmt.get_data(filename, data));

            /* Use the interned ID as the inode for uniqueness */
            let inode = event_machine.intern(&path_buf);

            event_machine.add_mmap_exec(
                ancillary.borrow().time(),
                global_pid,
                fmt.get_u64(addr, data)?,
                fmt.get_u64(len, data)?,
                0, /* Pgoffset */
                0, /* Device Maj */
                0, /* Device Min */
                inode as u64,
                &path_buf)
        });
    }

    fn hook_comm_event(
        ancillary: ReadOnly<AncillaryData>,
        event: &mut Event,
        event_machine: Writable<ExportMachine>) {
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("ProcessId");
        let sid = fmt.get_field_ref_unchecked("UserSID");
        let comm = fmt.get_field_ref_unchecked("ImageFileName");

        event.add_callback(move |data| {
            let fmt = data.format();
            let data = data.event_data();
            let sid = fmt.get_field_unchecked(sid);

            let mut event_machine = event_machine.borrow_mut();

            let local_pid = fmt.get_u32(pid, data)?;
            let global_pid = event_machine.os.alloc_global_pid(local_pid);

            let dynamic = &data[sid.offset..];
            let sid_length = Self::sid_length(dynamic)?;
            let dynamic = &dynamic[sid_length..];

            /*
             * Processes within the machine are stored using the
             * global PID. This allows us to handle PID re-use
             * cases easily. It also ensures we can handle container
             * scenarios on Windows in the future. The Global PID
             * namespace is 32-bit still, as on Linux.
             */
            event_machine.add_comm_exec(
                global_pid,
                fmt.get_str(comm, dynamic)?,
                ancillary.borrow().time())?;

            /* Store the local PID in the ns_pid as on Linux */
            *event_machine.process_mut(global_pid).ns_pid_mut() = Some(local_pid);

            Ok(())
        });
    }

    fn hook_to_etw_session(
        mut machine: ExportMachine,
        session: &mut EtwSession) -> anyhow::Result<Writable<ExportMachine>> {
        let cpu_profiling = machine.settings.cpu_profiling;
        let cswitches = machine.settings.cswitches;
        let events = machine.settings.events.take();

        let callstack_reader = match machine.settings.callstack_helper.take() {
            Some(callstack_helper) => { callstack_helper.to_reader() },
            None => { anyhow::bail!("No callstack reader specified."); }
        };

        let machine = Writable::new(machine);

        if let Some(events) = events {
            let shared_sampler = Writable::new(
                ExportSampler::new(
                    &machine,
                    OSExportSampler::new(session)));

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

                let options = match event.has_no_callstack_flag() {
                    true => {
                        /* No callstack flag is enabled */
                        None
                    },
                    false => {
                        /* Event requires callstacks */
                        Some(PROPERTY_STACK_TRACE)
                    },
                };

                /* Add event to session */
                session.add_event(event, options);
            }
        }

        if cpu_profiling {
            let ancillary = session.ancillary_data();

            /* Hookup sample CPU profile event */
            let event = session.profile_cpu_event(Some(PROPERTY_STACK_TRACE));

            let fmt = event.format();
            let ip = fmt.get_field_ref_unchecked("InstructionPointer");
            let tid = fmt.get_field_ref_unchecked("ThreadId");
            let count = fmt.get_field_ref_unchecked("Count");

            let event_machine = machine.clone();
            let event_ancillary = ancillary.clone();

            event.add_callback(move |data| {
                let fmt = data.format();
                let data = data.event_data();

                let mut event_machine = event_machine.borrow_mut();
                let ancillary = event_ancillary.borrow();

                let ip = fmt.get_u64(ip, data)?;
                let tid = fmt.get_u32(tid, data)?;
                let count = fmt.get_u32(count, data)?;

                if tid == 0 && count == 1 {
                    /* Don't expect a callstack from idle thread */
                    return Ok(());
                }

                let key = CpuProfileKey::new(
                    ancillary.time(),
                    tid);

                let value = CpuProfile::new(
                    ancillary.cpu(),
                    ip);

                /* Save the CPU profile for async frames */
                if let Some(samples) = event_machine.os.cpu_samples.as_mut() {
                    samples.insert(key, value);
                }

                Ok(())
            });

            let event_machine = machine.clone();
            let kind = machine.borrow_mut().sample_kind("cpu");

            callstack_reader.add_async_frames_callback(
                move |callstack| {
                    let mut event_machine = event_machine.borrow_mut();

                    /* Lookup matching sample */
                    let key = CpuProfileKey::new(
                        callstack.time(),
                        callstack.tid());

                    if let Some(samples) = event_machine.os.cpu_samples.as_mut() {
                        if let Occupied(entry) = samples.entry(key) {
                            /* Remove sample */
                            let (key, value) = entry.remove_entry();

                            let local_pid = callstack.pid();
                            let global_pid = event_machine.os.get_or_alloc_global_pid(local_pid);

                            /* Add sample to the process */
                            let _ = event_machine.add_sample(
                                key.time,
                                1,
                                global_pid,
                                key.tid,
                                value.cpu as u16,
                                kind,
                                callstack.frames());
                        }
                    }
                });

            let event_machine = machine.clone();

            callstack_reader.add_flushed_callback(
                move || {
                    let mut event_machine = event_machine.borrow_mut();

                    /* Take remaining samples */
                    let samples = event_machine.os.cpu_samples.take();

                    /*
                     * Add remaining samples as single frame stacks. This
                     * typically means the callstack was never able to be
                     * read. This can be due to paging on X64 or internal
                     * timeouts or errors within the kernel for async user
                     * unwinding. Even on errors, we want an accurate
                     * picture of the machine activity, so we still need
                     * to add these, even if we don't have the full stack
                     * or the process ID.
                     */
                    if let Some(mut samples) = samples {
                        let mut frames: [u64; 1] = [0; 1];

                        /* Put these in an Unknown process */
                        let global_pid = event_machine.os.new_global_pid();

                        let _ = event_machine.add_comm_exec(
                            global_pid,
                            "Unknown",
                            0);

                        for (key, value) in samples.drain() {
                            /* Update single frame array */
                            frames[0] = value.ip;

                            /* Add sample to the process */
                            let _ = event_machine.add_sample(
                                key.time,
                                1,
                                global_pid,
                                key.tid,
                                value.cpu as u16,
                                kind,
                                &frames);
                        }
                    }
                });
        }

        if cswitches {
            /* Get sample kind for cswitch */
            let kind = machine.borrow_mut().sample_kind("cswitch");

            let ancillary = session.ancillary_data();

            let cswitch_event = session.cswitch_event(Some(PROPERTY_STACK_TRACE));
            let fmt = cswitch_event.format();
            let new_tid = fmt.get_field_ref_unchecked("NewThreadId");
            let old_tid = fmt.get_field_ref_unchecked("OldThreadId");

            /* ETW callstacks come via its own event, link them to cswitches */
            let event_machine = machine.clone();

            callstack_reader.add_async_frames_callback(move |callstack| {
                let mut machine = event_machine.borrow_mut();

                let tid = callstack.tid();

                let info = match machine.os.cswitches.entry(tid) {
                    Occupied(entry) => {
                        let info = entry.get();

                        /* Time must match to ensure correct stack */
                        if info.end_time == callstack.time() {
                            Some(entry.remove())
                        } else {
                            None
                        }
                    },
                    _ => { None },
                };

                if let Some(info) = info {
                    let local_pid = callstack.pid();
                    let global_pid = machine.os.get_or_alloc_global_pid(local_pid);

                    if info.end_time > info.start_time {
                        let duration = info.end_time - info.start_time;

                        let sample = machine.make_sample(
                            info.start_time,
                            duration,
                            tid,
                            info.cpu as u16,
                            kind,
                            callstack.frames());

                        machine.process_mut(global_pid).add_sample(sample);
                    }
                }
            });

            /* Handle actual cswitch event */
            let event_machine = machine.clone();
            let event_ancillary = ancillary.clone();

            cswitch_event.add_callback(move |data| {
                let fmt = data.format();
                let data = data.event_data();

                let new_tid = fmt.get_u32(new_tid, data)?;
                let old_tid = fmt.get_u32(old_tid, data)?;

                let mut machine = event_machine.borrow_mut();
                let ancillary = event_ancillary.borrow();

                /* Ignore swapping to idle thread */
                if new_tid != 0 {
                    /* Mark when thread got running again only if we have data for it */
                    if let Occupied(mut entry) = machine.os.cswitches.entry(new_tid) {
                        entry.get_mut().end_time = ancillary.time();
                    }
                }

                /* Ignore swapping from idle thread */
                if old_tid != 0 {
                    /* Mark when thread got interrupted and on what CPU */
                    let info = machine.os.cswitches.entry(old_tid).or_default();

                    info.cpu = ancillary.cpu();
                    info.start_time = ancillary.time();
                    info.end_time = 0;
                }

                Ok(())
            });
        }

        /* Hook mmap records */
        Self::hook_mmap_event(
            session.ancillary_data(),
            session.mmap_load_event(),
            machine.clone());

        Self::hook_mmap_event(
            session.ancillary_data(),
            session.mmap_load_capture_start_event(),
            machine.clone());

        /* Hook comm exec records */
        Self::hook_comm_event(
            session.ancillary_data(),
            session.comm_start_event(),
            machine.clone());

        Self::hook_comm_event(
            session.ancillary_data(),
            session.comm_start_capture_event(),
            machine.clone());

        /* Hook comm exit record */
        let event_ancillary = session.ancillary_data();
        let event_machine = machine.clone();
        let event = session.comm_end_event();
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("ProcessId");

        event.add_callback(move |data| {
            let fmt = data.format();
            let data = data.event_data();

            let mut machine = event_machine.borrow_mut();
            let ancillary = event_ancillary.borrow();

            let local_pid = fmt.get_u32(pid, data)?;
            let global_pid = machine.os.get_or_alloc_global_pid(local_pid);

            machine.add_comm_exit(
                global_pid,
                ancillary.time())
        });

        Ok(machine)
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn QueryPerformanceCounter(
        time: *mut u64) -> u32;

    fn QueryPerformanceFrequency(
        freq: *mut u64) -> u32;

    fn GetActiveProcessorCount(
        group: u16) -> u32;
}

#[cfg(target_os = "windows")]
impl ExportMachineOSHooks for ExportMachine {
    fn os_add_kernel_mappings_with(
        &mut self,
        kernel_symbols: &mut impl ExportSymbolReader) {
        let mut frames = Vec::new();
        let mut addrs = HashSet::new();

        /* Take mappings from Idle process */
        let kernel_mappings: Vec<ExportMapping> = self
            .process_mut(0)
            .mappings_mut()
            .drain(..)
            .collect();

        for proc in self.procs.values_mut() {
            proc.get_unique_kernel_ips(
                &mut addrs,
                &mut frames,
                &self.callstacks);

            if addrs.is_empty() {
                continue;
            }

            /* Copy unique addresses to a Vec */
            frames.clear();

            for addr in &addrs {
                frames.push(*addr);
            }

            /* Find the correct mappings */
            for mapping in &kernel_mappings {
                for addr in &addrs {
                    /* Mapping is used in process */
                    if mapping.contains_ip(*addr) {
                        /* Copy mapping for process */
                        let mut mapping = mapping.clone();

                        /* Resolve symbols */
                        mapping.add_matching_symbols(
                            &mut frames,
                            kernel_symbols,
                            &mut self.strings);

                        /* Add resolved mapping to process */
                        proc.add_mapping(mapping);

                        /* Next mapping */
                        break;
                    }
                }
            }
        }
    }

    fn os_capture_file_symbol_metadata(&mut self) {
        self.load_pe_metadata();
    }

    fn os_resolve_local_file_symbols(&mut self) {
        /* TODO */
    }

    fn os_resolve_local_anon_symbols(&mut self) {
        /* TODO */
    }

    fn os_add_mmap_exec(
        &mut self,
        _pid: u32,
        _mapping: &mut ExportMapping,
        _filename: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn os_add_comm_exec(
        &mut self,
        _pid: u32,
        _comm: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn os_qpc_time(&self) -> u64 {
        let mut t = 0u64;

        unsafe {
            QueryPerformanceCounter(&mut t);
        }

        t
    }

    fn os_qpc_freq(&self) -> u64 {
        let mut t = 0u64;

        unsafe {
            QueryPerformanceFrequency(&mut t);
        }

        t
    }

    fn os_cpu_count(&self) -> u32 {
        unsafe {
            GetActiveProcessorCount(0xFFFF)
        }
    }
}

impl ExportSessionHelp for EtwSession {
    fn build_exporter(
        &mut self,
        settings: ExportSettings) -> anyhow::Result<Writable<ExportMachine>> {
        OSExportMachine::hook_to_etw_session(
            ExportMachine::new(settings),
            self)
    }
}

#[cfg(target_os = "windows")]
impl UniversalExporterOSHooks for UniversalExporter {
    fn os_parse_until(
        mut self,
        name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>> {
        use crate::helpers::callstack::*;

        let settings = self.settings()?;

        let callstack_helper = match settings.callstack_helper.as_ref() {
            Some(helper) => { helper },
            None => { anyhow::bail!("CallstackHelper is not set."); },
        };

        let mut session = EtwSession::new()
            .with_per_cpu_buffer_bytes(self.cpu_buf_bytes())
            .with_callstack_help(&callstack_helper);

        session = self.run_build_hooks(session)?;

        let exporter = session.build_exporter(settings)?;

        session.capture_environment();

        exporter.borrow_mut().mark_start();
        session.parse_until(name, until)?;
        exporter.borrow_mut().mark_end();

        self.run_parsed_hooks(&exporter)?;

        Ok(exporter)
    }
}

pub(crate) fn default_export_settings() -> ExportSettings {
    let helper = CallstackHelper::new();

    ExportSettings::new(helper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::callstack::CallstackHelp;

    #[test]
    #[ignore]
    fn it_works() {
        let helper = CallstackHelper::new();

        let mut session = EtwSession::new()
            .with_callstack_help(&helper);

        let settings = ExportSettings::new(helper)
            .with_cpu_profiling(1000)
            .with_cswitches();

        let exporter = session.build_exporter(settings).unwrap();

        let duration = std::time::Duration::from_secs(1);

        session.parse_for_duration(
            "one_collect_export_self_test",
            duration).unwrap();

        let exporter = exporter.borrow();

        let strings = exporter.strings();

        for process in exporter.processes() {
            let mut comm = "Unknown";

            if let Some(comm_id) = process.comm_id() {
                if let Ok(value) = strings.from_id(comm_id) {
                    comm = value;
                }
            }

            println!("{:?} ({}, Root PID: {}):", process.ns_pid(), comm, process.pid());

            for mapping in process.mappings() {
                let filename = match strings.from_id(mapping.filename_id()) {
                    Ok(name) => { name },
                    Err(_) => { "Unknown" },
                };

                println!(
                    "0x{:x} - 0x{:x}: {}",
                    mapping.start(),
                    mapping.end(),
                    filename);
            }

            for sample in process.samples() {
                println!(
                    "{}: CPU={}, TID={}, IP={}, STACK_ID={}, KIND={}",
                    sample.time(),
                    sample.cpu(),
                    sample.tid(),
                    sample.ip(),
                    sample.callstack_id(),
                    sample.kind());
            }

            println!();
        }
    }

    #[test]
    fn os_export_machine() {
        let mut machine = OSExportMachine::new();
        assert!(machine.get_global_pid(1).is_none());

        /* Allocating PID should work */
        let global_pid = machine.alloc_global_pid(1);
        assert_eq!(global_pid, machine.get_global_pid(1).unwrap());
        assert_eq!(global_pid, machine.get_or_alloc_global_pid(1));

        /* Allocating inplace should be different */
        let new_global_pid = machine.alloc_global_pid(1);
        assert_ne!(global_pid, new_global_pid);
        assert_eq!(new_global_pid, machine.get_global_pid(1).unwrap());
        assert_eq!(new_global_pid, machine.get_or_alloc_global_pid(1));

        let global_pid = new_global_pid;

        /* Allocating another should be different */
        let new_global_pid = machine.alloc_global_pid(2);
        assert_ne!(global_pid, new_global_pid);
        assert_eq!(new_global_pid, machine.get_global_pid(2).unwrap());
        assert_eq!(new_global_pid, machine.get_or_alloc_global_pid(2));
    }
}
