use std::collections::{HashMap, HashSet};
use std::collections::hash_map::{Values, ValuesMut};
use std::time::Duration;
use std::path::Path;

use crate::Writable;
use crate::event::{Event, EventData};
use crate::intern::{InternedStrings, InternedCallstacks};

use crate::helpers::callstack::CallstackHelper;

use modulemetadata::ModuleMetadata;
use pe_file::PEModuleMetadata;
use process::MetricValue;
use ruwind::UnwindType;
use chrono::{DateTime, Utc};

mod lookup;

pub mod os;
use os::OSExportMachine;
use os::OSExportSampler;
use os::OSExportSettings;

/* Make it easy for callers to use public OS extensions */
#[cfg(target_os = "linux")]
pub use os::linux::ExportSettingsLinuxExt;

pub const KERNEL_START:u64 = 0xFFFF800000000000;
pub const KERNEL_END:u64 = 0xFFFFFFFFFFFFFFFF;

pub type ExportDevNode = ruwind::ModuleKey;

pub mod graph;
pub mod formats;
pub mod modulemetadata;
pub mod pe_file;

pub mod universal;
use modulemetadata::ModuleMetadataLookup;

pub use universal::{
    UniversalExporter,
};

pub mod symbols;
pub use symbols::{
    ExportSymbolReader,
    KernelSymbolReader,
    ExportSymbol,
    DynamicSymbol,
};

pub mod process;
pub use process::{
    ExportProcess,
    ExportProcessSample,
    ExportProcessReplay,
};

pub mod mappings;
pub use mappings::{
    ExportMapping,
};

#[derive(Default)]
struct ExportCSwitch {
    start_time: u64,
    sample: Option<ExportProcessSample>,
}

struct ExportSampler {
    exporter: Writable<ExportMachine>,
    frames: Vec<u64>,
    os: OSExportSampler,
}

pub trait ExportSamplerOSHooks {
    fn os_event_callstack(
        &mut self,
        data: &EventData) -> anyhow::Result<()>;

    fn os_event_time(
        &self,
        data: &EventData) -> anyhow::Result<u64>;

    fn os_event_pid(
        &self,
        data: &EventData) -> anyhow::Result<u32>;

    fn os_event_tid(
        &self,
        data: &EventData) -> anyhow::Result<u32>;

    fn os_event_cpu(
        &self,
        data: &EventData) -> anyhow::Result<u16>;
}

impl ExportSampler {
    fn new(
        exporter: &Writable<ExportMachine>,
        os: OSExportSampler) -> Self {
        Self {
            exporter: exporter.clone(),
            os,
            frames: Vec::new(),
        }
    }

    fn make_sample(
        &mut self,
        data: &EventData,
        value: MetricValue,
        kind: u16) -> anyhow::Result<ExportProcessSample> {
        self.frames.clear();

        /* OS Specific callstack hook */
        self.os_event_callstack(data)?;

        Ok(self.exporter.borrow_mut().make_sample(
            self.os_event_time(data)?,
            value,
            self.os_event_tid(data)?,
            self.os_event_cpu(data)?,
            kind,
            &self.frames))
    }

    fn add_custom_sample(
        &mut self,
        pid: u32,
        sample: ExportProcessSample) -> anyhow::Result<()> {
        self.exporter.borrow_mut().add_custom_sample(pid, sample)
    }

    fn add_sample(
        &mut self,
        data: &EventData,
        value: MetricValue,
        kind: u16) -> anyhow::Result<()> {
        self.frames.clear();

        /* OS Specific callstack hook */
        self.os_event_callstack(data)?;

        self.exporter.borrow_mut().add_sample(
            self.os_event_time(data)?,
            value,
            self.os_event_pid(data)?,
            self.os_event_tid(data)?,
            self.os_event_cpu(data)?,
            kind,
            &self.frames)
    }
}

pub struct ExportBuiltContext<'a> {
    exporter: &'a mut ExportMachine,
    session: &'a mut os::Session,
    sample_kind: Option<u16>,
}

impl<'a> ExportBuiltContext<'a> {
    fn new(
        exporter: &'a mut ExportMachine,
        session: &'a mut os::Session) -> Self {
        Self {
            exporter,
            session,
            sample_kind: None,
        }
    }

    fn take_sample_kind(&mut self) -> Option<u16> { self.sample_kind.take() }

    pub fn exporter_mut(&mut self) -> &mut ExportMachine { self.exporter }

    pub fn session_mut(&mut self) -> &mut os::Session { self.session }

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
    data: &'a EventData<'a>,
}

impl<'a> ExportTraceContext<'a> {
    fn new(
        sampler: &'a mut ExportSampler,
        sample_kind: u16,
        data: &'a EventData) -> Self {
        Self {
            sampler,
            sample_kind,
            data,
        }
    }

    pub fn data(&self) -> &'a EventData { self.data }

    pub fn cpu(&self) -> anyhow::Result<u16> {
        self.sampler.os_event_cpu(self.data)
    }

    pub fn time(&self) -> anyhow::Result<u64> {
        self.sampler.os_event_time(self.data)
    }

    pub fn pid(&self) -> anyhow::Result<u32> {
        self.sampler.os_event_pid(self.data)
    }

    pub fn tid(&self) -> anyhow::Result<u32> {
        self.sampler.os_event_tid(self.data)
    }

    pub fn add_sample_with_kind(
        &mut self,
        value: MetricValue,
        kind: u16) -> anyhow::Result<()> {
        self.sampler.add_sample(
            self.data,
            value,
            kind)
    }

    pub fn make_sample_with_kind(
        &mut self,
        value: MetricValue,
        kind: u16) -> anyhow::Result<ExportProcessSample> {
        self.sampler.make_sample(
            self.data,
            value,
            kind)
    }

    pub fn make_sample(
        &mut self,
        value: MetricValue) -> anyhow::Result<ExportProcessSample> {
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
        value: MetricValue) -> anyhow::Result<()> {
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
    cswitches: bool,
    unwinder: bool,
    callstack_helper: Option<CallstackHelper>,
    os: OSExportSettings,
    events: Option<Vec<ExportEventCallback>>,
    target_pids: Option<Vec<i32>>,
}

impl Default for ExportSettings {
    fn default() -> Self {
        os::default_export_settings()
    }
}

impl ExportSettings {
    #[allow(unused_mut)]
    pub fn new(mut callstack_helper: CallstackHelper) -> Self {
        let unwinder = callstack_helper.has_unwinder();

        Self {
            string_buckets: 64,
            callstack_buckets: 512,
            cpu_profiling: false,
            cpu_freq: 1000,
            cswitches: false,
            callstack_helper: Some(callstack_helper.with_external_lookup()),
            unwinder,
            os: OSExportSettings::new(),
            events: None,
            target_pids: None,
        }
    }

    pub fn has_unwinder(&self) -> bool { self.unwinder }

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

    pub fn with_cpu_profiling(
        self,
        freq: u64) -> Self {
        let mut clone = self;
        clone.cpu_profiling = true;
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

    pub fn with_cswitches(self) -> Self {
        let mut clone = self;
        clone.cswitches = true;
        clone
    }

    pub fn with_target_pid(
        self,
        pid: i32) -> Self {
        let mut clone = self;

        match clone.target_pids.as_mut() {
            Some(pids) => { pids.push(pid); },
            None => { clone.target_pids = Some(vec![pid]); }
        }

        clone
    }
    pub fn cpu_freq(&self) -> u64 { self.cpu_freq }
}

pub struct ExportMachine {
    settings: ExportSettings,
    strings: InternedStrings,
    callstacks: InternedCallstacks,
    pub(crate) os: OSExportMachine,
    procs: HashMap<u32, ExportProcess>,
    module_metadata: ModuleMetadataLookup,
    kinds: Vec<String>,
    map_index: usize,
    drop_closures: Vec<Box<dyn FnMut()>>,
    start_date: Option<DateTime<Utc>>,
    start_qpc: Option<u64>,
    end_qpc: Option<u64>,
    duration: Option<Duration>,
}

pub trait ExportMachineSessionHooks {
    fn hook_export_machine(
        &mut self) -> anyhow::Result<Writable<ExportMachine>>;
}

pub trait ExportMachineOSHooks {
    fn os_add_kernel_mappings_with(
        &mut self,
        kernel_symbols: &mut impl ExportSymbolReader);

    fn os_capture_file_symbol_metadata(&mut self);

    fn os_resolve_local_file_symbols(&mut self);

    fn os_resolve_local_anon_symbols(&mut self);

    fn os_add_mmap_exec(
        &mut self,
        pid: u32,
        mapping: &mut ExportMapping,
        filename: &str) -> anyhow::Result<()>;

    fn os_add_comm_exec(
        &mut self,
        pid: u32,
        comm: &str) -> anyhow::Result<()>;

    fn os_add_dynamic_symbol(
        &mut self,
        symbol: &DynamicSymbol) -> anyhow::Result<()>;

    fn os_qpc_time(&self) -> u64;

    fn os_qpc_freq(&self) -> u64;

    fn os_cpu_count(&self) -> u32;
}

pub type CommMap = HashMap<Option<usize>, Vec<u32>>;

const NO_FRAMES: [u64; 1] = [0; 1];

impl ExportMachine {
    pub fn new(settings: ExportSettings) -> Self {
        let strings = InternedStrings::new(settings.string_buckets);
        let callstacks = InternedCallstacks::new(settings.callstack_buckets);

        Self {
            settings,
            strings,
            callstacks,
            os: OSExportMachine::new(),
            procs: HashMap::new(),
            module_metadata: ModuleMetadataLookup::new(),
            kinds: Vec::new(),
            map_index: 0,
            drop_closures: Vec::new(),
            start_date: None,
            start_qpc: None,
            end_qpc: None,
            duration: None,
        }
    }

    pub fn start_date(&self) -> Option<DateTime<Utc>> { self.start_date }

    pub fn start_qpc(&self) -> Option<u64> { self.start_qpc }

    pub fn end_qpc(&self) -> Option<u64> { self.end_qpc }

    pub fn duration(&self) -> Option<Duration> { self.duration }

    pub fn settings(&self) -> &ExportSettings { &self.settings }

    pub fn qpc_freq(&self) -> u64 { self.os_qpc_freq() }

    pub fn cpu_count(&self) -> u32 { self.os_cpu_count() }

    pub fn get_mapping_metadata(
        &self,
        mapping: &ExportMapping) -> Option<&ModuleMetadata> {
        match mapping.node() {
            Some(node) => { self.module_metadata.get(node) },
            None => { None }
        }
    }

    pub fn replay_by_time(
        &mut self,
        predicate: impl Fn(&ExportProcess) -> bool,
        mut callback: impl FnMut(&ExportMachine, &ExportProcessReplay) -> anyhow::Result<()>) -> anyhow::Result<()> {
        let mut replay_procs = Vec::new();

        /* Need to do sorting as mut */
        for process in self.processes_mut() {
            if !predicate(process) {
                continue;
            }

            /* Sort */
            process.sort_samples_by_time();
            process.sort_mappings_by_time();
        }

        /* Replays are immutable refs */
        for process in self.processes() {
            if !predicate(process) {
                continue;
            }

            /* Allocate details for replaying */
            replay_procs.push(process.to_replay());
        }

        loop {
            let mut earliest = u64::MAX;

            /* Find earliest */
            for replay in &replay_procs {
                if replay.done() {
                    continue;
                }

                let time = replay.time();

                if time < earliest {
                    earliest = time;
                }
            }

            /* No more */
            if earliest == u64::MAX {
                break;
            }

            /* Emit and advance */
            for replay in &mut replay_procs {
                if replay.done() {
                    continue;
                }

                if replay.time() == earliest {
                    (callback)(&self, replay)?;

                    replay.advance();
                }
            }
        }

        Ok(())
    }

    pub fn mark_start(&mut self) {
        self.mark_start_direct(
            Utc::now(),
            self.os_qpc_time());
    }

    pub fn mark_start_direct(
        &mut self,
        start_date: DateTime<Utc>,
        start_qpc: u64) {
        self.start_date = Some(start_date);
        self.start_qpc = Some(start_qpc);
    }

    pub fn mark_end(&mut self) {
        if let Some(start_qpc) = self.start_qpc {
            let end_qpc = self.os_qpc_time();
            let qpc_freq = self.os_qpc_freq();

            let qpc_duration = end_qpc - start_qpc;
            let micros = (qpc_duration * 1000000u64) / qpc_freq;

            self.end_qpc = Some(end_qpc);
            self.duration = Some(Duration::from_micros(micros));
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

    pub fn add_kernel_mappings_with(
        &mut self,
        kernel_symbols: &mut impl ExportSymbolReader) {
        self.os_add_kernel_mappings_with(kernel_symbols)
    }

    pub fn add_kernel_mappings(
        &mut self) {
        let mut kernel_symbols = KernelSymbolReader::new();

        self.add_kernel_mappings_with(&mut kernel_symbols);
    }

    pub fn add_dynamic_symbol(
        &mut self,
        symbol: &DynamicSymbol) -> anyhow::Result<()> {
        self.os_add_dynamic_symbol(symbol)
    }

    pub fn capture_file_symbol_metadata(&mut self) {
        self.os_capture_file_symbol_metadata();
    }

    pub fn resolve_local_file_symbols(&mut self) {
        self.os_resolve_local_file_symbols();
    }


    pub fn resolve_local_anon_symbols(&mut self) {
        /* Dynamic symbols need to be mapped before resolving */
        for proc in self.procs.values_mut() {
            proc.add_dynamic_symbol_mappings(&mut self.map_index);
        }

        self.os_resolve_local_anon_symbols();
    }

    pub fn capture_and_resolve_symbols(&mut self) {
        self.capture_file_symbol_metadata();
        self.add_kernel_mappings();
        self.resolve_local_file_symbols();
        self.resolve_local_anon_symbols();
    }

    fn process_mut(
        &mut self,
        pid: u32) -> &mut ExportProcess {
        self.procs.entry(pid).or_insert_with(|| ExportProcess::new(pid))
    }

    pub fn add_mmap_exec(
        &mut self,
        time: u64,
        pid: u32,
        addr: u64,
        len: u64,
        pgoffset: u64,
        maj: u32,
        min: u32,
        ino: u64,
        filename: &str) -> anyhow::Result<()> {
        let anon = filename.is_empty() ||
            filename.starts_with('[') ||
            filename.starts_with("/memfd:") ||
            filename.starts_with("//anon");

        let unwind_type =
            if anon || filename.ends_with(".dll") || filename.ends_with(".exe") {
                UnwindType::Prolog
            } else {
                UnwindType::DWARF
            };

        let mut mapping = ExportMapping::new(
            time,
            self.intern(filename),
            addr,
            addr + len - 1,
            pgoffset,
            anon,
            self.map_index,
            unwind_type);

        if !anon {
            let node = ExportDevNode::from_parts(maj, min, ino);

            mapping.set_node(node);
        }

        self.os_add_mmap_exec(
            pid,
            &mut mapping,
            filename)?;

        self.map_index += 1;

        self.process_mut(pid).add_mapping(mapping);

        Ok(())
    }

    pub fn add_comm_exec(
        &mut self,
        pid: u32,
        comm: &str,
        time_qpc: u64) -> anyhow::Result<()> {
        let comm_id = self.intern(comm);

        let proc = self.process_mut(pid);

        proc.set_comm_id(comm_id);
        proc.set_create_time_qpc(time_qpc);

        self.os_add_comm_exec(
            pid,
            comm)
    }

    pub fn add_comm_exit(
        &mut self,
        pid: u32,
        time_qpc: u64) -> anyhow::Result<()> {
        self.process_mut(pid).set_exit_time_qpc(time_qpc);

        Ok(())
    }

    pub fn make_sample(
        &mut self,
        time: u64,
        value: MetricValue,
        tid: u32,
        cpu: u16,
        kind: u16,
        frames: &[u64]) -> ExportProcessSample {
        let mut frames = frames;

        if frames.is_empty() {
            frames = &NO_FRAMES;
        }

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
        value: MetricValue,
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

    pub fn add_custom_sample(
        &mut self,
        pid: u32,
        sample: ExportProcessSample) -> anyhow::Result<()> {
        self.process_mut(pid).add_sample(sample);

        Ok(())
    }

    pub fn load_pe_metadata(
        &mut self) {
        for proc in self.procs.values() {
            for map in proc.mappings() {
                if let Some(key) = map.node() {

                    // Handle each binary exactly once, regardless of of it's loaded into multiple processes.
                    if self.module_metadata.contains(key) {
                        continue;
                    }

                    // Skip anonymous mappings.
                    if map.anon() {
                        continue;
                    }

                    if let Ok(filename) = self.strings.from_id(map.filename_id()) {
                        if filename.ends_with(".dll") || filename.ends_with(".exe") {
                            if let ModuleMetadata::PE(pe_metadata) = self.module_metadata.entry(*key)
                                .or_insert(ModuleMetadata::PE(PEModuleMetadata::new())) {

                                if let Ok(file) = proc.open_file(Path::new(filename)) {
                                    // Ignore failures for now, but ideally, we log these failures.
                                    let _ = pe_metadata.get_metadata_direct(file, &mut self.strings);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn add_drop_closure(
        &mut self,
        closure: impl FnMut() + 'static) {
        self.drop_closures.push(Box::new(closure));
    }
}

impl Drop for ExportMachine {
    fn drop(&mut self) {
        for closure in &mut self.drop_closures {
            closure();
        }
    }
}

pub trait ExportBuilderHelp {
    fn with_exporter_events(
        self,
        settings: &ExportSettings) -> Self;
}

pub trait ExportSessionHelp {
    fn build_exporter(
        &mut self,
        settings: ExportSettings) -> anyhow::Result<Writable<ExportMachine>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_by_time() {
        let mut machine = ExportMachine::new(ExportSettings::default());
        let proc = machine.process_mut(1);

        let first = ExportProcessSample::new(1, MetricValue::Count(0), 0, 0, 0, 0, 0);
        let second = ExportProcessSample::new(3, MetricValue::Count(0), 0, 0, 0, 0, 0);
        let third = ExportProcessSample::new(5, MetricValue::Count(0), 0, 0, 0, 0, 0);
        let forth = ExportProcessSample::new(7, MetricValue::Count(0), 0, 0, 0, 0, 0);

        proc.add_sample(forth);
        proc.add_sample(second);
        proc.add_sample(first);
        proc.add_sample(third);

        let proc = machine.process_mut(2);

        let first = ExportProcessSample::new(2, MetricValue::Count(0), 0, 0, 0, 0, 0);
        let second = ExportProcessSample::new(4, MetricValue::Count(0), 0, 0, 0, 0, 0);
        let third = ExportProcessSample::new(6, MetricValue::Count(0), 0, 0, 0, 0, 0);
        let forth = ExportProcessSample::new(8, MetricValue::Count(0), 0, 0, 0, 0, 0);

        proc.add_sample(forth);
        proc.add_sample(second);
        proc.add_sample(first);
        proc.add_sample(third);

        let mut time = 0;

        machine.replay_by_time(
            |_process| true,
            |_machine, event| {
                if event.time() % 2 == 0 {
                    assert_eq!(2, event.process().pid());
                } else {
                    assert_eq!(1, event.process().pid());
                }

                assert_eq!(event.time() - 1, time);

                time = event.time();

                Ok(())
            }).expect("Should work");
    }
}
