// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::{HashMap, HashSet};
use std::collections::hash_map::{Values, ValuesMut};
use std::time::Duration;
use std::path::Path;

use crate::Writable;
use crate::event::{Event, EventData};
use crate::intern::{InternedStrings, InternedCallstacks};

#[cfg(feature = "scripting")]
pub mod scripting;

#[cfg(feature = "scripting")]
pub use scripting::ScriptedUniversalExporter;

use crate::helpers::callstack::CallstackHelper;

use modulemetadata::ModuleMetadata;
use pe_file::PEModuleMetadata;
use process::MetricValue::{self, Span};
use ruwind::UnwindType;
use chrono::{DateTime, Utc};

mod lookup;

pub mod record;
use record::ExportRecordType;
use record::ExportRecordData;
use record::ExportRecord;

pub mod span;
use span::ExportSpan;

pub mod os;
use os::OSExportMachine;
use os::OSExportSampler;
use os::OSExportSettings;

/* Make it easy for callers to use public OS extensions */
#[cfg(target_os = "linux")]
pub use os::linux::ExportSettingsLinuxExt;

pub const KERNEL_START:u64 = 0xFFFF800000000000;
pub const KERNEL_END:u64 = 0xFFFFFFFFFFFFFFFF;

const NANOS_IN_SEC:u64 = 1000000000;

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

#[derive(Default)]
struct ExportProxy {
    errors: Vec<anyhow::Error>,
    events: HashMap<usize, Event>,
}

impl ExportProxy {
    fn proxy_event_data(
        &mut self,
        event_id: usize,
        full_data: &[u8],
        event_data: &[u8]) {
        if let Some(event) = self.events.get_mut(&event_id) {
            self.errors.clear();

            event.process(
                full_data,
                event_data,
                &mut self.errors);

            /* Log errors, if any */
            for error in &self.errors {
                eprintln!("Error: Event '{}': {}", event.name(), error);
            }
        }
    }

    fn add_event(
        &mut self,
        event: Event) {
        self.events.insert(event.id(), event);
    }
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
        tid: u32,
        kind: u16) -> anyhow::Result<ExportProcessSample> {
        self.frames.clear();

        /* OS Specific callstack hook */
        self.os_event_callstack(data)?;

        let time = self.os_event_time(data)?;
        let cpu = self.os_event_cpu(data)?;

        Ok(self.exporter.borrow_mut().make_sample(
            time,
            value,
            tid,
            cpu,
            kind,
            &self.frames))
    }

    fn add_custom_sample(
        &mut self,
        pid: u32,
        sample: ExportProcessSample) -> anyhow::Result<()> {
        self.exporter.borrow_mut().add_custom_sample(pid, sample)
    }

    fn add_custom_sample_with_record(
        &mut self,
        pid: u32,
        sample: ExportProcessSample,
        record_type: u16,
        record_data: &[u8]) -> anyhow::Result<()> {
        self.exporter.borrow_mut().add_custom_sample_with_record(
            pid,
            sample,
            record_type,
            record_data)
    }

    fn add_sample(
        &mut self,
        data: &EventData,
        value: MetricValue,
        kind: u16) -> anyhow::Result<()> {
        self.frames.clear();

        /* OS Specific callstack hook */
        self.os_event_callstack(data)?;

        let time = self.os_event_time(data)?;
        let pid = self.os_event_pid(data)?;
        let tid = self.os_event_tid(data)?;
        let cpu = self.os_event_cpu(data)?;

        self.exporter.borrow_mut().add_sample(
            time,
            value,
            pid,
            tid,
            cpu,
            kind,
            &self.frames)
    }

    fn add_sample_with_record(
        &mut self,
        data: &EventData,
        value: MetricValue,
        kind: u16,
        record_type: u16,
        record_data: &[u8]) -> anyhow::Result<()> {
        self.frames.clear();

        /* OS Specific callstack hook */
        self.os_event_callstack(data)?;

        let time = self.os_event_time(data)?;
        let pid = self.os_event_pid(data)?;
        let tid = self.os_event_tid(data)?;
        let cpu = self.os_event_cpu(data)?;

        self.exporter.borrow_mut().add_sample_with_record(
            time,
            value,
            pid,
            tid,
            cpu,
            kind,
            record_type,
            record_data,
            &self.frames)
    }

    fn add_span(
        &mut self,
        span: ExportSpan) -> anyhow::Result<MetricValue> {
        Ok(self.exporter.borrow_mut().span_to_value(span))
    }
}

pub struct ExportBuiltContext<'a> {
    exporter: &'a mut ExportMachine,
    session: &'a mut os::Session,
    event: &'a Event,
    sample_kind: Option<u16>,
    record_type: Option<u16>,
}

impl<'a> ExportBuiltContext<'a> {
    fn new(
        exporter: &'a mut ExportMachine,
        event: &'a Event,
        session: &'a mut os::Session) -> Self {
        Self {
            exporter,
            session,
            event,
            sample_kind: None,
            record_type: None,
        }
    }

    fn take_sample_kind(&mut self) -> Option<u16> { self.sample_kind.take() }

    fn take_record_type(&mut self) -> Option<u16> { self.record_type.take() }

    pub fn event(&self) -> &Event { self.event }

    pub fn exporter_mut(&mut self) -> &mut ExportMachine { self.exporter }

    pub fn session_mut(&mut self) -> &mut os::Session { self.session }

    pub fn use_event_for_kind(
        &mut self,
        record: bool) {
        let kind = self.set_sample_kind(self.event.name());

        if record {
            self.set_record_type(
                ExportRecordType::from_event(
                    kind,
                    self.event));
        }
    }

    pub fn duration_to_qpc(
        &self,
        duration: Duration) -> u64 {
        let ns = duration.as_nanos() as f64;
        let freq = ExportMachine::qpc_freq();
        let ns_per_tick = freq as f64 / NANOS_IN_SEC as f64;

        (ns * ns_per_tick).floor() as u64
    }

    pub fn set_sample_kind(
        &mut self,
        kind: &str) -> u16 {
        let kind = self.exporter.sample_kind(kind);

        self.sample_kind = Some(kind);

        kind
    }

    pub fn set_record_type(
        &mut self,
        record_type: ExportRecordType) {
        let record_type = self.exporter.record_type(record_type);

        self.record_type = Some(record_type);
    }
}

pub struct ExportTraceContext<'a> {
    sampler: Writable<ExportSampler>,
    proxy: Writable<ExportProxy>,
    sample_kind: u16,
    record_type: u16,
    data: &'a EventData<'a>,
}

impl<'a> ExportTraceContext<'a> {
    fn new(
        sampler: Writable<ExportSampler>,
        proxy: Writable<ExportProxy>,
        sample_kind: u16,
        record_type: u16,
        data: &'a EventData) -> Self {
        Self {
            sampler,
            proxy,
            sample_kind,
            record_type,
            data,
        }
    }

    pub fn data(&self) -> &'a EventData { self.data }

    pub fn cpu(&self) -> anyhow::Result<u16> {
        self.sampler.borrow().os_event_cpu(self.data)
    }

    pub fn time(&self) -> anyhow::Result<u64> {
        self.sampler.borrow().os_event_time(self.data)
    }

    pub fn pid(&self) -> anyhow::Result<u32> {
        self.sampler.borrow().os_event_pid(self.data)
    }

    pub fn tid(&self) -> anyhow::Result<u32> {
        self.sampler.borrow().os_event_tid(self.data)
    }

    pub fn proxy_data(
        &mut self,
        event_id: usize,
        full_data: &[u8],
        event_data: &[u8]) {
        self.proxy.borrow_mut().proxy_event_data(
            event_id,
            full_data,
            event_data);
    }

    pub fn proxy_event_data(
        &mut self,
        event_id: usize,
        range: std::ops::Range<usize>) {
        self.proxy_data(
            event_id,
            self.data.full_data(),
            &self.data.event_data()[range]);
    }

    pub fn add_sample_with_kind(
        &mut self,
        value: MetricValue,
        kind: u16) -> anyhow::Result<()> {
        self.sampler.borrow_mut().add_sample(
            self.data,
            value,
            kind)
    }

    pub fn make_sample_with_kind(
        &mut self,
        value: MetricValue,
        tid: u32,
        kind: u16) -> anyhow::Result<ExportProcessSample> {
        self.sampler.borrow_mut().make_sample(
            self.data,
            value,
            tid,
            kind)
    }

    pub fn make_sample(
        &mut self,
        value: MetricValue,
        tid: u32) -> anyhow::Result<ExportProcessSample> {
        self.make_sample_with_kind(
            value,
            tid,
            self.sample_kind)
    }

    pub fn add_custom_sample(
        &mut self,
        pid: u32,
        sample: ExportProcessSample) -> anyhow::Result<()> {
        self.sampler.borrow_mut().add_custom_sample(
            pid,
            sample)
    }

    pub fn add_custom_sample_with_record(
        &mut self,
        pid: u32,
        sample: ExportProcessSample,
        record_data: &[u8]) -> anyhow::Result<()> {
        self.sampler.borrow_mut().add_custom_sample_with_record(
            pid,
            sample,
            self.record_type,
            record_data)
    }

    pub fn add_pid_sample(
        &mut self,
        pid: u32,
        tid: u32,
        value: MetricValue) -> anyhow::Result<()> {
        let sample = self.make_sample_with_kind(
            value,
            tid,
            self.sample_kind)?;

        self.sampler.borrow_mut().add_custom_sample(
            pid,
            sample)
    }

    pub fn add_pid_sample_with_record(
        &mut self,
        pid: u32,
        tid: u32,
        value: MetricValue,
        record_data: &[u8]) -> anyhow::Result<()> {
        let sample = self.make_sample_with_kind(
            value,
            tid,
            self.sample_kind)?;

        self.sampler.borrow_mut().add_custom_sample_with_record(
            pid,
            sample,
            self.record_type,
            record_data)
    }

    pub fn add_sample(
        &mut self,
        value: MetricValue) -> anyhow::Result<()> {
        self.add_sample_with_kind(
            value,
            self.sample_kind)
    }

    pub fn add_sample_with_event_data(
        &mut self,
        value: MetricValue,
        range: std::ops::Range<usize>) -> anyhow::Result<()> {
        self.sampler.borrow_mut().add_sample_with_record(
            self.data,
            value,
            self.sample_kind,
            self.record_type,
            &self.data.event_data()[range])
    }

    pub fn add_sample_with_record(
        &mut self,
        value: MetricValue,
        record_data: &[u8]) -> anyhow::Result<()> {
        self.sampler.borrow_mut().add_sample_with_record(
            self.data,
            value,
            self.sample_kind,
            self.record_type,
            record_data)
    }

    pub fn add_span(
        &mut self,
        span: ExportSpan) -> anyhow::Result<MetricValue> {
        self.sampler.borrow_mut().add_span(span)
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

pub struct ExportSampleFilterContext<'a> {
    kinds: &'a Vec<String>,
    spans: &'a Vec<ExportSpan>,
    record_types: &'a Vec<ExportRecordType>,
    record_type_id: u16,
    record_data: Option<&'a [u8]>,
    strings: &'a InternedStrings,
    proc: &'a ExportProcess,
    sample: &'a ExportProcessSample,
}

impl<'a> ExportSampleFilterContext<'a> {
    fn run_hooks(
        &self,
        hooks: &Vec<Box<dyn Fn(&ExportSampleFilterContext) -> ExportFilterAction>>) -> bool {
        for hook in hooks {
            match hook(&self) {
                ExportFilterAction::Keep => { },
                ExportFilterAction::Drop => { return false; },
            }
        }

        return true;
    }

    pub fn sample(&self) -> &ExportProcessSample { self.sample }

    pub fn sample_span(&self) -> Option<&ExportSpan> {
        if let MetricValue::Span(id) = self.sample.value() {
            if id < self.spans.len() {
                return Some(&self.spans[id]);
            }
        }

        None
    }

    pub fn span_name(
        &self,
        span: &ExportSpan) -> &str {
        span.name(self.strings)
    }

    pub fn pid(&self) -> u32 { self.proc.pid() }

    pub fn sample_record_data(&self) -> Option<ExportRecordData> {
        if self.record_data.is_none() {
            return None;
        }

        Some(ExportRecordData::new(
            self.record_type_id,
            &self.record_types[self.record_type_id as usize],
            &self.record_data.unwrap()))
    }

    pub fn sample_kind_str(&self) -> &str {
        let kind = self.sample.kind() as usize;

        if kind >= self.kinds.len() {
            return "Unknown";
        }

        &self.kinds[kind]
    }

    pub fn comm_name(&self) -> &str {
        match self.proc.comm_id() {
            Some(id) => {
                match self.strings.from_id(id) {
                    Ok(name) => { name },
                    Err(_) => { "Unknown" },
                }
            },
            None => { "Unknown" },
        }
    }
}

macro_rules! filter_sample_ret_on_drop {
    ($self: expr, $proc:expr, $sample:expr, $record_type_id:expr, $record_data:expr) => {
        if !$self.sample_hooks.is_empty() {
            let context = ExportSampleFilterContext {
                kinds: &$self.kinds,
                strings: &$self.strings,
                record_types: &$self.record_types,
                record_type_id: $record_type_id,
                record_data: $record_data,
                spans: &$self.spans,
                proc: $proc,
                sample: $sample,
            };

            if !context.run_hooks(&$self.sample_hooks) {
                return Ok(());
            }
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
    sample_hooks: Option<Vec<Box<dyn Fn(&ExportSampleFilterContext) -> ExportFilterAction>>>,
    target_pids: Option<Vec<i32>>,
    proxy_id: usize,
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
            sample_hooks: None,
            target_pids: None,
            proxy_id: 0,
        }
    }

    pub fn for_each_event(
        &self,
        mut closure: impl FnMut(&Event)) {
        if let Some(events) = &self.events {
            for event in events {
                if let Some(event) = &event.event {
                    closure(event);
                }
            }
        }
    }

    pub fn has_unwinder(&self) -> bool { self.unwinder }

    pub fn new_proxy_event(
        &mut self,
        name: String) -> Event {
        self.proxy_id += 1;

        let mut event = Event::new(self.proxy_id, name);
        event.set_proxy_flag();

        event
    }

    pub fn with_sample_hook(
        self,
        hook: impl Fn(&ExportSampleFilterContext) -> ExportFilterAction + 'static) -> Self {

        let mut clone = self;

        let hook = Box::new(hook);

        match clone.sample_hooks.as_mut() {
            Some(hooks) => { hooks.push(hook); },
            None => { clone.sample_hooks = Some(vec![hook]); }
        }

        clone
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

pub enum ExportFilterAction {
    Keep,
    Drop,
}

pub struct ExportMachine {
    settings: ExportSettings,
    strings: InternedStrings,
    callstacks: InternedCallstacks,
    pub(crate) os: OSExportMachine,
    procs: HashMap<u32, ExportProcess>,
    records: Vec<ExportRecord>,
    spans: Vec<ExportSpan>,
    record_data: Vec<u8>,
    module_metadata: ModuleMetadataLookup,
    kinds: Vec<String>,
    record_types: Vec<ExportRecordType>,
    map_index: usize,
    drop_closures: Vec<Box<dyn FnMut()>>,
    start_date: Option<DateTime<Utc>>,
    start_qpc: Option<u64>,
    end_qpc: Option<u64>,
    duration: Option<Duration>,
    sample_hooks: Vec<Box<dyn Fn(&ExportSampleFilterContext) -> ExportFilterAction>>,
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

    fn os_qpc_time() -> u64;

    fn os_qpc_freq() -> u64;

    fn os_cpu_count() -> u32;
}

pub type CommMap = HashMap<Option<usize>, Vec<u32>>;

const NO_FRAMES: [u64; 1] = [0; 1];

impl ExportMachine {
    pub fn new(mut settings: ExportSettings) -> Self {
        let mut strings = InternedStrings::new(settings.string_buckets);
        let callstacks = InternedCallstacks::new(settings.callstack_buckets);
        let sample_hooks = settings.sample_hooks.take().unwrap_or_default();
        let mut records = Vec::new();
        let mut record_types = Vec::new();

        /* Ensure string ID 0 is always empty */
        strings.to_id("");

        /* Ensure record ID 0 is always empty/default */
        records.push(ExportRecord::default());
        record_types.push(ExportRecordType::default());

        Self {
            settings,
            strings,
            callstacks,
            os: OSExportMachine::new(),
            procs: HashMap::new(),
            records,
            spans: Vec::new(),
            record_data: Vec::new(),
            module_metadata: ModuleMetadataLookup::new(),
            kinds: Vec::new(),
            record_types,
            map_index: 0,
            drop_closures: Vec::new(),
            start_date: None,
            start_qpc: None,
            end_qpc: None,
            duration: None,
            sample_hooks,
        }
    }

    pub fn start_date(&self) -> Option<DateTime<Utc>> { self.start_date }

    pub fn start_qpc(&self) -> Option<u64> { self.start_qpc }

    pub fn end_qpc(&self) -> Option<u64> { self.end_qpc }

    pub fn duration(&self) -> Option<Duration> { self.duration }

    pub fn settings(&self) -> &ExportSettings { &self.settings }

    pub fn qpc_time() -> u64 { Self::os_qpc_time() }

    pub fn qpc_freq() -> u64 { Self::os_qpc_freq() }

    pub fn qpc_to_ns(
        freq: u64,
        mut qpc: u64) -> u64 {
        let mut ns: u64 = 0;

        if freq != 0 {
            while qpc >= freq {
                ns += NANOS_IN_SEC;
                qpc -= freq;
            }

            ns += qpc * NANOS_IN_SEC / freq;
        }

        ns
    }

    pub fn qpc_to_duration(
        freq: u64,
        qpc: u64) -> Duration {
        Duration::from_nanos(Self::qpc_to_ns(freq, qpc))
    }

    pub fn cpu_count() -> u32 { Self::os_cpu_count() }

    pub fn get_mapping_metadata(
        &self,
        mapping: &ExportMapping) -> Option<&ModuleMetadata> {
        match mapping.node() {
            Some(node) => { self.module_metadata.get(node) },
            None => { None }
        }
    }

    pub fn add_sample_hook(
        &mut self,
        hook: impl Fn(&ExportSampleFilterContext) -> ExportFilterAction + 'static) {
        self.sample_hooks.push(Box::new(hook));
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
            Self::os_qpc_time());
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
            let end_qpc = Self::os_qpc_time();
            let qpc_freq = Self::os_qpc_freq();
            let duration = Self::qpc_to_duration(qpc_freq, end_qpc - start_qpc);

            self.end_qpc = Some(end_qpc);
            self.duration = Some(duration);
        }
    }

    pub fn sample_kinds(&self) -> &Vec<String> { &self.kinds }

    pub fn record_types(&self) -> &Vec<ExportRecordType> { &self.record_types }

    pub fn strings(&self) -> &InternedStrings { &self.strings }

    pub fn callstacks(&self) -> &InternedCallstacks { &self.callstacks }

    pub fn processes(&self) -> Values<u32, ExportProcess> { self.procs.values() }

    pub fn sample_record_data(
        &self,
        sample: &ExportProcessSample) -> ExportRecordData {
        /* Lookup data via sample's record ID */
        let record = &self.records[sample.record_id()];

        let record_type_id = record.record_type();

        ExportRecordData::new(
            record_type_id,
            &self.record_types[record_type_id as usize],
            &self.record_data[record.start()..record.end()])
    }

    pub fn sample_span(
        &self,
        sample: &ExportProcessSample) -> Option<&ExportSpan> {
        self.span_from_value(sample.value())
    }

    pub fn span_from_value(
        &self,
        value: MetricValue) -> Option<&ExportSpan> {
        if let Span(id) = value {
            if id < self.spans.len() {
                return Some(&self.spans[id]);
            }
        }

        None
    }

    pub fn span_to_value(
        &mut self,
        span: ExportSpan) -> MetricValue {
        let id = self.spans.len();

        self.spans.push(span);

        MetricValue::Span(id)
    }

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

    pub fn record_type(
        &mut self,
        record_type: ExportRecordType) -> u16 {
        for (i, existing) in self.record_types.iter().enumerate() {
            if existing == &record_type {
                return i as u16;
            }
        }

        let count = self.record_types.len() as u16;
        self.record_types.push(record_type);
        count
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
        /*
         * PID 0 is reserved for the kernel, and shouldn't get exec'd
         * while we are tracing. If PID 0 access is required, we must
         * have an explicit method for it.
         *
         * NOTE:
         * On Linux, processes in containers outside of the current
         * container get a PID of 0. This causes the kernel process to
         * have modules added incorrectly.
         */
        if pid == 0 {
            return Ok(());
        }

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
        /*
         * PID 0 is reserved for the kernel, and shouldn't get exec'd
         * while we are tracing. If PID 0 access is required, we must
         * have an explicit method for it.
         *
         * NOTE:
         * On Linux, processes in containers outside of the current
         * container get a PID of 0. This causes the kernel process to
         * have it's comm name changed incorrectly.
         */
        if pid == 0 {
            return Ok(());
        }

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
        if pid == 0 {
            return Ok(());
        }

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

        let proc = self.procs.entry(pid).or_insert_with(|| ExportProcess::new(pid));

        filter_sample_ret_on_drop!(self, &proc, &sample, 0, None);

        proc.add_sample(sample);

        Ok(())
    }

    fn attach_record_to_sample(
        &mut self,
        pid: u32,
        mut sample: ExportProcessSample,
        record_type: u16,
        record_data: &[u8]) -> anyhow::Result<()> {
        if sample.has_record() {
            anyhow::bail!("Record is already attached.");
        }

        let proc = self.procs.entry(pid).or_insert_with(|| ExportProcess::new(pid));

        filter_sample_ret_on_drop!(self, &proc, &sample, record_type, Some(record_data));

        /*
         * Add record data to global data slice:
         * Instead of having many vecs (IE: each process) we keep
         * a single vec that can grow naturally to accomodate the
         * system wide view of records with minimal allocations.
         */
        let record_id = self.records.len();
        let offset = self.record_data.len();
        let len = record_data.len() as u32;

        self.records.push(
            ExportRecord::new(
                record_type,
                offset,
                len));

        self.record_data.extend_from_slice(record_data);

        /* Associate record with sample and add */
        sample.attach_record(record_id);

        proc.add_sample(sample);

        Ok(())
    }

    pub fn add_sample_with_record(
        &mut self,
        time: u64,
        value: MetricValue,
        pid: u32,
        tid: u32,
        cpu: u16,
        kind: u16,
        record_type: u16,
        record_data: &[u8],
        frames: &[u64]) -> anyhow::Result<()> {
        let sample = self.make_sample(
            time,
            value,
            tid,
            cpu,
            kind,
            frames);

        self.attach_record_to_sample(
            pid,
            sample,
            record_type,
            record_data)
    }

    pub fn add_custom_sample(
        &mut self,
        pid: u32,
        sample: ExportProcessSample) -> anyhow::Result<()> {
        let proc = self.procs.entry(pid).or_insert_with(|| ExportProcess::new(pid));

        filter_sample_ret_on_drop!(self, &proc, &sample, 0, None);

        proc.add_sample(sample);

        Ok(())
    }

    pub fn add_custom_sample_with_record(
        &mut self,
        pid: u32,
        sample: ExportProcessSample,
        record_type: u16,
        record_data: &[u8]) -> anyhow::Result<()> {
        self.attach_record_to_sample(
            pid,
            sample,
            record_type,
            record_data)
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
    use crate::event::*;

    #[test]
    fn sample_records() {
        let mut machine = ExportMachine::new(ExportSettings::default());

        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "1".into(), "unsigned char".into(),
                LocationType::Static, 0, 1));

        let kind = machine.sample_kind("test");
        let record_type = machine.record_type(ExportRecordType::from_event(kind, &e));
        let mut record_data: [u8; 1] = [b'Z'];
        let mut frames = Vec::new();

        frames.push(1);
        frames.push(2);
        frames.push(3);

        machine.add_sample_with_record(
            0,
            MetricValue::Count(0),
            0,
            0,
            0,
            kind,
            record_type,
            &record_data,
            &frames).unwrap();

        record_data[0] = b'A';

        machine.add_sample_with_record(
            0,
            MetricValue::Count(0),
            0,
            0,
            0,
            kind,
            record_type,
            &record_data,
            &frames).unwrap();

        let proc = machine.find_process(0).unwrap();
        let samples = proc.samples();

        assert_eq!(2, samples.len());

        let sample = &samples[0];
        let data = machine.sample_record_data(sample);
        let record_type = data.record_type();
        let record_data = data.record_data();
        assert_eq!(1, record_type.id());
        assert_eq!("test", record_type.name());
        assert_eq!(1, record_data.len());
        assert_eq!(b'Z', record_data[0]);

        let sample = &samples[1];
        let data = machine.sample_record_data(sample);
        let record_type = data.record_type();
        let record_data = data.record_data();
        assert_eq!(1, record_type.id());
        assert_eq!("test", record_type.name());
        assert_eq!(1, record_data.len());
        assert_eq!(b'A', record_data[0]);
    }

    #[test]
    fn record_type() {
        let mut machine = ExportMachine::new(ExportSettings::default());

        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "1".into(), "unsigned char".into(),
                LocationType::Static, 0, 1));

        let kind = machine.sample_kind("test");

        let first = machine.record_type(ExportRecordType::from_event(kind, &e));
        assert_ne!(0, first);
        assert_eq!(first, machine.record_type(ExportRecordType::from_event(kind, &e)));

        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "1".into(), "unsigned char".into(),
                LocationType::Static, 0, 1));

        format.add_field(
            EventField::new(
                "2".into(), "unsigned char".into(),
                LocationType::Static, 0, 1));

        let second = machine.record_type(ExportRecordType::from_event(kind, &e));
        assert_ne!(0, second);
        assert_ne!(first, second);
        assert_eq!(second, machine.record_type(ExportRecordType::from_event(kind, &e)));
    }

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

    #[cfg(target_os = "windows")]
    #[test]
    fn proxy() {
        let mut settings = ExportSettings::default();
        let count = Writable::new(0usize);

        let mut first = settings.new_proxy_event("1".into());
        let mut second = settings.new_proxy_event("2".into());
        let mut third = settings.new_proxy_event("3".into());

        let e_count = count.clone();
        first.add_callback(move |data| {
            *e_count.borrow_mut() += 1;
            assert_eq!(b'1', data.event_data()[0]);
            assert_eq!(1, data.event_data().len());
            Ok(())
        });

        let e_count = count.clone();
        second.add_callback(move |data| {
            *e_count.borrow_mut() += 1;
            assert_eq!(b'2', data.event_data()[0]);
            assert_eq!(1, data.event_data().len());
            Ok(())
        });

        let e_count = count.clone();
        third.add_callback(move |data| {
            *e_count.borrow_mut() += 1;
            assert_eq!(b'3', data.event_data()[0]);
            assert_eq!(1, data.event_data().len());
            Ok(())
        });

        assert_eq!(1, first.id());
        assert_eq!(2, second.id());
        assert_eq!(3, third.id());

        let mut proxy = ExportProxy::default();

        proxy.add_event(first);
        proxy.add_event(second);
        proxy.add_event(third);

        let machine = Writable::new(ExportMachine::new(settings));

        let session = crate::etw::EtwSession::new();

        let sampler = ExportSampler::new(
            &machine,
            OSExportSampler::new(&session));

        let mut data = Vec::new();

        data.push(b'1');
        data.push(b'2');
        data.push(b'3');

        let format = EventFormat::new();

        let event_data = EventData::new(
            &data,
            &data,
            &format);

        let mut context = ExportTraceContext::new(
            Writable::new(sampler),
            Writable::new(proxy),
            0,
            0,
            &event_data);

        context.proxy_event_data(1, 0..1);
        context.proxy_event_data(2, 1..2);
        context.proxy_event_data(3, 2..3);

        assert_eq!(3, *count.borrow());
    }
}
