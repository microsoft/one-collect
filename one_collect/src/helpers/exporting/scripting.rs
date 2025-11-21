// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::scripting::{ScriptEngine, ScriptEvent};
use crate::event::*;

use rhai::{CustomType, TypeBuilder, Engine, EvalAltResult};
use tracing::{info, error};

pub struct UniversalExporterSwapper {
    exporter: Option<UniversalExporter>,
}

impl UniversalExporterSwapper {
    pub fn new(settings: ExportSettings) -> Self {
        Self {
            exporter: Some(UniversalExporter::new(settings)),
        }
    }

    pub fn new_proxy_event(
        &mut self,
        name: String,
        id: usize) -> Option<Event> {
        if let Some(exporter) = self.exporter.as_mut() {
            if let Some(settings) = exporter.settings_mut() {
                return Some(settings.new_proxy_event(name, id));
            }
        }

        None
    }

    pub fn add_event(
        &mut self,
        event: Event,
        built: impl FnMut(&mut ExportBuiltContext) -> anyhow::Result<()> + 'static,
        trace: impl FnMut(&mut ExportTraceContext) -> anyhow::Result<()> + 'static) {
        if let Some(exporter) = self.exporter.as_mut() {
            exporter.add_event(event, built, trace);
        }
    }

    pub fn swap(
        &mut self,
        mut swap: impl FnMut(UniversalExporter) -> UniversalExporter) {
        if let Some(exporter) = self.exporter.take() {
            self.exporter.replace(swap(exporter));
        }
    }

    pub fn take(
        &mut self) -> anyhow::Result<UniversalExporter> {
        match self.exporter.take() {
            Some(exporter) => { Ok(exporter) },
            None => { anyhow::bail!("Exporter was removed!"); },
        }
    }
}

type TimelineEventIdFn = Box<dyn FnMut(&ExportTraceContext, &mut [u8])>;
type TimelineEventRecFn = Box<dyn FnMut(&ExportTraceContext, &mut Vec<u8>)>;
type TimelineEventFilterFn = Box<dyn FnMut(&ExportTraceContext) -> bool>;

struct TimelineEvent {
    event: Event,
    id_closure: TimelineEventIdFn,
    record_closure: Option<TimelineEventRecFn>,
    filter_closure: Option<TimelineEventFilterFn>,
    flags: TimelineEventFlags,
}

#[derive(Default, Clone)]
struct FieldFilter {
    field: String,
    operation: String,
    value: String,
}

#[derive(Default, Clone)]
pub struct TimelineEventFlags {
    flags: u8,
    record_fields: Vec<String>,
    filter_fields: Vec<FieldFilter>,
    filter_record_fields: Vec<FieldFilter>,
}

impl CustomType for TimelineEventFlags {
    fn build(mut builder: TypeBuilder<Self>) {
        builder
            .with_fn("should_start", Self::should_start)
            .with_fn("should_end", Self::should_end)
            .with_fn("should_record_field", Self::should_record_field)
            .with_fn("should_filter_field", Self::should_filter_field)
            .with_fn("should_filter_record", Self::should_filter_record)
            .with_fn("clear", Self::clear);
    }
}

impl TimelineEventFlags {
    const TIMELINE_EVENT_FLAG_NONE: u8 = 0x0;
    const TIMELINE_EVENT_FLAG_START: u8 = 0x1;
    const TIMELINE_EVENT_FLAG_END: u8 = 0x2;

    pub fn will_start(&self) -> bool { self.flags & Self::TIMELINE_EVENT_FLAG_START != 0 }

    pub fn should_start(&mut self) { self.flags |= Self::TIMELINE_EVENT_FLAG_START; }

    pub fn will_end(&self) -> bool { self.flags & Self::TIMELINE_EVENT_FLAG_END != 0 }

    pub fn should_end(&mut self) { self.flags |= Self::TIMELINE_EVENT_FLAG_END; }

    pub fn should_record_field(
        &mut self,
        field: String) {
        self.record_fields.push(field);
    }

    pub fn should_filter_field(
        &mut self,
        field: String,
        operation: String,
        value: String) {
        self.filter_fields.push(
            FieldFilter {
                field,
                operation,
                value,
                });
    }

    pub fn should_filter_record(
        &mut self,
        field: String,
        operation: String,
        value: String) {
        self.filter_record_fields.push(
            FieldFilter {
                field,
                operation,
                value,
                });
    }

    pub fn record_fields(&self) -> &[String] { &self.record_fields }

    pub fn clear(&mut self) {
        self.flags = Self::TIMELINE_EVENT_FLAG_NONE;
        self.record_fields.clear();
        self.filter_fields.clear();
        self.filter_record_fields.clear();
    }
}

#[derive(Clone)]
struct ScriptTimeline {
    timeline: Writable<ExporterTimeline>,
}

impl CustomType for ScriptTimeline {
    fn build(mut builder: TypeBuilder<Self>) {
        builder
            .with_fn("with_event", Self::with_event_one)
            .with_fn("with_event", Self::with_event_two)
            .with_fn("with_event", Self::with_event_three)
            .with_fn("with_event", Self::with_event_four)
            .with_fn("with_min_ns", Self::with_min_ns)
            .with_fn("with_min_us", Self::with_min_us)
            .with_fn("with_min_ms", Self::with_min_ms)
            .with_fn("with_min_sec", Self::with_min_secs);
    }
}

impl ScriptTimeline {
    fn with_event(
        &mut self,
        event: ScriptEvent,
        fields: &Vec<&str>,
        flags: TimelineEventFlags) -> Result<(), Box<EvalAltResult>> {
        match self.timeline.borrow_mut().track_event(
            event.to_event().ok_or("Event has already been used.")?,
            fields,
            flags)
        {
            Ok(()) => { Ok(()) },
            Err(e) => { Err(format!("{}", e).into()) },
        }
    }

    pub fn with_min_ns(
        &mut self,
        nanos: i64) {
        self.timeline.borrow_mut().set_min_duration(Duration::from_nanos(nanos as u64));
    }

    pub fn with_min_us(
        &mut self,
        micros: i64) {
        self.timeline.borrow_mut().set_min_duration(Duration::from_micros(micros as u64));
    }

    pub fn with_min_ms(
        &mut self,
        millis: i64) {
        self.timeline.borrow_mut().set_min_duration(Duration::from_millis(millis as u64));
    }

    pub fn with_min_secs(
        &mut self,
        secs: i64) {
        self.timeline.borrow_mut().set_min_duration(Duration::from_secs(secs as u64));
    }

    pub fn apply(
        self,
        exporter: &mut UniversalExporterSwapper) -> Result<(), Box<EvalAltResult>> {
        match self.timeline.borrow_mut().apply(exporter) {
            Ok(()) => { Ok(()) },
            Err(e) => { Err(format!("{}", e).into()) },
        }
    }

    pub fn with_event_one(
        &mut self,
        event: ScriptEvent,
        id_field: String,
        flags: TimelineEventFlags) -> Result<(), Box<EvalAltResult>> {
        let mut fields = Vec::new();
        fields.push(id_field.as_str());

        self.with_event(event, &fields, flags)
    }

    pub fn with_event_two(
        &mut self,
        event: ScriptEvent,
        id_field_one: String,
        id_field_two: String,
        flags: TimelineEventFlags) -> Result<(), Box<EvalAltResult>> {
        let mut fields = Vec::new();
        fields.push(id_field_one.as_str());
        fields.push(id_field_two.as_str());

        self.with_event(event, &fields, flags)
    }

    pub fn with_event_three(
        &mut self,
        event: ScriptEvent,
        id_field_one: String,
        id_field_two: String,
        id_field_three: String,
        flags: TimelineEventFlags) -> Result<(), Box<EvalAltResult>> {
        let mut fields = Vec::new();
        fields.push(id_field_one.as_str());
        fields.push(id_field_two.as_str());
        fields.push(id_field_three.as_str());

        self.with_event(event, &fields, flags)
    }

    pub fn with_event_four(
        &mut self,
        event: ScriptEvent,
        id_field_one: String,
        id_field_two: String,
        id_field_three: String,
        id_field_four: String,
        flags: TimelineEventFlags) -> Result<(), Box<EvalAltResult>> {
        let mut fields = Vec::new();
        fields.push(id_field_one.as_str());
        fields.push(id_field_two.as_str());
        fields.push(id_field_three.as_str());
        fields.push(id_field_four.as_str());

        self.with_event(event, &fields, flags)
    }
}

macro_rules! apply_timeline {
    ($self:expr, $exporter:expr, $size:expr) => {
        struct TimelineValues {
            record: Vec<u8>,
            span: ExportSpan,
            pid: u32,
            tid: u32,
        }

        let map: HashMap<[u8; $size], TimelineValues> = HashMap::new();
        let map = Writable::new(map);

        let min_duration = $self.min_duration.clone();
        let mut capacity = 0;

        /* Determine how many spans we likely will have */
        for event in &$self.events {
            if !event.flags.will_end() {
                capacity += 1;
            }
        }

        let record_capacity = if let Some(last) = $self.record_format.fields().last() {
            last.offset + last.size
        } else {
            0
        };

        let should_record = record_capacity != 0;

        for mut event in $self.events.drain(..) {
            let fn_map = map.clone();

            let mut record_filter_closure: Option<Box<dyn FnMut(&[u8]) -> bool>> = None;

            if !event.flags.filter_record_fields.is_empty() {
                let mut filter_closures = Vec::new();

                for filter in &event.flags.filter_record_fields {
                    match $self.record_format.try_get_field_filter_closure(
                        &filter.field,
                        &filter.operation,
                        &filter.value) {
                        Some(closure) => {
                            filter_closures.push(closure);
                        },
                        None => {
                            anyhow::bail!(
                                "Unable to apply record filter \"{} {} {}\" on event \"{}\". \
                                Check that the field exists and for type compatibility.",
                                filter.field,
                                filter.operation,
                                filter.value,
                                event.event.name());
                        }
                    }
                }

                record_filter_closure = Some(Box::new(move |record_data| {
                    for closure in &mut filter_closures {
                        if !closure(record_data) {
                            return false;
                        }
                    }

                    true
                }));
            }

            if event.flags.will_end() {
                let name = $self.name.clone();

                #[derive(Default)]
                struct SharedContext {
                    qpc_min: u64,
                    record_format: Option<EventFormat>,
                }

                let event_id = event.event.id();
                let context = Writable::new(SharedContext::default());
                let fn_context = context.clone();

                if should_record {
                    context.borrow_mut().record_format = Some(
                        $self.record_format.clone());
                }

                $exporter.add_event(
                    event.event,
                    move |built| {
                        let mut context = fn_context.borrow_mut();

                        let kind = built.set_sample_kind(&name);

                        /* Calculate QPC min duration if any */
                        if let Some(min_duration) = min_duration {
                            context.qpc_min = built.duration_to_qpc(min_duration);
                        }

                        if let Some(record_format) = context.record_format.take() {
                            built.set_record_type(
                                ExportRecordType::new(
                                    kind,
                                    event_id,
                                    name.clone(),
                                    record_format));
                        }

                        Ok(())
                    },
                    move |trace| {
                        let mut map = fn_map.borrow_mut();
                        let mut id: [u8; $size] = [0; $size];

                        (event.id_closure)(trace, &mut id);

                        /* First complete event flushes duration */
                        if let Some(mut values) = map.remove(&id) {
                            let context = context.borrow();

                            let time = trace.time()?;

                            values.span.mark_last_child_end(time);
                            values.span.mark_end(time);

                            if values.span.qpc_duration() >= context.qpc_min {
                                /* Filter out event only after removing */
                                if let Some(filter) = &mut event.filter_closure {
                                    if !filter(trace) {
                                        return Ok(());
                                    }
                                }

                                if should_record {
                                    /* Filter based on current recorded values */
                                    if let Some(record_filter) = record_filter_closure.as_mut() {
                                        if !record_filter(&mut values.record) {
                                            return Ok(());
                                        }
                                    }

                                    /* Record values, if any */
                                    if let Some(record_closure) = event.record_closure.as_mut() {
                                        record_closure(trace, &mut values.record);
                                    }

                                    trace.sample_builder()
                                        .with_pid(values.pid)
                                        .with_tid(values.tid)
                                        .with_record_data(&values.record)
                                        .save_span(values.span)?;
                                } else {
                                    trace.sample_builder()
                                        .with_pid(values.pid)
                                        .with_tid(values.tid)
                                        .save_span(values.span)?;
                                }
                            }
                        }

                        Ok(())
                    });
            } else {
                let timeline_name = $self.name.clone();
                let event_name = event.event.name().to_owned();

                #[derive(Default)]
                struct SharedContext {
                    name_id: usize,
                    timeline_name_id: usize,
                }

                let context = Writable::new(SharedContext::default());
                let fn_context = context.clone();
                let will_start = event.flags.will_start();

                $exporter.add_event(
                    event.event,
                    move |built| {
                        let exporter = built.exporter_mut();

                        /* Pre-cache intern names */
                        let mut context = fn_context.borrow_mut();
                        context.name_id = exporter.intern(&event_name);
                        context.timeline_name_id = exporter.intern(&timeline_name);

                        Ok(())
                    },
                    move |trace| {
                        let context = context.borrow();
                        let mut map = fn_map.borrow_mut();
                        let mut id: [u8; $size] = [0; $size];

                        /* Filter out event before adding */
                        if let Some(filter) = &mut event.filter_closure {
                            if !filter(trace) {
                                return Ok(());
                            }
                        }

                        (event.id_closure)(trace, &mut id);

                        let pid = trace.pid()?;
                        let tid = trace.tid()?;
                        let time = trace.time()?;

                        let values = if will_start {
                            /* First will_start event sets pid/tid values */
                            Some(map.entry(id).or_insert_with(|| {
                                TimelineValues {
                                    record: Vec::with_capacity(record_capacity),
                                    span: ExportSpan::start(
                                        context.timeline_name_id,
                                        time,
                                        capacity),
                                    pid,
                                    tid,
                                }}))
                        } else {
                            map.get_mut(&id)
                        };

                        if let Some(values) = values {
                            /* Filter based on current recorded values */
                            if let Some(record_filter) = record_filter_closure.as_mut() {
                                if !record_filter(&mut values.record) {
                                    return Ok(());
                                }
                            }

                            /* Record values, if any */
                            if let Some(record_closure) = event.record_closure.as_mut() {
                                record_closure(trace, &mut values.record);
                            }

                            /* Add new child, ending last child if any */
                            values.span.mark_last_child_end(time);

                            values.span.add_child(
                                ExportSpan::start(
                                    context.name_id,
                                    time,
                                    0));
                        }

                        Ok(())
                    });
            }
        }
    }
}

pub struct ExporterTimeline {
    name: String,
    events: Vec<TimelineEvent>,
    id_size: usize,
    min_duration: Option<Duration>,
    record_format: EventFormat,
}

impl ExporterTimeline {
    pub fn new(name: String) -> Self {
        Self {
            name,
            events: Vec::new(),
            id_size: 0,
            min_duration: None,
            record_format: EventFormat::default(),
        }
    }

    pub fn set_min_duration(
        &mut self,
        duration: Duration) {
        self.min_duration = Some(duration);
    }

    pub fn track_event(
        &mut self,
        event: Event,
        id_fields: &Vec<&str>,
        flags: TimelineEventFlags) -> anyhow::Result<()> {
        if flags.will_end() && flags.will_start() {
            anyhow::bail!(
                "Event \"{}\" cannot both start and end, check flags.",
                event.name());
        }

        if flags.will_start() && !flags.filter_record_fields.is_empty() {
            anyhow::bail!(
                "Event \"{}\" cannot start and filter on record data (Record data won't exist), check flags.",
                event.name());
        }

        let mut id_closures = Vec::new();

        if id_fields.is_empty() {
            anyhow::bail!(
                "Event \"{}\" must have an ID field.",
                event.name());
        }

        let mut total_id_size = 0;

        for name in id_fields {
            match event.try_get_field_data_closure(name) {
                Some(closure) => { id_closures.push(closure); },
                None => {
                    anyhow::bail!(
                        "Unable to get ID from \"{}\" for event \"{}\".",
                        name, event.name()); },
            }

            /* SAFETY: Already accessed above */
            let format = event.format();
            let field_ref = format.get_field_ref_unchecked(name);
            let field = format.get_field_unchecked(field_ref);

            /* Ensure static/known size */
            if field.size == 0 ||
               field.location == LocationType::DynRelative ||
               field.location == LocationType::DynAbsolute {
                anyhow::bail!(
                    "Field \"{}\" for event \"{}\", must be static size for ID.",
                    name, event.name());
            }

            /* Add up */
            total_id_size += field.size;
        }

        /* Ensure they are the same as the others */
        if self.events.is_empty() {
            self.id_size = total_id_size;
        } else if self.id_size != total_id_size {
            anyhow::bail!(
                "Previous ID was {} bytes, event \"{}\" ID is {} bytes.",
                self.id_size,
                event.name(),
                total_id_size);
        }

        let id_closure = Box::new(move |trace: &ExportTraceContext, mut slice: &mut [u8]| {
            let event_data = trace.data.event_data();

            for closure in &mut id_closures {
                let data = closure(event_data);
                let len = data.len();

                slice[0..len].copy_from_slice(data);
                slice = &mut slice[len..];
            }
        });

        struct RecordContext {
            write_offset: usize,
            closure: Box<dyn FnMut(&[u8]) -> &[u8]>,
        }

        let mut record_closures = Vec::new();

        for record_field in flags.record_fields() {
            if let Some(event_field) = event.format().get_field(record_field) {
                if event_field.size == 0 ||
                   event_field.location == LocationType::DynRelative ||
                   event_field.location == LocationType::DynAbsolute {
                    anyhow::bail!(
                        "Record field \"{}\" on event \"{}\" must have a static size.",
                        record_field, event.name());
                }

                let write_offset = match self.record_format.get_field(record_field) {
                    Some(existing_field) => {
                        if event_field.type_name != existing_field.type_name {
                            anyhow::bail!(
                                "Record field \"{}\" on event \"{}\" must all have the same type.",
                                record_field, event.name());
                        }

                        if event_field.size != existing_field.size {
                            anyhow::bail!(
                                "Record field \"{}\" on event \"{}\" must all have the same size.",
                                record_field, event.name());
                        }

                        if event_field.location != existing_field.location {
                            anyhow::bail!(
                                "Record field \"{}\" on event \"{}\" must all have the same location.",
                                record_field, event.name());
                        }

                        existing_field.offset
                    },
                    None => {
                        let mut new_field = event_field.clone();

                        let offset = match self.record_format.fields().last() {
                            Some(last_field) => { last_field.offset + last_field.size },
                            None => { 0 },
                        };

                        new_field.offset = offset;

                        self.record_format.add_field(new_field);

                        offset
                    }
                };

                match event.try_get_field_data_closure(record_field) {
                    Some(closure) => {
                        record_closures.push(
                            RecordContext {
                                write_offset,
                                closure,
                            });
                    },
                    None => {
                        anyhow::bail!(
                            "Unable to get record from \"{}\" for event \"{}\".",
                            record_field, event.name());
                    },
                }
            } else {
                anyhow::bail!(
                    "Record field \"{}\" does not exist for event \"{}\".",
                    record_field, event.name());
            }
        }

        let mut filter_closures = Vec::new();

        for filter in &flags.filter_fields {
            match event.try_get_field_filter_closure(
                &filter.field,
                &filter.operation,
                &filter.value) {
                Some(closure) => {
                    filter_closures.push(closure);
                },
                None => {
                    anyhow::bail!(
                        "Unable to apply event filter \"{} {} {}\" on event \"{}\". \
                        Check that the field exists and for type compatibility.",
                        filter.field,
                        filter.operation,
                        filter.value,
                        event.name());
                }
            }
        }

        let mut record_closure: Option<TimelineEventRecFn> = None;

        if !record_closures.is_empty() {
            record_closure = Some(Box::new(move |trace, record_data| {
                let event_data = trace.data.event_data();

                for closure in &mut record_closures {
                    let data = (closure.closure)(event_data);
                    let len = data.len();
                    let start = closure.write_offset;
                    let end = start + len;

                    /* Ensure enough space */
                    if record_data.len() < end {
                        record_data.resize(end, 0);
                    }

                    /* Copy */
                    record_data[start..end].copy_from_slice(data);
                }
            }));
        }

        let mut filter_closure: Option<TimelineEventFilterFn> = None;

        if !filter_closures.is_empty() {
            filter_closure  = Some(Box::new(move |trace| {
                let event_data = trace.data.event_data();

                for closure in &mut filter_closures {
                    if !closure(event_data) {
                        return false;
                    }
                }

                true
            }));
        }

        self.events.push(
            TimelineEvent {
                event,
                id_closure,
                record_closure,
                filter_closure,
                flags,
            });

        Ok(())
    }

    pub fn apply(
        &mut self,
        exporter: &mut UniversalExporterSwapper) -> anyhow::Result<()> {
        if self.events.len() < 2 {
            anyhow::bail!("Timelines must have at least 2 events.");
        }

        let mut has_completes = false;
        let mut has_starts = false;

        for event in &self.events {
            has_completes |= event.flags.will_end();
            has_starts |= event.flags.will_start();
        }

        if !has_completes {
            anyhow::bail!("Timelines must have at least 1 completion event.");
        }

        if !has_starts {
            anyhow::bail!("Timelines must have at least 1 start event.");
        }

        /* Apply closures based on ID size */
        match self.id_size {
            0..=8 => { apply_timeline!(self, exporter, 8); },
            9..=16 => { apply_timeline!(self, exporter, 16); },
            17..=24 => { apply_timeline!(self, exporter, 24); },
            25..=32 => { apply_timeline!(self, exporter, 32); },
            _ => { anyhow::bail!("ID must be 32 bytes or less."); },
        }

        Ok(())
    }
}

pub struct ScriptedUniversalExporter {
    exporter: Writable<UniversalExporterSwapper>,
    engine: ScriptEngine,
}

impl ScriptedUniversalExporter {
    pub fn new(settings: ExportSettings) -> Self {
        let mut engine = ScriptEngine::new();
        let mut swapper = UniversalExporterSwapper::new(settings);

        /*
         * Ensure engine cleanup always runs once exporter drops:
         * We need to do this well ahead of time to ensure if we
         * run a script partially, but some things got registered
         * we will clean them up. A simple scenario of this is
         * registering probes at the start of a script. Then the
         * script hits an error. We still want to cleanup the probes
         * even though errors were hit.
         */
        if let Some(exporter) = swapper.exporter.take() {
            let exporter = exporter.with_export_drop_hook(engine.cleanup_task());

            swapper.exporter.replace(exporter);
        }

        let mut scripted = Self {
            exporter: Writable::new(swapper),
            engine,
        };

        scripted.init();

        scripted
    }

    pub fn export_swapper(&self) -> Writable<UniversalExporterSwapper> {
        self.exporter.clone()
    }

    pub fn enable_os_scripting(&mut self) {
        self.engine.enable_os_scripting();
    }

    fn init(&mut self) {
        info!("Initializing script environment");
        let fn_exporter = self.export_swapper();

        self.rhai_engine().register_fn(
            "with_per_cpu_buffer_bytes",
            move |size: i64| {
                info!("Setting per-CPU buffer size: bytes={}", size);
                fn_exporter.borrow_mut().swap(|exporter| {
                    exporter.with_per_cpu_buffer_bytes(size as usize)
                });
            });

        self.rhai_engine().build_type::<ScriptTimeline>();
        self.rhai_engine().build_type::<TimelineEventFlags>();

        self.rhai_engine().register_fn(
            "new_timeline_event_flags",
            || -> Result<TimelineEventFlags, Box<EvalAltResult>> {
                Ok(TimelineEventFlags::default())
        });

        self.rhai_engine().register_fn(
            "new_timeline",
            |name: String| -> Result<ScriptTimeline, Box<EvalAltResult>> {
                info!("Registered new_timeline: name={}", name);
                Ok(ScriptTimeline {
                    timeline: Writable::new(ExporterTimeline::new(name))
                })
        });

        let fn_exporter = self.export_swapper();

        self.rhai_engine().register_fn(
            "use_timeline",
            move |timeline: ScriptTimeline| -> Result<(), Box<EvalAltResult>> {
                info!("Using timeline");
                timeline.apply(&mut fn_exporter.borrow_mut())
        });

        let fn_exporter = self.export_swapper();

        self.rhai_engine().register_fn(
            "record_event",
            move |event: ScriptEvent| -> Result<(), Box<EvalAltResult>> {
                if let Some(event) = event.to_event() {
                    info!("Recording event: name={}", event.name());
                fn_exporter.borrow_mut().add_event(
                    event,
                    move |built| {
                        built.use_event_for_kind(true);

                        Ok(())
                    },
                    move |trace| {
                        let attributes = trace.default_attributes()?;

                        trace
                            .sample_builder()
                            .with_attributes(attributes)
                            .with_record_all_event_data()
                            .save_value(MetricValue::Count(1))
                    });
            } else {
                return Err("Event has already been used.".into());
            }

            Ok(())
        });

        let fn_exporter = self.export_swapper();

        self.rhai_engine().register_fn(
            "sample_event",
            move |event: ScriptEvent,
                sample_field: String,
                sample_type: String,
                record_data: bool| -> Result<(), Box<EvalAltResult>> {
                info!("Script called sample_event: sample_field={}, sample_type={}, record_data={}", 
                      sample_field, sample_type, record_data);
                if let Some(event) = event.to_event() {
                    let mut get_data = match event.try_get_field_data_closure(&sample_field) {
                        Some(closure) => { closure },
                        None => { return Err(
                            format!(
                                "Field \"{}\" cannot be used for samples.",
                                sample_field).into());
                        },
                    };

                    /* SAFETY: Already accessed the field above */
                    let format = event.format();
                    let field_ref = format.get_field_ref_unchecked(&sample_field);
                    let sample_field = &format.get_field_unchecked(field_ref);

                    let mut get_metric = match MetricValue::try_get_value_closure(
                        &sample_type,
                        &sample_field.type_name) {
                        Some(closure) => { closure },
                        None => { return Err(
                            format!(
                                "Sample type \"{}\" with data type \"{}\" cannot be used.",
                                sample_type,
                                &sample_field.type_name).into());
                        },
                    };

                    fn_exporter.borrow_mut().add_event(
                        event,
                        move |built| {
                            built.use_event_for_kind(record_data);

                            Ok(())
                        },
                        move |trace| {
                            let event_data = trace.data().event_data();
                            let sample_data = get_data(event_data);
                            let sample_value = get_metric(sample_data)?;

                            if record_data {
                                let attributes = trace.default_attributes()?;

                                trace
                                    .sample_builder()
                                    .with_attributes(attributes)
                                    .with_record_all_event_data()
                                    .save_value(sample_value)
                            } else {
                                trace
                                    .sample_builder()
                                    .save_value(sample_value)
                            }
                        });
                } else {
                    return Err("Event has already been used.".into());
                }

                Ok(())
            });
    }

    pub fn rhai_engine(&mut self) -> &mut Engine {
        self.engine.rhai_engine()
    }

    pub fn from_script(
        self,
        script: &str) -> anyhow::Result<UniversalExporter> {
        info!("Starting script execution:\n{}", script);
        
        match self.engine.run(script) {
            Ok(()) => {
                info!("Script execution completed successfully");
            },
            Err(err) => {
                error!("Script execution failed: {:?}", err);
                let mut exporter = self.exporter.borrow_mut().take()?;

                exporter.cleanup();

                return Err(err);
            },
        }

        self.exporter.borrow_mut().take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let scripted = ScriptedUniversalExporter::new(ExportSettings::default());

        let exporter = scripted.from_script("with_per_cpu_buffer_bytes(1234);").expect("Should work");

        assert_eq!(1234, exporter.cpu_buf_bytes());
    }

    #[test]
    fn timeline_events() {
        fn create_event(id: usize) -> Event {
            let mut event = Event::new(id, "Test".into());
            let format = event.format_mut();

            format.add_field(
                EventField::new(
                    "1".into(), "char".into(),
                    LocationType::Static, 0, 1));
            format.add_field(
                EventField::new(
                    "2".into(), "int".into(),
                    LocationType::Static, 0, 4));
            format.add_field(
                EventField::new(
                    "3".into(), "long".into(),
                    LocationType::Static, 0, 8));
            format.add_field(
                EventField::new(
                    "4".into(), "uuid".into(),
                    LocationType::Static, 0, 16));
            format.add_field(
                EventField::new(
                    "5".into(), "uuid".into(),
                    LocationType::Static, 0, 16));

            event
        }

        let mut flags = TimelineEventFlags::default();

        /* Normal, should work */
        let mut timeline = ExporterTimeline::new("Test".into());
        timeline.track_event(create_event(1), &vec!("1", "2"), flags.clone()).unwrap();

        /* Mis-matched key size should fail */
        assert!(timeline.track_event(create_event(1), &vec!("2", "3"), flags.clone()).is_err());

        /* Start/End together should fail */
        let mut timeline = ExporterTimeline::new("Test".into());
        flags.should_start();
        flags.should_end();
        assert!(timeline.track_event(create_event(1), &vec!("1", "2"), flags.clone()).is_err());
        flags.clear();

        /* Not found field should fail */
        let mut timeline = ExporterTimeline::new("Test".into());
        assert!(timeline.track_event(create_event(1), &vec!("NotHere"), flags.clone()).is_err());

        /* Single event should not apply */
        let mut timeline = ExporterTimeline::new("Test".into());
        timeline.track_event(create_event(1), &vec!("1", "2"), flags.clone()).unwrap();

        let scripted = ScriptedUniversalExporter::new(ExportSettings::default());
        let swapper = scripted.export_swapper();
        assert!(timeline.apply(&mut swapper.borrow_mut()).is_err());

        /* Two events should apply */
        let mut timeline = ExporterTimeline::new("Test".into());
        flags.clear();
        flags.should_start();
        timeline.track_event(create_event(1), &vec!("1", "2"), flags.clone()).unwrap();

        flags.clear();
        flags.should_end();
        timeline.track_event(create_event(2), &vec!("1", "2"), flags.clone()).unwrap();

        let scripted = ScriptedUniversalExporter::new(ExportSettings::default());
        let swapper = scripted.export_swapper();
        timeline.apply(&mut swapper.borrow_mut()).unwrap();

        /* IDs over 32-bytes should fail */
        let mut timeline = ExporterTimeline::new("Test".into());
        flags.clear();
        flags.should_start();
        timeline.track_event(create_event(1), &vec!("1", "4", "5"), flags.clone()).unwrap();

        flags.clear();
        flags.should_end();
        timeline.track_event(create_event(2), &vec!("1", "4", "5"), flags.clone()).unwrap();

        let scripted = ScriptedUniversalExporter::new(ExportSettings::default());
        let swapper = scripted.export_swapper();
        assert!(timeline.apply(&mut swapper.borrow_mut()).is_err());
    }
}
