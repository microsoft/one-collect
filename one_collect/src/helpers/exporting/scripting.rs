// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::scripting::{ScriptEngine, ScriptEvent};
use crate::event::*;

use rhai::{CustomType, TypeBuilder, Engine, EvalAltResult};

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
        name: String) -> Option<Event> {
        if let Some(exporter) = self.exporter.as_mut() {
            if let Some(settings) = exporter.settings_mut() {
                return Some(settings.new_proxy_event(name));
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

struct TimelineEvent {
    event: Event,
    id_closure: Box<dyn FnMut(&ExportTraceContext, &mut [u8])>,
    flags: TimelineEventFlags,
}

#[derive(Default, Clone)]
pub struct TimelineEventFlags {
    flags: u8,
}

impl CustomType for TimelineEventFlags {
    fn build(mut builder: TypeBuilder<Self>) {
        builder
            .with_fn("should_start", Self::should_start)
            .with_fn("should_end", Self::should_end)
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

    pub fn clear(&mut self) { self.flags = Self::TIMELINE_EVENT_FLAG_NONE; }
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

        for mut event in $self.events.drain(..) {
            let fn_map = map.clone();

            if event.flags.will_end() {
                let name = $self.name.clone();

                let qpc_min = Writable::new(0u64);
                let set_qpc_min = qpc_min.clone();

                $exporter.add_event(
                    event.event,
                    move |built| {
                        built.set_sample_kind(&name);

                        /* Calculate QPC min duration if any */
                        if let Some(min_duration) = min_duration {
                            *set_qpc_min.borrow_mut() = built.duration_to_qpc(min_duration);
                        }

                        Ok(())
                    },
                    move |trace| {
                        let mut map = fn_map.borrow_mut();
                        let mut id: [u8; $size] = [0; $size];

                        (event.id_closure)(trace, &mut id);

                        /* First complete event flushes duration */
                        if let Some(mut values) = map.remove(&id) {
                            let time = trace.time()?;

                            values.span.mark_last_child_end(time);
                            values.span.mark_end(time);

                            if values.span.qpc_duration() >= *qpc_min.borrow() {
                                let value = trace.add_span(values.span)?;

                                trace.add_pid_sample(
                                    values.pid,
                                    values.tid,
                                    value)?;
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

                        (event.id_closure)(trace, &mut id);

                        let pid = trace.pid()?;
                        let tid = trace.tid()?;
                        let time = trace.time()?;

                        if will_start {
                            /* First will_start event sets pid/tid values */
                            let values = map.entry(id).or_insert_with(|| {
                                TimelineValues {
                                    span: ExportSpan::start(
                                        context.timeline_name_id,
                                        time,
                                        capacity),
                                    pid,
                                    tid,
                                }});

                            /* Add new child, ending last child if any */
                            values.span.mark_last_child_end(time);

                            values.span.add_child(
                                ExportSpan::start(
                                    context.name_id,
                                    time,
                                    0));
                        } else if let Some(values) = map.get_mut(&id) {
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
}

impl ExporterTimeline {
    pub fn new(name: String) -> Self {
        Self {
            name,
            events: Vec::new(),
            id_size: 0,
            min_duration: None,
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
            anyhow::bail!("Event cannot both start and end, check flags.");
        }

        let mut id_closures = Vec::new();

        if id_fields.is_empty() {
            anyhow::bail!("Event must have an ID field.");
        }

        let mut total_id_size = 0;

        for name in id_fields {
            match event.try_get_field_data_closure(name) {
                Some(closure) => { id_closures.push(closure); },
                None => { anyhow::bail!("Unable to get ID from \"{}\".", name); },
            }

            /* SAFETY: Already accessed above */
            let format = event.format();
            let field_ref = format.get_field_ref_unchecked(name);
            let field = format.get_field_unchecked(field_ref);

            /* Ensure static/known size */
            if field.size == 0 ||
               field.location == LocationType::DynRelative ||
               field.location == LocationType::DynAbsolute {
                anyhow::bail!("Field \"{}\", must be static size for ID.", name);
            }

            /* Add up */
            total_id_size += field.size;
        }

        /* Ensure they are the same as the others */
        if self.events.is_empty() {
            self.id_size = total_id_size;
        } else if self.id_size != total_id_size {
            anyhow::bail!(
                "Previous ID was {} bytes, Event \"{}\" ID is {} bytes.",
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

        self.events.push(
            TimelineEvent {
                event,
                id_closure,
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
        let mut scripted = Self {
            exporter: Writable::new(UniversalExporterSwapper::new(settings)),
            engine: ScriptEngine::new(),
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
        let fn_exporter = self.export_swapper();

        self.rhai_engine().register_fn(
            "with_per_cpu_buffer_bytes",
            move |size: i64| {
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
            Ok(ScriptTimeline {
                timeline: Writable::new(ExporterTimeline::new(name))
                })
        });

        let fn_exporter = self.export_swapper();

        self.rhai_engine().register_fn(
            "use_timeline",
            move |timeline: ScriptTimeline| -> Result<(), Box<EvalAltResult>> {
            timeline.apply(&mut fn_exporter.borrow_mut())
        });

        let fn_exporter = self.export_swapper();

        self.rhai_engine().register_fn(
            "record_event",
            move |event: ScriptEvent| -> Result<(), Box<EvalAltResult>> {
            if let Some(event) = event.to_event() {
                fn_exporter.borrow_mut().add_event(
                    event,
                    move |built| {
                        built.use_event_for_kind(true);

                        Ok(())
                    },
                    move |trace| {
                        let event_data = trace.data().event_data();

                        trace.add_sample_with_event_data(
                            MetricValue::Count(1),
                            0..event_data.len())
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
                                trace.add_sample_with_event_data(
                                    sample_value,
                                    0..event_data.len())
                            } else {
                                trace.add_sample(sample_value)
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
        self.engine.run(script)?;

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
