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
    completes: bool,
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
        completes: bool) -> Result<(), Box<EvalAltResult>> {
        match self.timeline.borrow_mut().track_event(
            event.to_event().ok_or("Event has already been used.")?,
            fields,
            completes)
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
        completes: bool) -> Result<(), Box<EvalAltResult>> {
        let mut fields = Vec::new();
        fields.push(id_field.as_str());

        self.with_event(event, &fields, completes)
    }

    pub fn with_event_two(
        &mut self,
        event: ScriptEvent,
        id_field_one: String,
        id_field_two: String,
        completes: bool) -> Result<(), Box<EvalAltResult>> {
        let mut fields = Vec::new();
        fields.push(id_field_one.as_str());
        fields.push(id_field_two.as_str());

        self.with_event(event, &fields, completes)
    }

    pub fn with_event_three(
        &mut self,
        event: ScriptEvent,
        id_field_one: String,
        id_field_two: String,
        id_field_three: String,
        completes: bool) -> Result<(), Box<EvalAltResult>> {
        let mut fields = Vec::new();
        fields.push(id_field_one.as_str());
        fields.push(id_field_two.as_str());
        fields.push(id_field_three.as_str());

        self.with_event(event, &fields, completes)
    }

    pub fn with_event_four(
        &mut self,
        event: ScriptEvent,
        id_field_one: String,
        id_field_two: String,
        id_field_three: String,
        id_field_four: String,
        completes: bool) -> Result<(), Box<EvalAltResult>> {
        let mut fields = Vec::new();
        fields.push(id_field_one.as_str());
        fields.push(id_field_two.as_str());
        fields.push(id_field_three.as_str());
        fields.push(id_field_four.as_str());

        self.with_event(event, &fields, completes)
    }
}

macro_rules! apply_timeline {
    ($self:expr, $exporter:expr, $size:expr) => {
        struct TimelineValues {
            pid: u32,
            tid: u32,
            time: u64,
        }

        /* TODO: When spans are available, store each time step */
        let map: HashMap<[u8; $size], TimelineValues> = HashMap::new();
        let map = Writable::new(map);

        let min_duration = $self.min_duration.clone();

        /* TODO: Allow spans to flush once available */
        for mut event in $self.events.drain(..) {
            let fn_map = map.clone();

            if event.completes {
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
                        if let Some(values) = map.remove(&id) {
                            let duration = trace.time()? - values.time;

                            if duration >= *qpc_min.borrow() {
                                trace.add_pid_sample(
                                    values.pid,
                                    values.tid,
                                    MetricValue::Duration(duration))?;
                            }
                        }

                        Ok(())
                    });
            } else {
                $exporter.add_event(
                    event.event,
                    move |_built| {
                        Ok(())
                    },
                    move |trace| {
                        let mut map = fn_map.borrow_mut();
                        let mut id: [u8; $size] = [0; $size];

                        (event.id_closure)(trace, &mut id);

                        let values = TimelineValues {
                            pid: trace.pid()?,
                            tid: trace.tid()?,
                            time: trace.time()?,
                        };

                        /* First non-complete event sets values */
                        map.entry(id).or_insert(values);

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
        completes: bool) -> anyhow::Result<()> {
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
                completes,
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

        for event in &self.events {
            if event.completes {
                has_completes = true;
                break;
            }
        }

        if !has_completes {
            anyhow::bail!("Timelines must have at least 1 completion event.");
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
}
