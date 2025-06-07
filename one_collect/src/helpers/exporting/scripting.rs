// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::scripting::{ScriptEngine, ScriptEvent};

use rhai::{Engine, EvalAltResult};

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
