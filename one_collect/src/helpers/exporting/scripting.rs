use super::*;
use crate::scripting::ScriptEngine;

use rhai::Engine;

pub struct UniversalExporterSwapper {
    exporter: Option<UniversalExporter>,
}

impl UniversalExporterSwapper {
    pub fn new(settings: ExportSettings) -> Self {
        Self {
            exporter: Some(UniversalExporter::new(settings)),
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

    fn init(&mut self) {
        let fn_exporter = self.export_swapper();

        self.rhai_engine().register_fn(
            "with_per_cpu_buffer_bytes",
            move |size: i64| {
                fn_exporter.borrow_mut().swap(|exporter| {
                    exporter.with_per_cpu_buffer_bytes(size as usize)
                });
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
