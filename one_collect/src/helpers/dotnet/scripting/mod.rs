use crate::helpers::exporting::{
    UniversalExporter,
    ScriptedUniversalExporter
};
use crate::helpers::exporting::process::MetricValue;
use crate::helpers::dotnet::os::OSDotNetEventFactory;
use crate::event::Event;
use crate::scripting::ScriptEvent;
use crate::Writable;

use rhai::{CustomType, TypeBuilder, EvalAltResult};

mod runtime;

pub (crate) struct DotNetSample {
    event: Event,
    sample_value: Box<dyn FnMut(&[u8]) -> anyhow::Result<MetricValue>>,
    record: bool,
}

impl DotNetSample {
    pub fn record(&self) -> bool { self.record }

    pub fn take(self) -> (Event, Box<dyn FnMut(&[u8]) -> anyhow::Result<MetricValue>>) {
        (self.event, self.sample_value)
    }
}

#[derive(Default, Clone)]
pub (crate) struct DotNetEventGroup {
    events: Vec<DotNetEvent>,
    keyword: u64,
    level: u8,
}

impl DotNetEventGroup {
    pub fn events(&self) -> &Vec<DotNetEvent> { &self.events }

    pub fn keyword(&self) -> u64 { self.keyword }

    pub fn level(&self) -> u8 { self.level }

    fn update_keyword(
        &mut self,
        keyword: u64,
        level: u8) {
        self.keyword |= keyword;

        if level > self.level {
            self.level = level;
        }
    }

    fn add(
        &mut self,
        event: DotNetEvent) {
        self.update_keyword(event.keywords, event.level);

        self.events.push(event);
    }
}

#[derive(Default, Clone)]
pub (crate) struct DotNetEvent {
    id: u16,
    keywords: u64,
    level: u8,
}

#[derive(Default, Clone)]
pub (crate) struct DotNetScenario {
    runtime: DotNetEventGroup,
    record: bool,
    callstacks: bool,
}

pub (crate) trait DotNetScenarioOSHooks {
    fn os_use_scenario(
        &mut self,
        exporter: UniversalExporter) -> UniversalExporter;
}

impl DotNetScenario {
    pub fn runtime(&self) -> &DotNetEventGroup { &self.runtime }

    fn with_records(&mut self) { self.record = true; }

    fn with_callstacks(&mut self) { self.callstacks = true; }

    fn use_scenario(
        &mut self,
        exporter: UniversalExporter) -> UniversalExporter {
        self.os_use_scenario(exporter)
    }
}

impl CustomType for DotNetScenario {
    fn build(mut builder: TypeBuilder<Self>) {
        builder
            .with_fn("with_records", Self::with_records)
            .with_fn("with_callstacks", Self::with_callstacks);

        Self::build_runtime(&mut builder);
    }
}

pub trait DotNetScripting {
    fn enable_dotnet_scripting(&mut self);
}

impl DotNetScripting for ScriptedUniversalExporter {
    fn enable_dotnet_scripting(&mut self) {
        self.rhai_engine().build_type::<DotNetScenario>();

        self.rhai_engine().register_fn(
            "new_dotnet_scenario",
            || -> DotNetScenario { DotNetScenario::default() });

        let fn_exporter = self.export_swapper();

        self.rhai_engine().register_fn(
            "use_dotnet_scenario",
            move |mut scenario: DotNetScenario| {
                fn_exporter.borrow_mut().swap(|exporter| {
                    scenario.use_scenario(exporter)
                });
            });

        let fn_exporter = self.export_swapper();

        let factory = Writable::new(
            OSDotNetEventFactory::new(
                move |name| { fn_exporter.borrow_mut().new_proxy_event(name) }));

        let fn_factory = factory.clone();

        self.export_swapper().borrow_mut().swap(move |exporter| {
            factory.borrow_mut().hook_to_exporter(exporter)
        });

        self.rhai_engine().register_fn(
            "event_from_dotnet",
            move |provider_name: String,
            keyword: i64,
            level: i64,
            id: i64,
            name: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            match fn_factory.borrow_mut().new_event(
                &provider_name,
                keyword as u64,
                level as u8,
                id as usize,
                name) {
                Ok(event) => { Ok(event.into()) },
                Err(e) => { Err(format!("{}", e).into()) }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::exporting::ExportSettings;

    #[test]
    fn it_works() {
        let mut exporter = ScriptedUniversalExporter::new(
            ExportSettings::default());

        exporter.enable_dotnet_scripting();

        exporter.from_script(
            "let callstacks = new_dotnet_scenario(); \
            callstacks.with_callstacks();
            callstacks.with_records();
            callstacks.with_exceptions(); \
            callstacks.with_gc_allocs(); \
            callstacks.with_contentions(); \
            use_dotnet_scenario(callstacks); \
            \
            let records = new_dotnet_scenario(); \
            records.with_records(); \
            records.with_gc_times(); \
            records.with_gc_stats(); \
            records.with_gc_segments(); \
            records.with_gc_concurrent_threads(); \
            records.with_gc_finalizers(); \
            records.with_gc_suspends(); \
            records.with_gc_restarts(); \
            records.with_tp_worker_threads(); \
            records.with_tp_worker_thread_adjustments(); \
            records.with_tp_io_threads(); \
            records.with_arm_threads(); \
            records.with_arm_allocs(); \
            use_dotnet_scenario(records);
            \
            let event = event_from_dotnet( \
                \"Microsoft-Windows-DotNETRuntime\", \
                0x8000, 2, 80, \"ExceptionThrown\"); \
            event.append_field(\"Test\", \"u32\", 4); \
            record_event(event);\
            ").unwrap();
    }
}
