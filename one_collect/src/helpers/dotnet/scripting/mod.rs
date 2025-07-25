// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::helpers::exporting::{
    ScriptedUniversalExporter
};
use crate::helpers::exporting::scripting::UniversalExporterSwapper;
use crate::helpers::exporting::process::MetricValue;
use crate::helpers::dotnet::os::OSDotNetEventFactory;
use crate::event::Event;
use crate::scripting::ScriptEvent;
use crate::Writable;
use crate::Guid;

use crypto::sha1::Sha1;
use crypto::digest::Digest;

use rhai::{CustomType, TypeBuilder, EvalAltResult};

mod runtime;

pub(crate) fn event_full_name(provider_name: &str, guid: Guid, event_name: &str) -> String {
    use std::fmt::Write;

    let mut full = String::new();

    full.push_str(provider_name);
    full.push_str(":{");

    let _ = write!(
        full,
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid.data1, guid.data2, guid.data3,
        guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3],
        guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]);

    full.push_str("}/");
    full.push_str(event_name);

    full
}

pub(crate) fn guid_from_provider(provider_name: &str) -> anyhow::Result<Guid> {
    match provider_name {
        "Microsoft-Windows-DotNETRuntime" => {
            Ok(Guid::from_u128(0xe13c0d23_ccbc_4e12_931b_d9cc2eee27e4))
        },
        "Microsoft-Windows-DotNETRuntimeRundown" => {
            Ok(Guid::from_u128(0xA669021C_C450_4609_A035_5AF59AF4DF18))
        },
        "Microsoft-Windows-DotNETRuntimeStress" => {
            Ok(Guid::from_u128(0xCC2BCBBA_16B6_4cf3_8990_D74C2E8AF500))
        },
        "Microsoft-Windows-DotNETRuntimePrivate" => {
            Ok(Guid::from_u128(0x763FD754_7086_4dfe_95EB_C01A46FAF4CA))
        },
        "Microsoft-DotNETRuntimeMonoProfiler" => {
            Ok(Guid::from_u128(0x7F442D82_0F1D_5155_4B8C_1529EB2E31C2))
        },
        _ => {
            if provider_name.starts_with("{") {
                /* Direct Guid */
                let provider = provider_name
                    .replace("-", "")
                    .replace("{", "")
                    .replace("}", "");

                match u128::from_str_radix(provider.trim(), 16) {
                    Ok(provider) => { Ok(Guid::from_u128(provider)) },
                    Err(_) => { anyhow::bail!("Invalid provider format."); }
                }
            } else {
                /* Event Source */
                let namespace_bytes: [u8; 16] = [
                    0x48, 0x2C, 0x2D, 0xB2,
                    0xC3, 0x90, 0x47, 0xC8,
                    0x87, 0xF8, 0x1A, 0x15,
                    0xBF, 0xC1, 0x30, 0xFB];

                let mut hasher = Sha1::new();

                hasher.input(&namespace_bytes);

                for c in provider_name.to_uppercase().chars() {
                    let c = c as u16;
                    hasher.input(&c.to_be_bytes());
                }

                let mut result: [u8; 20] = [0; 20];

                hasher.result(&mut result);

                let a = u32::from_ne_bytes(result[0..4].try_into()?);
                let b = u16::from_ne_bytes(result[4..6].try_into()?);
                let mut c = u16::from_ne_bytes(result[6..8].try_into()?);

                /* High 4 bits of octet 7 to 5, as per RFC 4122 */
                c = (c & 0x0FFF) | 0x5000;

                Ok(Guid {
                    data1: a,
                    data2: b,
                    data3: c,
                    data4: [
                        result[8], result[9], result[10], result[11],
                        result[12], result[13], result[14], result[15]
                    ]
                })
            }
        }
    }
}

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

impl DotNetScenario {
    fn with_records(&mut self) { self.record = true; }

    fn with_callstacks(&mut self) { self.callstacks = true; }

    fn use_scenario(
        &mut self,
        exporter: &Writable<UniversalExporterSwapper>,
        factory: &Writable<OSDotNetEventFactory>) {
        let mut add_sample = |sample: DotNetSample| {
            let record = sample.record();

            let (event, mut closure) = sample.take();

            exporter.borrow_mut().add_event(
                event,
                move |built| {
                    built.use_event_for_kind(record);

                    Ok(())
                },
                move |trace| {
                    let record_data = trace.data().event_data();

                    let value = closure(record_data)?;

                    let mut sample = trace.sample_builder();

                    if record {
                        sample.with_record_all_event_data();
                    }

                    sample.save_value(value)
                });
        };

        self.add_runtime_samples(&mut factory.borrow_mut(), &mut add_sample);
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

        let fn_exporter = self.export_swapper();

        /* Singleton factory for scripts */
        let factory = Writable::new(
            OSDotNetEventFactory::new(
                move |name, id| { fn_exporter.borrow_mut().new_proxy_event(name, id) }));

        self.rhai_engine().register_fn(
            "new_dotnet_scenario",
            || -> DotNetScenario { DotNetScenario::default() });

        let fn_exporter = self.export_swapper();
        let fn_factory = factory.clone();

        self.rhai_engine().register_fn(
            "use_dotnet_scenario",
            move |mut scenario: DotNetScenario| {
                scenario.use_scenario(
                    &fn_exporter,
                    &fn_factory);
            });

        let fn_factory = factory.clone();

        self.export_swapper().borrow_mut().swap(move |exporter| {
            fn_factory.borrow_mut().hook_to_exporter(exporter)
        });

        let fn_factory = factory.clone();

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

    #[test]
    fn event_full_names() {
        let provider_name = "Microsoft-Windows-DotNETRuntime";
        let guid = guid_from_provider(provider_name).unwrap();
        let full = event_full_name(provider_name, guid, "GCAllocTick");

        assert_eq!("Microsoft-Windows-DotNETRuntime:{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}/GCAllocTick", &full);
    }
}
