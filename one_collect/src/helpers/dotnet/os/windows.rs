use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::helpers::dotnet::*;
use crate::helpers::dotnet::universal::UniversalDotNetHelperOSHooks;

#[cfg(feature = "scripting")]
use crate::helpers::dotnet::scripting::{DotNetScenario, DotNetScenarioOSHooks};
#[cfg(feature = "scripting")]
use crate::helpers::exporting::UniversalExporter;

use crate::helpers::exporting::symbols::*;

use crate::ReadOnly;
use crate::event::*;
use crate::event::os::windows::WindowsEventExtension;

use crate::etw::{Guid, EtwSession, AncillaryData};

pub(crate) struct OSDotNetHelper {
    jit_symbols: bool,
}

impl OSDotNetHelper {
    pub fn new() -> Self {
        Self {
            jit_symbols: false,
        }
    }
}

pub trait DotNetHelperWindowsExt {
    fn with_jit_symbols(self) -> Self;
}

impl DotNetHelperWindowsExt for DotNetHelper {
    fn with_jit_symbols(mut self) -> Self {
        self.os.jit_symbols = true;

        self
    }
}

#[cfg(all(target_os = "windows", feature = "scripting"))]
impl DotNetScenarioOSHooks for DotNetScenario {
    fn os_use_scenario(
        &mut self,
        exporter: UniversalExporter) -> UniversalExporter {
        exporter
    }
}

#[cfg(target_os = "windows")]
impl UniversalDotNetHelperOSHooks for DotNetHelper {
    fn os_with_dynamic_symbols(self) -> Self {
        self.with_jit_symbols()
    }

    fn os_cleanup_dynamic_symbols(&mut self) {
        /* Placeholder */
    }
}

const CLR_RUNTIME_PROVIDER: Guid = Guid::from_u128(0xe13c0d23_ccbc_4e12_931b_d9cc2eee27e4);

const CLR_RUNDOWN_PROVIDER: Guid = Guid::from_u128(0xa669021c_c450_4609_a035_5af59af4df18);

const JIT_KEYWORD: u64 = 0x10;

const END_ENUM_KEYWORD: u64 = 0x80;

const END_RUNDOWN_KEYWORD: u64 = 0x100;

fn clr_method_event(
    id: usize,
    name: String,
    provider: Guid,
    keywords: u64) -> Event {

    let mut event = Event::for_etw(
        id,
        name,
        provider,
        5, /* Verbose */
        keywords);

    event.set_no_callstack_flag();

    let mut len: usize;
    let mut offset: usize = 0;
    let format = event.format_mut();

    len = 8;
    format.add_field(EventField::new(
        "MethodID".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ModuleID".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "MethodStartAddress".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
    format.add_field(EventField::new(
        "MethodSize".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "MethodToken".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "MethodFlags".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 0;
    format.add_field(EventField::new(
        "MethodNameSpace".into(), "wchar".into(),
        LocationType::StaticUTF16String, offset, len));

    format.add_field(EventField::new(
        "MethodName".into(), "wchar".into(),
        LocationType::StaticUTF16String, offset, len));

    format.add_field(EventField::new(
        "MethodSignature".into(), "wchar".into(),
        LocationType::StaticUTF16String, offset, len));

    format.add_field(EventField::new(
        "ClrInstanceID".into(), "u16".into(),
        LocationType::Static, offset, len));

    event
}

fn append_unicode(
    buffer: &mut String,
    bytes: &[u8]) {
    for chunk in bytes.chunks_exact(2) {
        /* SAFETY: Exactly 2 bytes */
        let c = u16::from_ne_bytes(chunk[0..2].try_into().unwrap());

        if let Some(c) = char::from_u32(c as u32) {
            buffer.push(c);
        } else {
            buffer.push('?');
        }
    }
}

fn hook_method_load(
    event: &mut Event,
    helper: &mut DotNetHelper,
    ancillary: ReadOnly<AncillaryData>,
    match_only: bool) {
    let jit_symbol_hooks = helper.jit_symbol_hooks.clone();
    let fmt = event.format();
    let start = fmt.get_field_ref_unchecked("MethodStartAddress");
    let size = fmt.get_field_ref_unchecked("MethodSize");
    let dynamic = fmt.get_field_ref_unchecked("MethodNameSpace");
    let mut buffer = String::new();

    event.add_callback(move |data| {
        let fmt = data.format();
        let data = data.event_data();
        let ancillary = ancillary.borrow();

        let start = fmt.get_u64(start, data)?;
        let size = fmt.get_u32(size, data)? as u64;

        if size == 0 {
            anyhow::bail!("Zero sized symbol");
        }

        let namespace = fmt.get_data(dynamic, data);
        let name = fmt.get_data_with_offset(dynamic, data, namespace.len() + 2);

        buffer.clear();
        append_unicode(&mut buffer, namespace);
        buffer.push('.');
        append_unicode(&mut buffer, name);

        let mut symbol = DynamicSymbol::new(
            ancillary.time(),
            ancillary.pid(),
            start,
            start + size - 1,
            &buffer);

        if match_only {
            symbol.set_flag(SYM_FLAG_MUST_MATCH);
        }

        for hook in jit_symbol_hooks.borrow_mut().iter_mut() {
            hook(&symbol);
        }

        Ok(())
    });
}

impl DotNetHelp for EtwSession {
    fn with_dotnet_help(
        mut self,
        helper: &mut DotNetHelper) -> Self {
        if helper.os.jit_symbols {
            /* Hook runtime method events */
            let mut new_method_event = clr_method_event(
                143,
                "MethodLoadVerbose".into(),
                CLR_RUNTIME_PROVIDER,
                JIT_KEYWORD | END_ENUM_KEYWORD);

            hook_method_load(
                &mut new_method_event,
                helper,
                self.ancillary_data(),
                false);

            self.add_event(
                new_method_event,
                None);

            let mut unload_method_event = clr_method_event(
                144,
                "MethodUnloadVerbose".into(),
                CLR_RUNTIME_PROVIDER,
                JIT_KEYWORD | END_ENUM_KEYWORD);

            hook_method_load(
                &mut unload_method_event,
                helper,
                self.ancillary_data(),
                true);

            self.add_event(
                unload_method_event,
                None);

            /* Hook rundown method events */
            let mut existing_method_event = clr_method_event(
                144,
                "MethodDCEndVerbose".into(),
                CLR_RUNDOWN_PROVIDER,
                JIT_KEYWORD | END_RUNDOWN_KEYWORD);

            hook_method_load(
                &mut existing_method_event,
                helper,
                self.ancillary_data(),
                true);

            let rundown_count = Arc::new(AtomicUsize::new(0));
            let callback_count = rundown_count.clone();

            /* Increment when we get an existing method event */
            existing_method_event.add_callback(move |_data| {
                callback_count.fetch_add(1, Ordering::Relaxed);

                Ok(())
            });

            /* Wait for method events to stop flowing */
            self.add_rundown_callback(move |context| {
                let sec = std::time::Duration::from_secs(1);
                let max_secs = 5;

                /* Wait for at least 1 unload method event */
                for _ in 0..max_secs {
                    if rundown_count.load(Ordering::Relaxed) != 0 {
                        break;
                    }

                    std::thread::sleep(sec);
                }

                if rundown_count.load(Ordering::Relaxed) == 0 {
                    return;
                }

                /* Wait for the unload method events to stop */
                let max_secs = 30;

                for _ in 0..max_secs {
                    let before = rundown_count.load(Ordering::Relaxed);

                    std::thread::sleep(sec);
                    context.flush_trace();

                    let after = rundown_count.load(Ordering::Relaxed);

                    if before == after {
                        /* Double check */
                        std::thread::sleep(sec);
                        context.flush_trace();

                        let after = rundown_count.load(Ordering::Relaxed);

                        /* Assume no more if 2 seconds goes by */
                        if before == after {
                            break;
                        }
                    }
                }
            });

            self.add_rundown_event(existing_method_event, None);
        }

        self
    }
}
