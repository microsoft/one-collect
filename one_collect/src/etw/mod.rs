use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::collections::HashMap;
use std::thread::{self};

use twox_hash::XxHash64;

use crate::sharing::*;
use crate::event::*;

#[allow(dead_code)]
mod abi;
mod events;

use abi::{
    TraceSession,
    TraceEnable,
    EVENT_RECORD,
    EVENT_HEADER_EXTENDED_DATA_ITEM
};

pub const PROPERTY_ENABLE_KEYWORD_0: u32 = abi::EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0;
pub const PROPERTY_ENABLE_SILOS: u32 = abi::EVENT_ENABLE_PROPERTY_ENABLE_SILOS;
pub const PROPERTY_EVENT_KEY: u32 = abi::EVENT_ENABLE_PROPERTY_EVENT_KEY;
pub const PROPERTY_EXCLUDE_INPRIVATE: u32 = abi::EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE;
pub const PROPERTY_IGNORE_KEYWORD_0: u32 = abi::EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0;
pub const PROPERTY_PROCESS_START_KEY: u32 = abi::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY;
pub const PROPERTY_PROVIDER_GROUP: u32 = abi::EVENT_ENABLE_PROPERTY_PROVIDER_GROUP;
pub const PROPERTY_PSM_KEY: u32 = abi::EVENT_ENABLE_PROPERTY_PSM_KEY;
pub const PROPERTY_SID: u32 = abi::EVENT_ENABLE_PROPERTY_SID;
pub const PROPERTY_SOURCE_CONTAINER_TRACKING: u32 = abi::EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING;
pub const PROPERTY_STACK_TRACE: u32 = abi::EVENT_ENABLE_PROPERTY_STACK_TRACE;
pub const PROPERTY_TS_ID: u32 = abi::EVENT_ENABLE_PROPERTY_TS_ID;

pub const LEVEL_CRITICAL: u8 = abi::TRACE_LEVEL_CRITICAL;
pub const LEVEL_ERROR: u8 = abi::TRACE_LEVEL_ERROR;
pub const LEVEL_WARNING: u8 = abi::TRACE_LEVEL_WARNING;
pub const LEVEL_INFORMATION: u8 = abi::TRACE_LEVEL_INFORMATION;
pub const LEVEL_VERBOSE: u8 = abi::TRACE_LEVEL_VERBOSE;

pub const DISABLE_PROVIDER: u32 = abi::EVENT_CONTROL_CODE_DISABLE_PROVIDER;
pub const ENABLE_PROVIDER: u32 = abi::EVENT_CONTROL_CODE_ENABLE_PROVIDER;
pub const CAPTURE_STATE: u32 = abi::EVENT_CONTROL_CODE_CAPTURE_STATE;

#[repr(C)]
#[derive(Default, Eq, PartialEq, Copy, Clone)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Hash for Guid {
    fn hash<H: Hasher>(
        &self,
        state: &mut H) {
        state.write_u32(self.data1);
        state.write_u16(self.data2);
        state.write_u16(self.data3);
    }
}

impl Guid {
    pub const fn from_u128(uuid: u128) -> Self {
        Self {
            data1: (uuid >> 96) as u32,
            data2: (uuid >> 80 & 0xffff) as u16,
            data3: (uuid >> 64 & 0xffff) as u16,
            data4: (uuid as u64).to_be_bytes()
        }
    }
}

#[derive(Default)]
pub struct AncillaryData {
    event: Option<*const EVENT_RECORD>,
}

impl AncillaryData {
    pub fn cpu(&self) -> u32 {
        match self.event {
            Some(event) => {
                unsafe { (*event).ProcessorIndex as u32 }
            },
            None => { 0 },
        }
    }

    pub fn pid(&self) -> u32 {
        match self.event {
            Some(event) => {
                unsafe { (*event).EventHeader.ProcessId }
            },
            None => { 0 },
        }
    }

    pub fn tid(&self) -> u32 {
        match self.event {
            Some(event) => {
                unsafe { (*event).EventHeader.ThreadId }
            },
            None => { 0 },
        }
    }

    pub fn time(&self) -> u64 {
        match self.event {
            Some(event) => {
                unsafe { (*event).EventHeader.TimeStamp }
            },
            None => { 0 },
        }
    }

    pub fn provider(&self) -> Guid {
        match self.event {
            Some(event) => {
                unsafe { (*event).EventHeader.ProviderId }
            },
            None => { Guid::default() },
        }
    }

    pub fn activity(&self) -> Guid {
        match self.event {
            Some(event) => {
                unsafe { (*event).EventHeader.ActivityId }
            },
            None => { Guid::default() },
        }
    }

    pub fn callstack(
        &self,
        frames: &mut Vec<u64>,
        match_id: &mut u64) -> bool {
        if let Some(ext) = self.find_ext(
            abi::EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
            unsafe {
                let ext_size = (*ext).DataSize as usize;
                if ext_size < 8 {
                    return false;
                }

                let frame_count = (ext_size - 8) / 8;
                let ext_frames = (*ext).DataPtr as *const u64;
                *match_id = *ext_frames;

                /* Skip MatchId */
                let ext_frames = ext_frames.add(1);

                for i in 0..frame_count {
                    frames.push(*ext_frames.add(i));
                }

                return true;
            }
        } else if let Some(ext) = self.find_ext(
            abi::EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
            unsafe {
                let ext_size = (*ext).DataSize as usize;
                if ext_size < 8 {
                    return false;
                }

                let frame_count = (ext_size - 8) / 4;
                let ext_frames = (*ext).DataPtr as *const u64;
                *match_id = *ext_frames;

                /* Skip MatchId */
                let ext_frames = ext_frames.add(1) as *const u32;

                for i in 0..frame_count {
                    frames.push(*ext_frames.add(i) as u64);
                }

                return true;
            }
        }

        false
    }

    fn find_ext(
        &self,
        ext_type: u32) -> Option<*const EVENT_HEADER_EXTENDED_DATA_ITEM> {
        match self.event {
            Some(event) => {
                unsafe {
                    let ext = (*event).ExtendedData;

                    for i in 0..(*event).ExtendedDataCount as usize {
                        let item = ext.add(i);

                        if (*item).ExtType == ext_type as u16 {
                            return Some(item);
                        }
                    }

                    None
                }
            },
            None => { None},
        }
    }
}

type ProviderLookup = HashMap<Guid, ProviderEvents, BuildHasherDefault<XxHash64>>;
type EventLookup = HashMap<usize, Vec<Event>, BuildHasherDefault<XxHash64>>;

struct ProviderEvents {
    use_op_id: bool,
    events: EventLookup,
}

impl ProviderEvents {
    fn new() -> Self {
        Self {
            use_op_id: false,
            events: HashMap::default(),
        }
    }

    fn use_op_id(&self) -> bool { self.use_op_id }

    fn use_op_id_mut(&mut self) -> &mut bool { &mut self.use_op_id }

    fn get_events_mut(
        &mut self,
        id: usize) -> &mut Vec<Event> {
        self.events.entry(id).or_insert_with(Vec::new)
    }

    fn get_events_mut_if_exist(
        &mut self,
        id: usize) -> Option<&mut Vec<Event>> {
        self.events.get_mut(&id)
    }
}

pub struct SessionCallbackContext {
    handle: u64,
}

impl SessionCallbackContext {
    fn new(handle: u64) -> Self {
        SessionCallbackContext {
            handle,
        }
    }
}

type SendClosure = Box<dyn Fn(&SessionCallbackContext) + Send + 'static>;

pub struct EtwSession {
    enabled: HashMap<Guid, TraceEnable>,
    providers: ProviderLookup,

    /* Callbacks */
    event_error_callback: Option<Box<dyn Fn(&Event, &anyhow::Error)>>,
    starting_callbacks: Option<Vec<SendClosure>>,
    started_callbacks: Option<Vec<SendClosure>>,
    stopping_callbacks: Option<Vec<SendClosure>>,
    stopped_callbacks: Option<Vec<SendClosure>>,

    /* Ancillary data */
    ancillary: Writable<AncillaryData>,

    /* Flags */
    elevate: bool,
    profile_interval: Option<u32>,
}

const SYSTEM_PROCESS_PROVIDER: Guid = Guid::from_u128(0x151f55dc_467d_471f_83b5_5f889d46ff66);
const REAL_SYSTEM_PROCESS_PROVIDER: Guid = Guid::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
const REAL_SYSTEM_IMAGE_PROVIDER: Guid = Guid::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518);

const SYSTEM_PROCESS_KW_GENERAL: u64 = 1u64;
const SYSTEM_PROCESS_KW_LOADER: u64 = 4096u64;

const SYSTEM_PROFILE_PROVIDER: Guid = Guid::from_u128(0xbfeb0324_1cee_496f_a409_2ac2b48a6322);
const REAL_SYSTEM_PROFILE_PROVIDER: Guid = Guid::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc);

const SYSTEM_PROFILE_KW_GENERAL: u64 = 1u64;

const SYSTEM_INTERRUPT_PROVIDER: Guid = Guid::from_u128(0xd4bbee17_b545_4888_858b_744169015b25);
const REAL_SYSTEM_INTERRUPT_PROVIDER: Guid = Guid::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc);

const SYSTEM_INTERRUPT_KW_DPC: u64 = 4u64;

impl EtwSession {
    pub fn new() -> Self {
        Self {
            enabled: HashMap::default(),
            providers: HashMap::default(),

            /* Callbacks */
            event_error_callback: None,
            starting_callbacks: Some(Vec::new()),
            started_callbacks: Some(Vec::new()),
            stopping_callbacks: Some(Vec::new()),
            stopped_callbacks: Some(Vec::new()),

            /* Ancillary data */
            ancillary: Writable::new(AncillaryData::default()),

            /* Flags */
            elevate: false,
            profile_interval: None,
        }
    }

    pub fn set_event_error_callback(
        &mut self,
        callback: impl Fn(&Event, &anyhow::Error) + 'static) {
        self.event_error_callback = Some(Box::new(callback));
    }

    pub fn add_starting_callback(
        &mut self,
        callback: impl Fn(&SessionCallbackContext) + Send + 'static) {
        if let Some(callbacks) = self.starting_callbacks.as_mut() {
            callbacks.push(Box::new(callback));
        }
    }

    pub fn add_started_callback(
        &mut self,
        callback: impl Fn(&SessionCallbackContext) + Send + 'static) {
        if let Some(callbacks) = self.started_callbacks.as_mut() {
            callbacks.push(Box::new(callback));
        }
    }

    pub fn add_stopping_callback(
        &mut self,
        callback: impl Fn(&SessionCallbackContext) + Send + 'static) {
        if let Some(callbacks) = self.stopping_callbacks.as_mut() {
            callbacks.push(Box::new(callback));
        }
    }

    pub fn add_stopped_callback(
        &mut self,
        callback: impl Fn(&SessionCallbackContext) + Send + 'static) {
        if let Some(callbacks) = self.stopped_callbacks.as_mut() {
            callbacks.push(Box::new(callback));
        }
    }

    pub fn requires_profile_interval(
        &mut self,
        interval_ms: u32) {
        self.profile_interval = Some(interval_ms);
    }

    pub fn requires_elevation(&mut self) {
        self.elevate = true;
    }

    pub fn enable_provider(
        &mut self,
        provider: Guid) -> &mut TraceEnable {
        self.enabled
            .entry(provider)
            .or_insert_with(|| TraceEnable::new(provider))
    }

    pub fn enable_provider_for(
        &mut self,
        event: &Event) -> &mut TraceEnable {
        self.enable_provider(*event.extension().provider())
    }

    fn provider_events_mut(
        &mut self,
        provider: Guid,
        lookup_provider: Option<Guid>,
        ensure_provider: impl FnOnce(&mut TraceEnable),
        id: usize) -> &mut Vec<Event> {
        ensure_provider(self.enable_provider(provider));

        let mut use_op_id = false;

        let provider = match lookup_provider {
            Some(alt_provider) => {
                use_op_id = true;
                alt_provider
            },
            None => { provider },
        };

        let events = self
            .providers
            .entry(provider)
            .or_insert_with(|| ProviderEvents::new());

        *events.use_op_id_mut() = use_op_id;

        events.get_events_mut(id)
    }

    pub fn add_event(
        &mut self,
        event: Event,
        properties: Option<u32>) {
        let provider = *event.extension().provider();
        let level = event.extension().level();
        let keyword = event.extension().keyword();

        self.add_complex_event(
            provider,
            |provider| {
                provider.ensure_level(level);
                provider.ensure_keyword(keyword);

                if let Some(properties) = properties {
                    provider.ensure_property(properties);
                }
            },
            event);
    }

    pub fn add_complex_event(
        &mut self,
        provider: Guid,
        ensure_provider: impl FnOnce(&mut TraceEnable),
        event: Event) {
        let mut lookup_provider = None;
        let actual_provider = *event.extension().provider();

        if provider != actual_provider {
            lookup_provider = Some(actual_provider);
        }

        let events = self.provider_events_mut(
            provider,
            lookup_provider,
            ensure_provider,
            event.id());

        events.push(event);
    }

    fn enable_singleton_event(
        &mut self,
        provider: Guid,
        lookup_provider: Option<Guid>,
        ensure_provider: impl FnOnce(&mut TraceEnable),
        id: usize,
        default_event: impl FnOnce(usize) -> Event) -> &mut Event {
        let events = self.provider_events_mut(
            provider,
            lookup_provider,
            ensure_provider,
            id);

        if events.is_empty() {
            events.push(default_event(id));
        }

        &mut events[0]
    }

    pub fn comm_start_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_PROCESS_PROVIDER,
            Some(REAL_SYSTEM_PROCESS_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_capture_environment();
                provider.ensure_keyword(SYSTEM_PROCESS_KW_GENERAL);
            },
            1,
            |id| events::comm(id, "Process::Start"))
    }

    pub fn comm_end_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_PROCESS_PROVIDER,
            Some(REAL_SYSTEM_PROCESS_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_capture_environment();
                provider.ensure_keyword(SYSTEM_PROCESS_KW_GENERAL);
            },
            2,
            |id| events::comm(id, "Process::End"))
    }

    pub fn comm_start_capture_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_PROCESS_PROVIDER,
            Some(REAL_SYSTEM_PROCESS_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_capture_environment();
                provider.ensure_keyword(SYSTEM_PROCESS_KW_GENERAL);
            },
            3,
            |id| events::comm(id, "Process::DCStart"))
    }

    pub fn comm_end_capture_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_PROCESS_PROVIDER,
            Some(REAL_SYSTEM_PROCESS_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_capture_environment();
                provider.ensure_keyword(SYSTEM_PROCESS_KW_GENERAL);
            },
            4,
            |id| events::comm(id, "Process::DCEnd"))
    }

    pub fn mmap_load_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_PROCESS_PROVIDER,
            Some(REAL_SYSTEM_IMAGE_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_capture_environment();
                provider.ensure_keyword(SYSTEM_PROCESS_KW_LOADER);
            },
            10,
            |id| events::mmap(id, "ImageLoad::Load"))
    }

    pub fn mmap_unload_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_PROCESS_PROVIDER,
            Some(REAL_SYSTEM_IMAGE_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_capture_environment();
                provider.ensure_keyword(SYSTEM_PROCESS_KW_LOADER);
            },
            2,
            |id| events::mmap(id, "ImageLoad::Unload"))
    }

    pub fn mmap_load_capture_start_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_PROCESS_PROVIDER,
            Some(REAL_SYSTEM_IMAGE_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_capture_environment();
                provider.ensure_keyword(SYSTEM_PROCESS_KW_LOADER);
            },
            3,
            |id| events::mmap(id, "ImageLoad::DCStart"))
    }

    pub fn mmap_load_capture_end_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_PROCESS_PROVIDER,
            Some(REAL_SYSTEM_IMAGE_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_capture_environment();
                provider.ensure_keyword(SYSTEM_PROCESS_KW_LOADER);
            },
            4,
            |id| events::mmap(id, "ImageLoad::DCEnd"))
    }

    pub fn profile_cpu_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_PROFILE_PROVIDER,
            Some(REAL_SYSTEM_PROFILE_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_keyword(SYSTEM_PROFILE_KW_GENERAL);
            },
            46,
            |id| events::sample_profile(id, "Profile::SampleProfile"))
    }

    pub fn dpc_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_INTERRUPT_PROVIDER,
            Some(REAL_SYSTEM_INTERRUPT_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_keyword(SYSTEM_INTERRUPT_KW_DPC);
            },
            68,
            |id| events::dpc(id, "Profile::DPC"))
    }

    pub fn threaded_dpc_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_INTERRUPT_PROVIDER,
            Some(REAL_SYSTEM_INTERRUPT_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_keyword(SYSTEM_INTERRUPT_KW_DPC);
            },
            66,
            |id| events::dpc(id, "Profile::ThreadDPC"))
    }

    pub fn timer_dpc_event(&mut self) -> &mut Event {
        self.requires_elevation();

        self.enable_singleton_event(
            SYSTEM_INTERRUPT_PROVIDER,
            Some(REAL_SYSTEM_INTERRUPT_PROVIDER),
            |provider| {
                provider.ensure_no_filtering();
                provider.ensure_keyword(SYSTEM_INTERRUPT_KW_DPC);
            },
            69,
            |id| events::dpc(id, "Profile::TimerDPC"))
    }

    pub fn ancillary_data(&self) -> ReadOnly<AncillaryData> {
        self.ancillary.read_only()
    }

    pub fn capture_environment(&mut self) {
        /* Placeholder */
    }

    pub fn parse_for_duration(
        self,
        name: &str,
        duration: std::time::Duration) -> anyhow::Result<()> {

        self.parse_until(
            name,
            move || std::thread::sleep(duration))
    }

    fn take_enabled(
        &mut self) -> HashMap<Guid, TraceEnable> {
        let mut map = HashMap::default();

        for (k,v) in self.enabled.drain() {
            map.insert(k, v);
        }

        map
    }

    fn take_events(
        &mut self) -> ProviderLookup {
        let mut map = HashMap::default();

        for (k,v) in self.providers.drain() {
            map.insert(k, v);
        }

        map
    }

    pub fn parse_until(
        mut self,
        name: &str,
        until: impl FnOnce() + Send + 'static) -> anyhow::Result<()> {
        let mut session = TraceSession::new(name.into());

        if self.elevate {
            session.enable_privilege("SeDebugPrivilege");
            session.enable_privilege("SeSystemProfilePrivilege");
        }

        if let Some(interval) = self.profile_interval {
            session.set_profile_interval(interval)?;
        }

        session.start()?;
        
        let handle = session.handle();

        let enabled = self.take_enabled();
        let mut events = self.take_events();

        let starting_callbacks = self.starting_callbacks.take();
        let started_callbacks = self.started_callbacks.take();
        let stopping_callbacks = self.stopping_callbacks.take();
        let stopped_callbacks = self.stopped_callbacks.take();

        let thread = thread::spawn(move || -> anyhow::Result<()> {
            let context = SessionCallbackContext::new(handle);

            /* Enable capture environments first */
            for enable in enabled.values() {
                if enable.needs_capture_environment() {
                    let result = enable.enable(handle);

                    if result.is_err() {
                        TraceSession::remote_stop(handle);
                        return result;
                    }
                }
            }

            /* Run starting hooks */
            if let Some(callbacks) = starting_callbacks {
                for callback in callbacks {
                    callback(&context);
                }
            }

            /* Enable non-capture environments next */
            for enable in enabled.values() {
                if !enable.needs_capture_environment() {
                    let result = enable.enable(handle);

                    if result.is_err() {
                        TraceSession::remote_stop(handle);
                        return result;
                    }
                }
            }

            /* Run started hooks */
            if let Some(callbacks) = started_callbacks {
                for callback in callbacks {
                    callback(&context);
                }
            }

            /* Run until told to stop */
            until();

            /* Disable providers */
            for enable in enabled.values() {
                let _ = enable.disable(handle);
            }

            /* Run stopping hooks */
            if let Some(callbacks) = stopping_callbacks {
                for callback in callbacks {
                    callback(&context);
                }
            }

            TraceSession::remote_stop(handle);

            /* Run stopped hooks */
            if let Some(callbacks) = stopped_callbacks {
                for callback in callbacks {
                    callback(&context);
                }
            }

            Ok(())
        });

        let ancillary = self.ancillary.clone();
        let error_callback = self.event_error_callback.take();
        let mut errors = Vec::new();

        let result = session.process(Box::new(move |event| {
            /* Find events by provider ID */
            if let Some(events) = events.get_mut(&event.EventHeader.ProviderId) {
                /* Determine which ID for lookup */
                let id: usize = match events.use_op_id() {
                    true => { event.EventHeader.EventDescriptor.Opcode.into() },
                    false => { event.EventHeader.EventDescriptor.Id.into() },
                };

                /* Find any registered closures for the event */
                if let Some(events) = events.get_events_mut_if_exist(id) {
                    /* Update ancillary data */
                    ancillary.borrow_mut().event = Some(event);

                    /* Process Event Data via Closures */
                    let slice = event.user_data_slice();

                    for event in events {
                        errors.clear();

                        event.process(
                            slice,
                            slice,
                            &mut errors);

                        /* Log errors, if any */
                        for error in &errors {
                            if let Some(callback) = &error_callback {
                                callback(event, error);
                            } else {
                                eprintln!("Error: Event '{}': {}", event.name(), error);
                            }
                        }
                    }

                    /* Clear ancillary data */
                    ancillary.borrow_mut().event = None;
                }
            }
        }));

        if result.is_err() {
            return result;
        }

        thread.join().unwrap()?;

        session.stop();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn session() {
        let mut session = EtwSession::new();

        session.comm_start_capture_event().add_callback(
            move |_data| {
                println!("comm_start_capture_event");
                Ok(())
            });

        session.mmap_load_capture_start_event().add_callback(
            move |_data| {
                println!("mmap_load_capture_start_event");
                Ok(())
            });

        session.comm_start_event().add_callback(
            move |_data| {
                println!("comm_start_event");
                Ok(())
            });

        session.mmap_load_event().add_callback(
            move |_data| {
                println!("mmap_load_event");
                Ok(())
            });

        session.comm_end_event().add_callback(
            move |_data| {
                println!("comm_end_event");
                Ok(())
            });

        session.mmap_unload_event().add_callback(
            move |_data| {
                println!("mmap_unload_event");
                Ok(())
            });

        session.parse_for_duration(
            "one_collect_unit_test",
            std::time::Duration::from_secs(10)).unwrap();
    }
}
