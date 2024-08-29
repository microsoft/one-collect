use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Vacant, Occupied};

use twox_hash::XxHash64;

use super::*;
use crate::sharing::*;
use crate::event::*;

mod events;

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
    cpu: u32,
    pid: u32,
    tid: u32,
    time: u64,
    provider: Guid,
    activity: Guid,
}

struct ProviderEvents {
    guid: Guid,
    capture_state: bool,
    level: u8,
    keyword: u64,
    events: HashMap<usize, Vec<Event>, BuildHasherDefault<XxHash64>>,
}

impl ProviderEvents {
    fn new(
        provider: Guid) -> Self {
        Self {
            guid: provider,
            capture_state: false,
            level: 0,
            keyword: 0,
            events: HashMap::default(),
        }
    }

    fn needs_callstacks(&self) -> bool {
        for events in self.events.values() {
            for event in events {
                if !event.has_no_callstack_flag() {
                    return true;
                }
            }
        }

        false
    }

    fn require_capture_state(&mut self) {
        self.capture_state = true;
    }

    fn get_events(
        &self,
        id: usize) -> Option<&Vec<Event>> {
        self.events.get(&id)
    }

    fn get_events_mut(
        &mut self,
        id: usize) -> &mut Vec<Event> {
        self.events.entry(id).or_insert_with(Vec::new)
    }

    fn ensure_level_keyword(
        &mut self,
        level: u8,
        keyword: u64) {
        if level > self.level {
            self.level = level;
        }

        self.keyword |= keyword;
    }

    fn add_event(
        &mut self,
        level: u8,
        keyword: u64,
        event: Event) {
        self.ensure_level_keyword(
            level,
            keyword);

        match self.events.entry(event.id()) {
            Vacant(entry) => {
                entry.insert(vec!(event));
            },
            Occupied(mut entry) => {
                entry.get_mut().push(event);
            },
        }
    }
}

pub struct EtwSession {
    providers: HashMap<Guid, ProviderEvents, BuildHasherDefault<XxHash64>>,

    /* Ancillary data */
    ancillary: Writable<AncillaryData>,
}

const SystemProcessProvider: Guid = Guid::from_u128(0x151f55dc_467d_471f_83b5_5f889d46ff66);
const SYSTEM_PROCESS_KW_GENERAL: u64 = 1u64;
const SYSTEM_PROCESS_KW_LOADER: u64 = 4096u64;

impl EtwSession {
    pub fn new() -> Self {
        Self {
            providers: HashMap::default(),

            /* Ancillary data */
            ancillary: Writable::new(AncillaryData::default()),
        }
    }

    fn get_provider_mut(
        &mut self,
        provider: Guid) -> &mut ProviderEvents {
        self.providers
            .entry(provider)
            .or_insert_with(|| ProviderEvents::new(provider))
    }

    fn event_entry_mut(
        &mut self,
        provider: Guid,
        level: u8,
        keyword: u64,
        id: usize,
        default: impl FnOnce() -> Event) -> &mut Event {
        let provider = self.get_provider_mut(provider);

        provider.ensure_level_keyword(
            level,
            keyword);

        let events = provider.get_events_mut(id);

        if events.is_empty() {
            events.push(default());
        }

        &mut events[0]
    }

    pub fn comm_start_event(&mut self) -> &mut Event {
        let id = 1;

        self.event_entry_mut(
            SystemProcessProvider,
            0,
            SYSTEM_PROCESS_KW_GENERAL,
            id,
            || events::comm(id, "Process::Start"))
    }

    pub fn comm_end_event(&mut self) -> &mut Event {
        let id = 2;

        self.event_entry_mut(
            SystemProcessProvider,
            0,
            SYSTEM_PROCESS_KW_GENERAL,
            id,
            || events::comm(id, "Process::End"))
    }

    pub fn comm_start_capture_event(&mut self) -> &mut Event {
        let id = 3;

        self.get_provider_mut(SystemProcessProvider)
            .require_capture_state();

        self.event_entry_mut(
            SystemProcessProvider,
            0,
            SYSTEM_PROCESS_KW_GENERAL,
            id,
            || events::comm(id, "Process::DCStart"))
    }

    pub fn comm_end_capture_event(&mut self) -> &mut Event {
        let id = 4;

        self.get_provider_mut(SystemProcessProvider)
            .require_capture_state();

        self.event_entry_mut(
            SystemProcessProvider,
            0,
            SYSTEM_PROCESS_KW_GENERAL,
            id,
            || events::comm(id, "Process::DCEnd"))
    }

    pub fn mmap_load_event(&mut self) -> &mut Event {
        let id = 10;

        self.event_entry_mut(
            SystemProcessProvider,
            0,
            SYSTEM_PROCESS_KW_LOADER,
            id,
            || events::mmap(id, "ImageLoad::Load"))
    }

    pub fn mmap_unload_event(&mut self) -> &mut Event {
        let id = 2;

        self.event_entry_mut(
            SystemProcessProvider,
            0,
            SYSTEM_PROCESS_KW_LOADER,
            id,
            || events::mmap(id, "ImageLoad::Unload"))
    }

    pub fn mmap_load_capture_start_event(&mut self) -> &mut Event {
        let id = 3;

        self.get_provider_mut(SystemProcessProvider)
            .require_capture_state();

        self.event_entry_mut(
            SystemProcessProvider,
            0,
            SYSTEM_PROCESS_KW_LOADER,
            id,
            || events::mmap(id, "ImageLoad::DCStart"))
    }

    pub fn mmap_load_capture_end_event(&mut self) -> &mut Event {
        let id = 4;

        self.get_provider_mut(SystemProcessProvider)
            .require_capture_state();

        self.event_entry_mut(
            SystemProcessProvider,
            0,
            SYSTEM_PROCESS_KW_LOADER,
            id,
            || events::mmap(id, "ImageLoad::DCEnd"))
    }

    pub fn ancillary_data(&self) -> ReadOnly<AncillaryData> {
        self.ancillary.read_only()
    }

    pub fn add_event(
        &mut self,
        provider: Guid,
        level: u8,
        keyword: u64,
        event: Event) {
        match self.providers.entry(provider) {
            Vacant(entry) => {
                let mut events = ProviderEvents::new(*entry.key());

                events.add_event(
                    level,
                    keyword,
                    event);

                entry.insert(events);
            },
            Occupied(mut entry) => {
                entry.get_mut().add_event(
                    level,
                    keyword,
                    event);
            }
        }
    }

    pub fn capture_environment(&mut self) {
        /* Placeholder */
    }

    fn build_session_handle(
        &mut self,
        _name: &str) -> anyhow::Result<()> {

        for provider in self.providers.values() {
            println!("Provider: Callstack={}", provider.needs_callstacks());
        }

        Ok(())
    }

    pub fn parse_for_duration(
        &mut self,
        name: &str,
        _duration: std::time::Duration) -> anyhow::Result<()> {
        self.build_session_handle(name)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_events() {
        let id = Guid::from_u128(0x9e814aad_3204_11d2_9a82_006008a86939);

        let mut events = ProviderEvents::new(id);

        events.add_event(0, 0, Event::new(0, "First".into()));
        events.add_event(1, 1, Event::new(1, "Second".into()));
        events.add_event(2, 2, Event::new(2, "Third".into()));

        /* Level should be highest value */
        assert_eq!(2, events.level);

        /* Keyword should be OR'd value */
        assert_eq!(3, events.keyword);

        /* Lookups should work */
        let found = events.get_events(0).unwrap();
        assert_eq!(1, found.len());
        assert_eq!(0, found[0].id());

        let found = events.get_events(1).unwrap();
        assert_eq!(1, found.len());
        assert_eq!(1, found[0].id());

        let found = events.get_events(2).unwrap();
        assert_eq!(1, found.len());
        assert_eq!(2, found[0].id());

        /* Should return None if not found */
        assert!(events.get_events(3).is_none());
    }

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
                println!("mmap_load_captue_start_event");
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
            "one_collect::unit_test",
            std::time::Duration::from_secs(5)).unwrap();
    }
}
