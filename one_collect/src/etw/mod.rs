use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Vacant, Occupied};

use twox_hash::XxHash64;

use super::*;
use crate::sharing::*;
use crate::event::*;

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
    level: u8,
    keyword: u64,
    events: HashMap<usize, Vec<Event>, BuildHasherDefault<XxHash64>>,
}

impl ProviderEvents {
    fn new(
        provider: Guid) -> Self {
        Self {
            guid: provider,
            level: 0,
            keyword: 0,
            events: HashMap::default(),
        }
    }

    fn get_events(
        &self,
        id: usize) -> Option<&Vec<Event>> {
        self.events.get(&id)
    }

    fn add_event(
        &mut self,
        level: u8,
        keyword: u64,
        event: Event) {
        if level > self.level {
            self.level = level;
        }

        self.keyword |= keyword;

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
}

impl EtwSession {
    pub fn new() -> Self {
        Self {
            providers: HashMap::default(),
        }
    }

    pub fn add_event(
        &mut self,
        provider: Guid,
        level: u8,
        keyword: u64,
        event: Event) -> anyhow::Result<()> {
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

        Ok(())
    }

    pub fn parse_for_duration(
        &mut self,
        duration: std::time::Duration) -> anyhow::Result<()> {
        todo!()
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

    #[test]
    fn session() {
    }
}
