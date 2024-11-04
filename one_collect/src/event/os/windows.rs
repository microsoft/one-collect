use crate::event::Event;
use crate::etw::Guid;

#[derive(Default)]
pub struct EventExtension {
    provider: Guid,
    level: u8,
    keyword: u64,
}

impl EventExtension {
    pub fn provider(&self) -> &Guid {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut Guid {
        &mut self.provider
    }

    pub fn level(&self) -> u8 { self.level }

    pub fn level_mut(&mut self) -> &mut u8 { &mut self.level }

    pub fn keyword(&self) -> u64 { self.keyword }

    pub fn keyword_mut(&mut self) -> &mut u64 { &mut self.keyword }
}

pub trait WindowsEventExtension {
    fn for_etw(
        id: usize,
        name: String,
        provider: Guid,
        level: u8,
        keyword: u64) -> Event;
}

impl WindowsEventExtension for Event {
    fn for_etw(
        id: usize,
        name: String,
        provider: Guid,
        level: u8,
        keyword: u64) -> Event {
        let mut event = Event::new(id, name);
        let ext = event.extension_mut();

        *ext.provider_mut() = provider;
        *ext.level_mut() = level;
        *ext.keyword_mut() = keyword;

        event
    }
}
