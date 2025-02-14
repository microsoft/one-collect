use crate::event::{Event, EventData};
use crate::etw::Guid;

type PidCallback = Box<dyn Fn(&EventData) -> anyhow::Result<i32>>;

#[derive(Default)]
pub struct EventExtension {
    provider: Guid,
    level: u8,
    keyword: u64,
    soft_pid: Option<PidCallback>,
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

    fn register_soft_pid(
        &mut self,
        callback: impl Fn(&EventData) -> anyhow::Result<i32> + 'static);

    fn soft_pid(
        &self,
        slice: &[u8]) -> Option<i32>;
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

    fn register_soft_pid(
        &mut self,
        callback: impl Fn(&EventData) -> anyhow::Result<i32> + 'static) {
        self.extension_mut().soft_pid = Some(Box::new(callback));
    }

    #[inline(always)]
    fn soft_pid(
        &self,
        slice: &[u8]) -> Option<i32> {
        match &self.extension().soft_pid {
            Some(callback) => {
                let data = EventData::new(
                    slice,
                    slice,
                    self.format());

                match (callback)(&data) {
                    Ok(pid) => { Some(pid) },
                    Err(_) => { None },
                }
            },
            None => { None },
        }
    }
}
