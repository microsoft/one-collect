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
