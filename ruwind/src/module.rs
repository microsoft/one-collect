use std::cmp::Ordering;
use super::*;

impl ModuleKey {
    pub fn new(
        dev: u64,
        ino: u64) -> Self {
        Self {
            dev,
            ino,
        }
    }
}

impl Clone for ModuleKey {
    fn clone(&self) -> Self {
        Self {
            dev: self.dev,
            ino: self.ino,
        }
    }
}

impl PartialEq for ModuleKey {
    fn eq(&self, other: &Self) -> bool {
        self.dev == other.dev &&
        self.ino == other.ino
    }
}

impl Module {
    pub fn new(
        start: u64,
        end: u64,
        offset: u64,
        dev: u64,
        ino: u64) -> Self {
        Self {
            start,
            end,
            offset,
            key: ModuleKey::new(
                dev,
                ino),
            anon: false,
        }
    }

    pub fn new_anon(
        start: u64,
        end: u64) -> Self {
        Self {
            start,
            end,
            offset: 0,
            key: ModuleKey::new(
                0,
                0),
            anon: true,
        }
    }
}

impl Ord for Module {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start.cmp(&other.start)
    }
}

impl PartialOrd for Module {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Module {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}
