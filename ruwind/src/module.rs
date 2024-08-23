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

    pub fn from_parts(
        dev_maj: u32,
        dev_min: u32,
        ino: u64) -> Self {
        Self {
            dev: (dev_maj as u64) << 8 | dev_min as u64,
            ino,
        }
    }

    pub fn dev(&self) -> u64 { self.dev }
    pub fn ino(&self) -> u64 { self.ino }
}

#[cfg(target_os = "linux")]
impl From<&std::fs::Metadata> for ModuleKey {
    fn from(meta: &std::fs::Metadata) -> Self {
        use std::os::linux::fs::MetadataExt;

        Self {
            dev: meta.st_dev(),
            ino: meta.st_ino(),
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

impl CodeSection for Module {
    fn anon(&self) -> bool { self.anon }

    fn rva(
        &self,
        ip: u64) -> u64 {
        (ip - self.start) + self.offset
    }

    fn key(&self) -> ModuleKey { self.key }
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
