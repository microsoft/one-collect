// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
use std::hash::{Hash, Hasher};

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

pub mod event;
pub mod sharing;
pub mod helpers;
pub mod intern;
pub mod os;

#[cfg(any(doc, target_os = "linux"))]
pub mod tracefs;
#[cfg(any(doc, target_os = "linux"))]
pub mod procfs;
#[cfg(any(doc, target_os = "linux"))]
pub mod perf_event;
#[cfg(any(doc, target_os = "linux"))]
pub mod openat;
#[cfg(any(doc, target_os = "linux"))]
pub mod user_events;

#[cfg(any(doc, target_os = "windows"))]
pub mod etw;

#[cfg(feature = "scripting")]
pub mod scripting;

pub use sharing::{Writable, ReadOnly};

pub mod pathbuf_ext;
pub use pathbuf_ext::{PathBufInteger};

pub type IOResult<T> = std::io::Result<T>;
pub type IOError = std::io::Error;

fn page_size_to_mask(page_size: u64) -> u64 {
    !((page_size - 1) as u64)
}

pub fn io_error(message: &str) -> IOError {
    IOError::new(
        std::io::ErrorKind::Other,
        message)
}
