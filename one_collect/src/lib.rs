// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#![doc = include_str!("../README.md")]

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

    pub fn to_bytes(&self) -> [u8; 16] {
        unsafe { std::mem::transmute(*self) }
    }

    /// Derive a GUID from a namespace and a name by hashing `namespace ++ name`
    /// with SHA-1 and laying the digest into the GUID fields (RFC 4122 v5 style).
    ///
    /// Only the version nibble is set (to 5); the variant bits are deliberately
    /// left untouched so the output stays byte-identical to the pre-existing
    /// `helpers::dotnet::provider::guid_from_provider` algorithm. This means the
    /// result is *not* a strictly conformant v5 UUID.
    ///
    /// Callers choose the byte encoding of `name` (UTF-8 for ETW session names,
    /// uppercase UTF-16BE for `EventSource` provider names).
    pub fn v5_from_name(namespace: &[u8], name: &[u8]) -> Self {
        use sha1::{Sha1, Digest};

        let mut hasher = Sha1::new();
        hasher.update(namespace);
        hasher.update(name);
        let result = hasher.finalize();

        let a = u32::from_ne_bytes([result[0], result[1], result[2], result[3]]);
        let b = u16::from_ne_bytes([result[4], result[5]]);
        let mut c = u16::from_ne_bytes([result[6], result[7]]);

        /* High 4 bits of octet 7 to 5, as per RFC 4122 */
        c = (c & 0x0FFF) | 0x5000;

        Self {
            data1: a,
            data2: b,
            data3: c,
            data4: [
                result[8], result[9], result[10], result[11],
                result[12], result[13], result[14], result[15],
            ],
        }
    }

}

/// Derive the ETW control GUID of a self-describing (EventSource /
/// TraceLogging) provider from its *name*.
///
/// Unlike manifest / classic providers (whose GUID must be looked up in the
/// OS provider database), a self-describing provider's GUID is a deterministic
/// hash of its name: the name is upper-cased, encoded as UTF-16BE, and
/// v5-hashed over the fixed 16-byte `EventSource` namespace.
///
/// This is a pure name-hash function. It does not parse `{GUID}` literals;
/// caller policy decides whether input should be treated as a literal GUID or
/// hashed as a provider name.
pub fn guid_from_provider_name_hash(name: &str) -> Guid {
    // The fixed namespace `EventSource` uses to hash provider names.
    const EVENTSOURCE_NAMESPACE: [u8; 16] = [
        0x48, 0x2C, 0x2D, 0xB2,
        0xC3, 0x90, 0x47, 0xC8,
        0x87, 0xF8, 0x1A, 0x15,
        0xBF, 0xC1, 0x30, 0xFB,
    ];

    // `EventSource` encodes the upper-cased name as UTF-16BE.
    // Avoid allocating an intermediate upper-cased String; encode directly.
    let mut name_bytes = Vec::with_capacity(name.len() * 2);
    for c in name.chars() {
        for upper in c.to_uppercase() {
            let mut utf16 = [0u16; 2];
            for unit in upper.encode_utf16(&mut utf16).iter().copied() {
                name_bytes.extend_from_slice(&unit.to_be_bytes());
            }
        }
    }

    Guid::v5_from_name(&EVENTSOURCE_NAMESPACE, &name_bytes)
}

pub mod event;
pub mod sharing;
pub mod helpers;
pub mod intern;
pub mod os;

mod ruwind;

/// Public types from the stack unwinding implementation that appear in
/// `one_collect`'s public API.
pub mod unwind {
    pub use crate::ruwind::{ModuleKey, UnwindType};
    pub use crate::ruwind::elf::ElfLoadHeader;
}

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

const fn page_size_to_mask(page_size: u64) -> u64 {
    !((page_size - 1) as u64)
}

pub fn io_error(message: &str) -> IOError {
    IOError::new(
        std::io::ErrorKind::Other,
        message)
}

#[cfg(test)]
mod tests {
    use super::{Guid, guid_from_provider_name_hash};

    const NS: &[u8] = b"one_collect test namespace";

    #[test]
    fn v5_from_name_is_deterministic() {
        assert_eq!(
            Guid::v5_from_name(NS, b"record-trace").to_bytes(),
            Guid::v5_from_name(NS, b"record-trace").to_bytes());
    }

    #[test]
    fn v5_from_name_distinct_names_distinct_guids() {
        assert_ne!(
            Guid::v5_from_name(NS, b"session-a").to_bytes(),
            Guid::v5_from_name(NS, b"session-b").to_bytes());
    }

    #[test]
    fn v5_from_name_distinct_namespaces_distinct_guids() {
        assert_ne!(
            Guid::v5_from_name(b"namespace-a", b"same-name").to_bytes(),
            Guid::v5_from_name(b"namespace-b", b"same-name").to_bytes());
    }

    #[test]
    fn v5_from_name_sets_version_nibble_to_5() {
        let guid = Guid::v5_from_name(NS, b"record-trace");
        assert_eq!(guid.data3 & 0xF000, 0x5000);
    }

    /// Ground-truth vector for the EventSource name-hash, independently
    /// computed (SHA-1 over the fixed EventSource namespace + upper-cased
    /// UTF-16BE name, version nibble forced to 5, fields read native-endian as
    /// `v5_from_name` does).  Locks the namespace seed and encoding.
    #[test]
    fn guid_from_provider_name_hash_matches_known_vector() {
        assert_eq!(
            guid_from_provider_name_hash("OneCollect-Test-Provider").to_bytes(),
            Guid::from_u128(0xB03CBD70_B6F7_5552_04A1_A17A1FE5F1A4).to_bytes());
    }

    #[test]
    fn guid_from_provider_name_hash_is_case_insensitive() {
        // The convention upper-cases before hashing, so casing is irrelevant.
        assert_eq!(
            guid_from_provider_name_hash("onecollect-test-provider").to_bytes(),
            guid_from_provider_name_hash("OneCollect-Test-Provider").to_bytes());
    }
}

