// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! # Registered ETW provider enumeration
//!
//! This module wraps the Windows Trace Data Helper (TDH)
//! `TdhEnumerateProviders` API to enumerate every provider registered in the
//! system provider database, returning a case-insensitive
//! `lowercased-name -> RegisteredProvider` map.
//!
//! The database is enumerated in a single pass, so resolving N provider names
//! costs one `TdhEnumerateProviders` call rather than N.  Both manifest-based
//! providers (`SchemaSource == 0`) and classic MOF providers
//! (`SchemaSource == 1`) are included.

use std::collections::HashMap;

use crate::Guid;

use windows_sys::Win32::System::Diagnostics::Etw::{
    PROVIDER_ENUMERATION_INFO, TRACE_PROVIDER_INFO, TdhEnumerateProviders,
};

/// A provider found in the OS-registered provider database.
#[derive(Clone, Copy)]
pub struct RegisteredProvider {
    /// Control GUID of the registered provider.
    pub guid: Guid,
    /// TDH schema source: `0` = XML manifest, `1` = classic WMI/MOF.  Retained
    /// so callers can report which decoding model a matched provider uses.
    pub schema_source: u32,
}

/// Convert a Win32 `GUID` (from `windows-sys`) into a [`Guid`].
///
/// Both types are `#[repr(C)]` with identical `data1/2/3/4` fields, so this is
/// a straight field copy.
fn win32_guid_to_guid(g: &windows_sys::core::GUID) -> Guid {
    Guid {
        data1: g.data1,
        data2: g.data2,
        data3: g.data3,
        data4: g.data4,
    }
}

/// Enumerate every provider registered in the system provider database via the
/// Windows TDH `TdhEnumerateProviders` API, returning a case-insensitive
/// `lowercased-name -> RegisteredProvider` map.
///
/// The whole database is read **once**; callers should memoize the result so
/// resolving N configured names costs a single enumeration rather than N.
/// Includes both manifest-based providers (`SchemaSource == 0`) and classic MOF
/// providers (`SchemaSource == 1`).  On a duplicate name the first entry wins.
///
/// # Errors
///
/// Returns an error only when the TDH API itself fails unexpectedly, so a
/// genuine lookup miss is never silently misresolved.
#[allow(unsafe_code)]
pub fn registered_providers() -> anyhow::Result<HashMap<String, RegisteredProvider>> {
    const ERROR_SUCCESS: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    // First call with a null buffer to discover the required size.
    let mut buffer_size: u32 = 0;
    // SAFETY: The documented size-probe form; TDH writes only through
    // `p_buffer_size` when the buffer pointer is null.
    let status = unsafe { TdhEnumerateProviders(std::ptr::null_mut(), &mut buffer_size) };
    if status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS {
        anyhow::bail!("TdhEnumerateProviders (size probe) failed with Win32 error {status}");
    }
    if (buffer_size as usize) < std::mem::size_of::<PROVIDER_ENUMERATION_INFO>() {
        // Empty or header-less result: nothing to enumerate.
        return Ok(HashMap::new());
    }

    // Allocate a `u32`-aligned buffer: `PROVIDER_ENUMERATION_INFO` and
    // `TRACE_PROVIDER_INFO` both have 4-byte alignment (`u32` / `GUID` fields),
    // which a `Vec<u32>` satisfies. `Vec<u8>` would only be byte-aligned, which
    // is undefined behaviour to reinterpret as these structs.
    let elem_count = (buffer_size as usize).div_ceil(std::mem::size_of::<u32>());
    let mut buffer: Vec<u32> = vec![0u32; elem_count];
    let byte_len = buffer.len() * std::mem::size_of::<u32>();

    // SAFETY: `buffer` is at least `buffer_size` bytes and 4-byte aligned; TDH
    // fills it with a `PROVIDER_ENUMERATION_INFO` header followed by the
    // provider array.
    let status = unsafe {
        TdhEnumerateProviders(
            buffer.as_mut_ptr() as *mut PROVIDER_ENUMERATION_INFO,
            &mut buffer_size,
        )
    };
    if status != ERROR_SUCCESS {
        // A second `ERROR_INSUFFICIENT_BUFFER` can happen if providers were
        // registered between the two calls; treat any non-success as a lookup
        // failure so we never read a partially populated buffer.
        anyhow::bail!("TdhEnumerateProviders (fill) failed with Win32 error {status}");
    }

    // Byte view for reading UTF-16 provider names by their buffer offset.
    // SAFETY: `buffer` owns `byte_len` valid, initialized bytes.
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, byte_len) };

    // SAFETY: the buffer starts with a valid `PROVIDER_ENUMERATION_INFO`
    // (guaranteed at least header-sized above) and is 4-byte aligned.
    let header = unsafe { &*(buffer.as_ptr() as *const PROVIDER_ENUMERATION_INFO) };
    let count = header.NumberOfProviders as usize;

    // Defensive bound: the provider array must fit within the buffer TDH
    // reported. `count` comes from the OS-populated header; clamp it to what
    // the buffer can actually hold so the `array_ptr.add(i)` reads below stay
    // in-bounds even if the header and buffer size were ever inconsistent.
    let array_offset = std::mem::size_of::<PROVIDER_ENUMERATION_INFO>()
        .saturating_sub(std::mem::size_of::<TRACE_PROVIDER_INFO>());
    let max_entries =
        byte_len.saturating_sub(array_offset) / std::mem::size_of::<TRACE_PROVIDER_INFO>();
    let count = count.min(max_entries);

    // Base pointer of the trailing flexible `TRACE_PROVIDER_INFO` array. The
    // binding types it as `[_; 1]`; take a raw pointer to the field and index
    // from it rather than materializing an out-of-bounds `&[_; 1]`. Forming a
    // raw pointer to a place is safe; the later dereferences below are not.
    let array_ptr = (&raw const header.TraceProviderInfoArray).cast::<TRACE_PROVIDER_INFO>();

    let mut map: HashMap<String, RegisteredProvider> = HashMap::with_capacity(count);
    for i in 0..count {
        // SAFETY: `i < count == NumberOfProviders`, so element `i` lies within
        // the buffer TDH populated.
        let info = unsafe { &*array_ptr.add(i) };
        let name_offset = info.ProviderNameOffset as usize;
        // A zero or out-of-range offset means the entry has no usable name.
        if name_offset == 0 || name_offset >= byte_len {
            continue;
        }
        // Skip empty names: a `ProviderNameOffset` that points straight at a
        // UTF-16 NUL decodes to `""`, which would otherwise insert a bogus
        // empty-key lookup target from a malformed/partial TDH entry.
        let Some(provider_name) = read_utf16z(bytes, name_offset).filter(|s| !s.is_empty()) else {
            continue;
        };
        let provider = RegisteredProvider {
            guid: win32_guid_to_guid(&info.ProviderGuid),
            schema_source: info.SchemaSource,
        };
        // First entry wins on duplicate names.
        let _ = map
            .entry(provider_name.to_ascii_lowercase())
            .or_insert(provider);
    }

    Ok(map)
}

/// Read a null-terminated UTF-16 (little-endian) string starting at
/// `byte_offset` within `bytes`, stopping at the terminator or the end of the
/// buffer. Returns `None` if the offset leaves no room for even one code unit.
fn read_utf16z(bytes: &[u8], byte_offset: usize) -> Option<String> {
    if byte_offset + 1 >= bytes.len() {
        return None;
    }
    let mut units = Vec::new();
    let mut i = byte_offset;
    while i + 1 < bytes.len() {
        let unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        i += 2;
    }
    Some(String::from_utf16_lossy(&units))
}

/// Resolve a self-describing (EventSource / TraceLogging) provider *name* to
/// its ETW control GUID.
///
/// Where [`registered_providers`] answers "which GUID is *registered* for this
/// name?" by consulting the OS provider database, this answers the complement:
/// self-describing providers are **not** registered — their control GUID is a
/// deterministic hash of the name.  Together the two cover name → GUID
/// resolution for every provider model, letting a caller pick a GUID and hand
/// it to `EtwSession::enable_provider`.
///
/// Accepts either:
/// * a literal `{GUID}` string (returned as-is after parsing), or
/// * a provider name, hashed via the EventSource convention (see
///   [`Guid::from_eventsource_name`], the shared source of truth for the
///   namespace seed and encoding).
///
/// # Errors
///
/// Returns an error only when a `{...}` literal is not valid GUID hex.  A plain
/// name never fails: it always hashes to some GUID.
pub fn guid_from_tracelogging_name(provider_name: &str) -> anyhow::Result<Guid> {
    if provider_name.starts_with('{') {
        // Direct `{GUID}` literal: strip braces/dashes and parse the hex.
        let hex = provider_name.replace(['-', '{', '}'], "");
        return u128::from_str_radix(hex.trim(), 16)
            .map(Guid::from_u128)
            .map_err(|_| anyhow::anyhow!("invalid provider GUID literal: {provider_name}"));
    }

    // Self-describing provider: name-hash to the control GUID.
    Ok(Guid::from_eventsource_name(provider_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground-truth vector for the EventSource name-hash, independently
    /// computed (SHA-1 over the fixed namespace + upper-cased UTF-16BE name,
    /// version nibble forced to 5, fields read little-endian as
    /// `Guid::v5_from_name` does).  Locks the namespace seed + encoding so a
    /// drift in either is caught here.
    const KNOWN_NAME: &str = "OneCollect-Test-Provider";
    const KNOWN_GUID: u128 = 0xB03CBD70_B6F7_5552_04A1_A17A1FE5F1A4;

    #[test]
    fn tracelogging_name_hashes_to_known_guid() {
        let guid = guid_from_tracelogging_name(KNOWN_NAME).unwrap();
        assert_eq!(guid.to_bytes(), Guid::from_u128(KNOWN_GUID).to_bytes());
    }

    #[test]
    fn tracelogging_name_is_case_insensitive() {
        // The convention upper-cases before hashing, so any casing of the same
        // name resolves to the same GUID.
        let upper = guid_from_tracelogging_name(&KNOWN_NAME.to_uppercase()).unwrap();
        let lower = guid_from_tracelogging_name(&KNOWN_NAME.to_lowercase()).unwrap();
        assert_eq!(upper.to_bytes(), Guid::from_u128(KNOWN_GUID).to_bytes());
        assert_eq!(lower.to_bytes(), Guid::from_u128(KNOWN_GUID).to_bytes());
    }

    #[test]
    fn tracelogging_guid_literal_is_parsed_verbatim() {
        // A `{GUID}` literal is parsed directly, not hashed.
        let guid = guid_from_tracelogging_name(
            "{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}",
        )
        .unwrap();
        assert_eq!(
            guid.to_bytes(),
            Guid::from_u128(0xE13C0D23_CCBC_4E12_931B_D9CC2EEE27E4).to_bytes());
    }

    #[test]
    fn tracelogging_invalid_guid_literal_errors() {
        // A `{...}` that isn't valid hex is a real error, not a silent hash.
        assert!(guid_from_tracelogging_name("{not-a-guid}").is_err());
    }
}