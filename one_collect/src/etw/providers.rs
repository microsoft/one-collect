// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! # Registered ETW provider enumeration
//!
//! This module wraps the Windows Trace Data Helper (TDH)
//! `TdhEnumerateProviders` API to visit every provider registered in the
//! system provider database, invoking a caller-supplied closure with each
//! provider's name and [`RegisteredProvider`] details.
//!
//! The database is enumerated in a single pass, so the closure sees every
//! provider from one `TdhEnumerateProviders` call. The caller decides what to
//! keep (e.g. matching a configured set of names) and can stop early by
//! returning [`ControlFlow::Break`], so no full map is ever materialized.
//! Both manifest-based providers (`SchemaSource == 0`) and classic MOF
//! providers (`SchemaSource == 1`) are visited.

use std::ops::ControlFlow;

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

/// Visit every provider registered in the system provider database via the
/// Windows TDH `TdhEnumerateProviders` API, calling `f` with each provider's
/// name and [`RegisteredProvider`] details.
///
/// The whole database is read in a **single** enumeration pass; `f` is invoked
/// once per provider in enumeration order. Provider names are passed in
/// Unicode lowercase (`str::to_lowercase`) for case-insensitive matching. The
/// caller decides what to keep and may stop
/// early by returning [`ControlFlow::Break`] (e.g. once every configured name
/// has been found), avoiding a full-map allocation. Both manifest-based
/// providers (`SchemaSource == 0`) and classic MOF providers
/// (`SchemaSource == 1`) are visited. Duplicate names are visited in
/// enumeration order, so a caller building a map keeps the first entry per name.
///
/// # Errors
///
/// Returns an error only when the TDH API itself fails unexpectedly, so a
/// genuine lookup miss is never silently misresolved.
#[allow(unsafe_code)]
pub fn for_each_registered_provider(
    mut f: impl FnMut(&str, RegisteredProvider) -> ControlFlow<()>,
) -> anyhow::Result<()> {
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
        return Ok(());
    }

    // Fill call with a bounded retry: providers can be registered between
    // probe and fill, causing one transient `ERROR_INSUFFICIENT_BUFFER`.
    let mut retries_remaining = 1u8;
    let final_bytes: Vec<u8> = loop {
        // Allocate a `u32`-aligned buffer: `PROVIDER_ENUMERATION_INFO` and
        // `TRACE_PROVIDER_INFO` both have 4-byte alignment (`u32` / `GUID`
        // fields), which a `Vec<u32>` satisfies.
        let elem_count = (buffer_size as usize).div_ceil(std::mem::size_of::<u32>());
        let mut buffer: Vec<u32> = vec![0u32; elem_count];
        let alloc_byte_len = buffer.len() * std::mem::size_of::<u32>();

        // SAFETY: `buffer` is writable and 4-byte aligned; TDH writes at most
        // `query_size` bytes and updates it with the required/used size.
        let mut query_size = buffer_size;
        let status = unsafe {
            TdhEnumerateProviders(
                buffer.as_mut_ptr() as *mut PROVIDER_ENUMERATION_INFO,
                &mut query_size,
            )
        };

        if status == ERROR_SUCCESS {
            let used_byte_len = query_size as usize;
            if used_byte_len > alloc_byte_len {
                anyhow::bail!(
                    "TdhEnumerateProviders returned size {used_byte_len} larger than allocation {alloc_byte_len}"
                );
            }
            // Parse only the byte count returned by TDH, not the full
            // allocation length.
            // SAFETY: `buffer` owns `alloc_byte_len` valid bytes; `used_byte_len`
            // is range-checked above.
            let used = unsafe {
                std::slice::from_raw_parts(buffer.as_ptr() as *const u8, used_byte_len)
            };
            break used.to_vec();
        }

        if status == ERROR_INSUFFICIENT_BUFFER && retries_remaining > 0 {
            retries_remaining -= 1;
            // Use TDH's returned required size when available.
            if query_size > buffer_size {
                buffer_size = query_size;
            }
            continue;
        }

        anyhow::bail!("TdhEnumerateProviders (fill) failed with Win32 error {status}");
    };

    for_each_provider_in_buffer(&final_bytes, &mut f)?;

    Ok(())
}

#[allow(unsafe_code)]
fn for_each_provider_in_buffer(
    bytes: &[u8],
    f: &mut impl FnMut(&str, RegisteredProvider) -> ControlFlow<()>,
) -> anyhow::Result<()> {
    if bytes.len() < std::mem::size_of::<PROVIDER_ENUMERATION_INFO>() {
        return Ok(());
    }

    let array_offset = std::mem::size_of::<PROVIDER_ENUMERATION_INFO>()
        .saturating_sub(std::mem::size_of::<TRACE_PROVIDER_INFO>());
    let max_entries =
        bytes.len().saturating_sub(array_offset) / std::mem::size_of::<TRACE_PROVIDER_INFO>();

    // SAFETY: We checked the slice is large enough for a header-sized read and
    // use `read_unaligned` to avoid alignment assumptions.
    let header: PROVIDER_ENUMERATION_INFO =
        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const PROVIDER_ENUMERATION_INFO) };
    let count = (header.NumberOfProviders as usize).min(max_entries);

    for i in 0..count {
        let entry_offset = array_offset + i * std::mem::size_of::<TRACE_PROVIDER_INFO>();
        if entry_offset + std::mem::size_of::<TRACE_PROVIDER_INFO>() > bytes.len() {
            break;
        }
        // SAFETY: Bounds checked above; `read_unaligned` avoids alignment
        // assumptions for the borrowed byte slice.
        let info: TRACE_PROVIDER_INFO = unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(entry_offset) as *const TRACE_PROVIDER_INFO)
        };

        let name_offset = info.ProviderNameOffset as usize;
        // A zero or out-of-range offset means the entry has no usable name.
        if name_offset == 0 || name_offset >= bytes.len() {
            continue;
        }

        // Skip empty names: a `ProviderNameOffset` that points straight at a
        // UTF-16 NUL decodes to `""`, which would otherwise hand the caller a
        // bogus empty-key lookup target from a malformed/partial TDH entry.
        let Some(provider_name) = read_utf16z(bytes, name_offset).filter(|s| !s.is_empty()) else {
            continue;
        };

        let provider = RegisteredProvider {
            guid: win32_guid_to_guid(&info.ProviderGuid),
            schema_source: info.SchemaSource,
        };

        // Use Unicode lowercase for case-insensitive matching semantics.
        if f(&provider_name.to_lowercase(), provider).is_break() {
            break;
        }
    }

    Ok(())
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
/// Where [`for_each_registered_provider`] answers "which GUID is *registered* for this
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
/// Returns an error only when a `{...}` literal is not valid GUID hex. A plain
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

    use windows_sys::core::GUID;

    fn write_utf16z(buf: &mut Vec<u8>, s: &str) -> u32 {
        let off = buf.len() as u32;
        for u in s.encode_utf16() {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes());
        off
    }

    #[allow(unsafe_code)]
    fn make_provider_enum_buffer(entries: &[(GUID, u32, Option<u32>)], names: &[&str]) -> Vec<u8> {
        let array_offset = std::mem::size_of::<PROVIDER_ENUMERATION_INFO>()
            .saturating_sub(std::mem::size_of::<TRACE_PROVIDER_INFO>());
        let entries_bytes = entries.len() * std::mem::size_of::<TRACE_PROVIDER_INFO>();

        let mut out = vec![0u8; array_offset + entries_bytes];
        let name_offsets: Vec<u32> = names
            .iter()
            .map(|name| write_utf16z(&mut out, name))
            .collect();

        let mut header: PROVIDER_ENUMERATION_INFO = unsafe { std::mem::zeroed() };
        header.NumberOfProviders = entries.len() as u32;
        // SAFETY: `out` has at least header size bytes; unaligned write is
        // accepted for byte buffers.
        unsafe {
            std::ptr::write_unaligned(out.as_mut_ptr() as *mut PROVIDER_ENUMERATION_INFO, header)
        };

        for (i, (guid, schema_source, maybe_name_idx)) in entries.iter().enumerate() {
            let mut info: TRACE_PROVIDER_INFO = unsafe { std::mem::zeroed() };
            info.ProviderGuid = *guid;
            info.SchemaSource = *schema_source;
            info.ProviderNameOffset = maybe_name_idx
                .and_then(|idx| name_offsets.get(idx as usize).copied())
                .unwrap_or(u32::MAX);

            let off = array_offset + i * std::mem::size_of::<TRACE_PROVIDER_INFO>();
            // SAFETY: `off` is computed within the allocated entry area;
            // unaligned write is accepted for byte buffers.
            unsafe {
                std::ptr::write_unaligned(
                    out.as_mut_ptr().add(off) as *mut TRACE_PROVIDER_INFO,
                    info,
                )
            };
        }

        out
    }

    #[test]
    fn skips_malformed_name_offsets() {
        let g1 = GUID {
            data1: 1,
            data2: 2,
            data3: 3,
            data4: [4; 8],
        };
        let g2 = GUID {
            data1: 9,
            data2: 8,
            data3: 7,
            data4: [6; 8],
        };

        // First entry points to an invalid offset and must be skipped;
        // second entry points to "ValidName" and must be delivered.
        let bytes = make_provider_enum_buffer(&[(g1, 0, None), (g2, 1, Some(0))], &["ValidName"]);

        let mut names = Vec::<String>::new();
        for_each_provider_in_buffer(&bytes, &mut |name, _| {
            names.push(name.to_string());
            ControlFlow::Continue(())
        })
        .unwrap();

        assert_eq!(names, vec!["validname".to_string()]);
    }

    #[test]
    fn respects_early_break() {
        let g1 = GUID {
            data1: 10,
            data2: 11,
            data3: 12,
            data4: [13; 8],
        };
        let g2 = GUID {
            data1: 20,
            data2: 21,
            data3: 22,
            data4: [23; 8],
        };
        let bytes = make_provider_enum_buffer(&[(g1, 0, Some(0)), (g2, 1, Some(1))], &["First", "Second"]);

        let mut seen = 0usize;
        for_each_provider_in_buffer(&bytes, &mut |_name, _| {
            seen += 1;
            ControlFlow::Break(())
        })
        .unwrap();

        assert_eq!(seen, 1, "Break must stop enumeration at first callback");
    }

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