// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! # TDH-Based Dynamic Event Decoder
//!
//! This module provides [`TdhDecoder`], a runtime schema decoder for
//! TraceLogging and TraceLoggingDynamic ETW events.  It uses the Windows
//! Trace Data Helper (TDH) APIs to discover event schemas on the fly and
//! converts them into the standard [`EventFormat`] / [`EventData`]
//! representation used throughout one_collect.
//!
//! ## Design
//!
//! The decoder caches the [`EventFormat`] directly, keyed by the raw
//! TraceLogging schema bytes and pointer width.  Because the format uses
//! the framework's standard `LocationType` conventions (`StaticString`,
//! `StaticUTF16String`, etc. with `size = 0` for variable-length fields),
//! the cached `EventFormat` is schema-stable: it doesn't depend on any
//! particular event's payload bytes.  A cache hit collapses to a hashmap
//! probe + `EventData::new` — effectively zero per-event overhead.
//!
//! Variable-length field resolution (scanning for null terminators, reading
//! length prefixes) is handled lazily by the framework's existing
//! `try_get_field_data_closure` skip-chain machinery in `event/mod.rs`.
//! Only fields the consumer actually reads incur scanning cost.
//!
//! ## Scope
//!
//! - **Supported**: TraceLogging and TraceLoggingDynamic events, nested
//!   struct fields (flattened with dot-notation names), basic scalar and
//!   string property types, 32-bit and 64-bit event payloads.
//!
//! - **Not yet supported** (future work): manifest-based event decoding,
//!   map / enum value resolution, array-typed properties, and properties
//!   whose length or count is given by another property.

use super::abi::{EVENT_RECORD, EventRecordExt};
use crate::event::{EventData, EventField, EventFormat, LocationType};

use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use tracing::{debug, trace, warn};
use twox_hash::XxHash64;

// ── windows-sys imports for TDH ─────────────────────────────────────

use windows_sys::Win32::System::Diagnostics::Etw::{
    TRACE_EVENT_INFO,
    EVENT_PROPERTY_INFO,
    TdhGetEventInformation,
    EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL,

    TDH_INTYPE_UNICODESTRING,
    TDH_INTYPE_ANSISTRING,
    TDH_INTYPE_INT8,
    TDH_INTYPE_UINT8,
    TDH_INTYPE_INT16,
    TDH_INTYPE_UINT16,
    TDH_INTYPE_INT32,
    TDH_INTYPE_UINT32,
    TDH_INTYPE_INT64,
    TDH_INTYPE_UINT64,
    TDH_INTYPE_FLOAT,
    TDH_INTYPE_DOUBLE,
    TDH_INTYPE_BOOLEAN,
    TDH_INTYPE_BINARY,
    TDH_INTYPE_GUID,
    TDH_INTYPE_POINTER,
    TDH_INTYPE_FILETIME,
    TDH_INTYPE_SYSTEMTIME,
    TDH_INTYPE_SID,
    TDH_INTYPE_HEXINT32,
    TDH_INTYPE_HEXINT64,
    TDH_INTYPE_COUNTEDSTRING,
    TDH_INTYPE_COUNTEDANSISTRING,
    TDH_INTYPE_REVERSEDCOUNTEDSTRING,
    TDH_INTYPE_REVERSEDCOUNTEDANSISTRING,
    TDH_INTYPE_NONNULLTERMINATEDSTRING,
    TDH_INTYPE_NONNULLTERMINATEDANSISTRING,

    // PROPERTY_FLAGS enum values used in EVENT_PROPERTY_INFO::Flags.
    PropertyStruct,
    PropertyParamLength,
    PropertyParamCount,
};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND};

/// `EVENT_HEADER_FLAG_32_BIT_HEADER` from the Windows SDK.
const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 = 0x0020;

// Aliases for PROPERTY_FLAGS constants (i32 in windows-sys) to keep
// call-site flag checks concise.
const PROPERTY_STRUCT: i32       = PropertyStruct;
const PROPERTY_PARAM_LENGTH: i32 = PropertyParamLength;
const PROPERTY_PARAM_COUNT: i32  = PropertyParamCount;

// EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL is imported from windows-sys
// (u32 = 11).  Usage sites cast to u16 where the ExtType field requires it.

// ── Error type ──────────────────────────────────────────────────────

/// Errors that can occur during TDH-based schema decoding.
#[derive(Debug)]
pub enum TdhDecodeError {
    /// No `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` extended-data item was
    /// found on the event.
    NotFound,
    /// A Win32 error code was returned by `TdhGetEventInformation`.
    Win32(u32),
    /// The `TRACE_EVENT_INFO` returned by TDH is structurally invalid.
    Malformed(&'static str),
}

impl std::fmt::Display for TdhDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no schema TL extended-data item found on event"),
            Self::Win32(code) => write!(f, "TdhGetEventInformation failed with Win32 error {code}"),
            Self::Malformed(msg) => write!(f, "malformed TRACE_EVENT_INFO: {msg}"),
        }
    }
}

impl std::error::Error for TdhDecodeError {}

// ── Cached schema ───────────────────────────────────────────────────

/// Cached schema: the event name and the `EventFormat` that the
/// framework's `try_get_field_data_closure` can resolve lazily.
#[derive(Clone)]
struct CachedSchema {
    /// The TraceLogging event name.
    event_name: String,
    /// Schema-stable `EventFormat` — field offsets are absolute for
    /// fixed-size fields, and the framework's skip chain handles
    /// variable-length fields lazily via `size = 0`.
    format: EventFormat,
    /// Monotonic ID assigned at insertion time.
    schema_id: SchemaId,
}

/// Hash builder using XxHash64, matching the rest of the ETW module.
type XxBuildHasher = BuildHasherDefault<XxHash64>;

/// Schema cache: two maps (32-bit / 64-bit) keyed by raw TL bytes.
struct SchemaCache {
    cache_64: HashMap<Vec<u8>, CachedSchema, XxBuildHasher>,
    cache_32: HashMap<Vec<u8>, CachedSchema, XxBuildHasher>,
}

impl SchemaCache {
    fn new() -> Self {
        Self {
            cache_64: HashMap::with_hasher(XxBuildHasher::default()),
            cache_32: HashMap::with_hasher(XxBuildHasher::default()),
        }
    }

    fn get(&self, key: &[u8], is_32bit: bool) -> Option<&CachedSchema> {
        let map = if is_32bit { &self.cache_32 } else { &self.cache_64 };
        map.get(key)
    }

    fn insert(&mut self, key: Vec<u8>, is_32bit: bool, schema: CachedSchema) {
        let map = if is_32bit { &mut self.cache_32 } else { &mut self.cache_64 };
        map.entry(key).or_insert(schema);
    }
}

// ── TdhDecoder ──────────────────────────────────────────────────────

/// Result of a successful [`TdhDecoder::decode`] call.
///
/// Contains the decoded [`EventData`], the TraceLogging `event_name`,
/// and a monotonic [`SchemaId`] that exporters can use as a cheap
/// lookup key for format registration.
#[non_exhaustive]
pub struct TdhDecodedEvent<'a> {
    /// The decoded event data.
    pub event_data: EventData<'a>,
    /// The TraceLogging event name, or `None` if the schema has no name.
    ///
    /// This is the primary identity for TraceLogging events (as opposed
    /// to the event ID, which is often 0).  Consumers can use this for
    /// OTEL log record naming without a second cache probe.
    pub event_name: Option<&'a str>,
    /// Monotonic identifier for this event's schema.
    ///
    /// Each distinct `(schema_tl_bytes, pointer_width)` pair gets a unique
    /// `SchemaId` on first insertion into the cache.  The same ID is
    /// returned on every subsequent cache hit.  Exporters can use this as
    /// a cheap lookup key to avoid re-registering the `EventFormat`:
    ///
    /// ```ignore
    /// let event = decoder.decode(record)?;
    /// let id = *my_map.entry(event.schema_id)
    ///     .or_insert_with(|| exporter.register(event.event_data.format()));
    /// ```
    pub schema_id: SchemaId,
}

/// Opaque monotonic identifier for a cached TDH schema.
///
/// Assigned once on cache insertion and returned with every decoded event
/// that matches the same schema.  Suitable as a `HashMap` key for
/// exporter-side format registration.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchemaId(u64);

/// Runtime decoder for TraceLogging / TraceLoggingDynamic ETW events.
///
/// Caches the `EventFormat` directly per schema.  Cache hits are a
/// hashmap probe + `EventData::new` with no per-event allocation.
pub struct TdhDecoder {
    cache: SchemaCache,
    /// Reusable aligned buffer for `TdhGetEventInformation` results.
    tei_buf: AlignedTeiBuf,
    /// Monotonic counter for assigning unique `SchemaId`s.
    next_schema_id: u64,
}

impl TdhDecoder {
    /// Creates a new decoder with an empty schema cache.
    pub fn new() -> Self {
        Self {
            cache: SchemaCache::new(),
            tei_buf: AlignedTeiBuf::new(),
            next_schema_id: 0,
        }
    }

    /// Decodes an `EVENT_RECORD` into a [`TdhDecodedEvent`].
    ///
    /// The returned [`TdhDecodedEvent`] contains the decoded
    /// [`EventData`], the TraceLogging `event_name`, and a monotonic
    /// [`SchemaId`] that exporters can use as a cheap lookup key for
    /// format registration.
    pub fn decode<'a>(
        &'a mut self,
        record: &'a EVENT_RECORD,
    ) -> Result<TdhDecodedEvent<'a>, TdhDecodeError> {
        let is_32bit = (record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;
        let schema_tl_bytes = find_schema_tl(record)?;

        if self.cache.get(schema_tl_bytes, is_32bit).is_none() {
            call_tdh_get_event_information(record, &mut self.tei_buf)?;
            let mut schema = build_cached_schema(self.tei_buf.as_bytes(), is_32bit)?;
            let id = self.next_schema_id;
            self.next_schema_id = id.wrapping_add(1);
            schema.schema_id = SchemaId(id);
            debug!(
                event_name = %schema.event_name,
                field_count = schema.format.fields().len(),
                schema_id = id,
                is_32bit,
                "TDH schema cache miss — new schema cached"
            );
            self.cache.insert(schema_tl_bytes.to_vec(), is_32bit, schema);
        }

        let schema = self.cache.get(schema_tl_bytes, is_32bit)
            .expect("just inserted");

        let user_data = record.user_data_slice();
        debug!(
            user_data_len = user_data.len(),
            field_count = schema.format.fields().len(),
            "TDH decode — user_data"
        );
        let event_name = if schema.event_name.is_empty() {
            None
        } else {
            Some(schema.event_name.as_str())
        };

        Ok(TdhDecodedEvent {
            event_data: EventData::new(user_data, user_data, &schema.format),
            event_name,
            schema_id: schema.schema_id,
        })
    }
}

impl Default for TdhDecoder {
    fn default() -> Self { Self::new() }
}

// ── Schema extraction from TDH ──────────────────────────────────────

/// Builds a `CachedSchema` from a `TRACE_EVENT_INFO` buffer.
///
/// Emits `EventField`s using the framework's standard `LocationType`
/// conventions so the resulting `EventFormat` is schema-stable and
/// can be cached directly.
fn build_cached_schema(tei_buf: &[u8], is_32bit: bool) -> Result<CachedSchema, TdhDecodeError> {
    if tei_buf.len() < std::mem::size_of::<TRACE_EVENT_INFO>() {
        return Err(TdhDecodeError::Malformed("buffer smaller than TRACE_EVENT_INFO"));
    }

    let tei = unsafe { &*(tei_buf.as_ptr() as *const TRACE_EVENT_INFO) };
    let property_count = tei.PropertyCount as usize;
    let top_level_count = tei.TopLevelPropertyCount as usize;

    let event_name = read_event_name(tei_buf, tei);

    if property_count == 0 {
        return Ok(CachedSchema {
            event_name,
            format: EventFormat::new(),
            schema_id: SchemaId(0), // assigned by caller
        });
    }

    let props_offset = std::mem::size_of::<TRACE_EVENT_INFO>()
        - std::mem::size_of::<EVENT_PROPERTY_INFO>();
    let props_size = property_count
        .checked_mul(std::mem::size_of::<EVENT_PROPERTY_INFO>())
        .ok_or(TdhDecodeError::Malformed("property count overflow"))?;
    let props_end = props_offset
        .checked_add(props_size)
        .ok_or(TdhDecodeError::Malformed("property array end overflow"))?;
    if tei_buf.len() < props_end {
        return Err(TdhDecodeError::Malformed("buffer too small for declared property count"));
    }

    let properties: &[EVENT_PROPERTY_INFO] = unsafe {
        std::slice::from_raw_parts(
            tei_buf.as_ptr().add(props_offset) as *const EVENT_PROPERTY_INFO,
            property_count,
        )
    };

    let mut format = EventFormat::new();
    let mut running_offset: usize = 0;
    // Once we encounter the first variable-length field, all subsequent
    // offsets become 0 (the framework's skip chain resolves them lazily).
    let mut seen_variable = false;

    walk_properties(
        tei_buf, properties, 0..top_level_count,
        "", &mut format, &mut running_offset, &mut seen_variable, is_32bit, 0,
    )?;

    Ok(CachedSchema {
        event_name,
        format,
        schema_id: SchemaId(0), // assigned by caller
    })
}

/// Maximum nesting depth for struct properties.
const MAX_STRUCT_DEPTH: usize = 8;

/// Recursively walks TDH properties, flattening structs, and emits
/// `EventField`s directly into the `EventFormat` using the framework's
/// `LocationType` conventions.
fn walk_properties(
    tei_buf: &[u8],
    properties: &[EVENT_PROPERTY_INFO],
    range: std::ops::Range<usize>,
    prefix: &str,
    format: &mut EventFormat,
    running_offset: &mut usize,
    seen_variable: &mut bool,
    is_32bit: bool,
    depth: usize,
) -> Result<(), TdhDecodeError> {
    for i in range {
        if i >= properties.len() {
            return Err(TdhDecodeError::Malformed("property index out of bounds"));
        }

        let prop = &properties[i];
        let raw_name = read_property_name(tei_buf, prop);
        let name = if raw_name.is_empty() { std::format!("field{i}") } else { raw_name };
        let qualified_name = if prefix.is_empty() {
            name
        } else {
            std::format!("{prefix}.{name}")
        };

        let flags = prop.Flags;

        // ── Struct property ─────────────────────────────────────────
        if (flags & PROPERTY_STRUCT) != 0 {
            if depth >= MAX_STRUCT_DEPTH {
                return Err(TdhDecodeError::Malformed("struct nesting depth exceeded"));
            }
            let struct_info = unsafe { prop.Anonymous1.structType };
            let start = struct_info.StructStartIndex as usize;
            let count = struct_info.NumOfStructMembers as usize;
            walk_properties(
                tei_buf, properties, start..start + count,
                &qualified_name, format, running_offset, seen_variable, is_32bit, depth + 1,
            )?;
            continue;
        }

        // ── Array/param-count properties ─────────────────────────────
        if (flags & PROPERTY_PARAM_COUNT) != 0 {
            let count = unsafe { prop.Anonymous2.count } as usize;
            if count != 1 {
                debug!(field = %qualified_name, count, "skipping unsupported array property");
                let offset = if *seen_variable { 0 } else { *running_offset };
                format.add_field(EventField::new(
                    qualified_name, "unsupported".to_string(),
                    LocationType::Static, offset, 0,
                ));
                *seen_variable = true;
                continue;
            }
        }

        // ── Leaf property ───────────────────────────────────────────
        let in_type = unsafe { prop.Anonymous1.nonStructType.InType } as i32;

        // Read the raw TDH length before interpretation.
        let raw_len = unsafe { prop.Anonymous3.length } as usize;

        debug!(
            field = %qualified_name,
            in_type,
            flags = format!("0x{:x}", flags),
            raw_len,
            "TDH property leaf"
        );

        // Read the TDH-reported byte length for this property.
        //
        // When `PropertyParamLength` (0x2) is set, `Anonymous3` holds a
        // property *index* (parameterized length) — we must NOT interpret
        // it as a literal byte count.  In all other cases (including
        // `flags = 0x0`, common for TraceLoggingDynamic self-describing
        // fields with in_type >= 256), `Anonymous3.length` is a direct
        // byte count that TDH populates from the schema.
        // For variable-length in_types (counted strings, non-null-terminated
        // strings), never use the TDH-reported length as a fixed size because
        // it is per-event and the schema is cached.  Force these through the
        // dynamic LocationType path instead.
        let is_variable_intype = matches!(
            in_type,
            TDH_INTYPE_UNICODESTRING
            | TDH_INTYPE_ANSISTRING
            | TDH_INTYPE_COUNTEDSTRING
            | TDH_INTYPE_COUNTEDANSISTRING
            | TDH_INTYPE_REVERSEDCOUNTEDSTRING
            | TDH_INTYPE_REVERSEDCOUNTEDANSISTRING
            | TDH_INTYPE_NONNULLTERMINATEDSTRING
            | TDH_INTYPE_NONNULLTERMINATEDANSISTRING
        );

        let explicit_len: Option<usize> = if is_variable_intype {
            // Variable-length types must use their LocationType-specific
            // decoding (null-scan or length-prefix) rather than a cached
            // per-event byte count.
            None
        } else if (flags & PROPERTY_PARAM_LENGTH) == 0 {
            let len = raw_len;
            if len > 0 { Some(len) } else { None }
        } else {
            None
        };

        let offset = if *seen_variable { 0 } else { *running_offset };

        // If we have an explicit byte length, treat as fixed regardless
        // of the in_type.
        if let Some(len) = explicit_len {
            let type_name = intype_to_type_name(in_type);
            format.add_field(EventField::new(
                qualified_name, type_name.to_string(),
                LocationType::Static, offset, len,
            ));
            if !*seen_variable {
                *running_offset += len;
            }
            continue;
        }

        // Map TDH in-type to the framework's LocationType + size.
        let (type_name, loc, size) = intype_to_field_info(in_type, is_32bit);

        format.add_field(EventField::new(
            qualified_name, type_name.to_string(),
            loc, offset, size,
        ));

        if size == 0 {
            // Variable-length field: all subsequent offsets become 0.
            *seen_variable = true;
        } else if !*seen_variable {
            *running_offset += size;
        }
    }

    Ok(())
}

// ── Internal helpers ────────────────────────────────────────────────

/// Finds the TraceLogging schema metadata in the event's extended-data.
fn find_schema_tl<'a>(record: &'a EVENT_RECORD) -> Result<&'a [u8], TdhDecodeError> {
    let item_ptr = record
        .find_extended_data(EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL as u16)
        .ok_or(TdhDecodeError::NotFound)?;
    let item = unsafe { &*item_ptr };
    if item.DataPtr == 0 || item.DataSize == 0 {
        return Err(TdhDecodeError::NotFound);
    }
    Ok(unsafe {
        std::slice::from_raw_parts(item.DataPtr as *const u8, item.DataSize as usize)
    })
}

/// Aligned buffer for `TRACE_EVENT_INFO`.
struct AlignedTeiBuf {
    storage: Vec<u64>,
    len: usize,
}

impl AlignedTeiBuf {
    fn new() -> Self {
        Self { storage: Vec::new(), len: 0 }
    }

    fn ensure_capacity(&mut self, byte_count: usize) {
        let u64_count = (byte_count + 7) / 8;
        if self.storage.len() < u64_count {
            self.storage.resize(u64_count, 0u64);
        }
    }

    fn as_bytes(&self) -> &[u8] {
        let ptr = self.storage.as_ptr() as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, self.len) }
    }

    fn as_mut_ptr(&mut self) -> *mut TRACE_EVENT_INFO {
        self.storage.as_mut_ptr() as *mut TRACE_EVENT_INFO
    }
}

/// Calls `TdhGetEventInformation`, growing the buffer as needed.
fn call_tdh_get_event_information(
    record: &EVENT_RECORD,
    buf: &mut AlignedTeiBuf,
) -> Result<(), TdhDecodeError> {
    let mut buffer_size: u32 = 0;
    let status = unsafe {
        TdhGetEventInformation(
            record as *const EVENT_RECORD, 0u32,
            core::ptr::null(), core::ptr::null_mut(), &mut buffer_size,
        )
    };
    if status == ERROR_NOT_FOUND {
        return Err(TdhDecodeError::NotFound);
    }
    if status != ERROR_INSUFFICIENT_BUFFER {
        warn!(win32_error = status, "TdhGetEventInformation sizing call failed");
        return Err(TdhDecodeError::Win32(status));
    }
    if buffer_size == 0 {
        return Err(TdhDecodeError::Malformed("TDH returned zero buffer size"));
    }
    buf.ensure_capacity(buffer_size as usize);
    let status = unsafe {
        TdhGetEventInformation(
            record as *const EVENT_RECORD, 0u32,
            core::ptr::null(), buf.as_mut_ptr(), &mut buffer_size,
        )
    };
    if status != 0 {
        warn!(win32_error = status, "TdhGetEventInformation fill call failed");
        return Err(TdhDecodeError::Win32(status));
    }
    buf.len = buffer_size as usize;
    trace!(buffer_size, "TdhGetEventInformation succeeded");
    Ok(())
}

// SAFETY guard for the `EventNameOffset` union read below.
// `TRACE_EVENT_INFO_0` is a union with two `u32` arms
// (`EventNameOffset` and `ActivityIDNameOffset`) at the same offset.
// Either arm always yields a valid bit pattern for a `u32`.
const _: () = assert!(
    std::mem::size_of::<
        windows_sys::Win32::System::Diagnostics::Etw::TRACE_EVENT_INFO_0
    >() == 4,
    "TRACE_EVENT_INFO_0 union must remain 4 bytes",
);

/// Reads the TraceLogging event name from `TRACE_EVENT_INFO`.
fn read_event_name(tei_buf: &[u8], tei: &TRACE_EVENT_INFO) -> String {
    // SAFETY: Both arms of `TRACE_EVENT_INFO_0` are `u32` at the same
    // offset, so either arm always yields a valid bit pattern.  The
    // const assertion above guards the 4-byte size against future
    // `windows-sys` layout drift.
    let name_offset = unsafe { tei.Anonymous1.EventNameOffset } as usize;
    read_utf16_at(tei_buf, name_offset)
}

/// Reads a null-terminated UTF-16 property name from the TEI buffer.
fn read_property_name(tei_buf: &[u8], prop: &EVENT_PROPERTY_INFO) -> String {
    read_utf16_at(tei_buf, prop.NameOffset as usize)
}

/// Reads a null-terminated UTF-16LE string from `buf` at `byte_offset`.
fn read_utf16_at(buf: &[u8], byte_offset: usize) -> String {
    if byte_offset == 0 || byte_offset >= buf.len() {
        return String::new();
    }
    let remaining = &buf[byte_offset..];
    let u16s: Vec<u16> = remaining
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Maps a TDH in-type to `(type_name, LocationType, size)`.
///
/// This is the single source of truth for the in-type → field-info
/// mapping, used by both `walk_properties` (schema construction) and
/// `intype_to_type_name` (explicit-length fallback).
const fn intype_to_field_info(in_type: i32, is_32bit: bool) -> (&'static str, LocationType, usize) {
    match in_type {
        // Fixed-size scalars
        TDH_INTYPE_INT8                          => ("s8",   LocationType::Static, 1),
        TDH_INTYPE_UINT8 | TDH_INTYPE_BOOLEAN   => ("u8",   LocationType::Static, 1),
        TDH_INTYPE_INT16                         => ("s16",  LocationType::Static, 2),
        TDH_INTYPE_UINT16                        => ("u16",  LocationType::Static, 2),
        TDH_INTYPE_INT32 | TDH_INTYPE_HEXINT32  => ("s32",  LocationType::Static, 4),
        TDH_INTYPE_UINT32                        => ("u32",  LocationType::Static, 4),
        TDH_INTYPE_INT64 | TDH_INTYPE_HEXINT64  => ("s64",  LocationType::Static, 8),
        TDH_INTYPE_UINT64                        => ("u64",  LocationType::Static, 8),
        TDH_INTYPE_FLOAT                         => ("float", LocationType::Static, 4),
        TDH_INTYPE_DOUBLE                        => ("double", LocationType::Static, 8),
        TDH_INTYPE_POINTER => {
            let sz = if is_32bit { 4 } else { 8 };
            ("pointer", LocationType::Static, sz)
        }
        TDH_INTYPE_FILETIME                      => ("filetime",   LocationType::Static, 8),
        TDH_INTYPE_SYSTEMTIME                    => ("systemtime", LocationType::Static, 16),
        TDH_INTYPE_GUID                          => ("guid",       LocationType::Static, 16),

        // Variable-length: null-terminated strings → size = 0
        TDH_INTYPE_ANSISTRING                    => ("string",  LocationType::StaticString, 0),
        TDH_INTYPE_UNICODESTRING                 => ("wstring", LocationType::StaticUTF16String, 0),

        // Counted strings (2-byte length prefix + content bytes).
        TDH_INTYPE_COUNTEDSTRING                 => ("counted_wstring", LocationType::StaticLenPrefixArray, 0),
        TDH_INTYPE_COUNTEDANSISTRING             => ("counted_string",  LocationType::StaticLenPrefixArray, 0),

        // Reversed-counted strings (length at end of data).
        // For TraceLogging the payload is typically null-terminated,
        // so we fall back to null-scan as a safe approximation.
        TDH_INTYPE_REVERSEDCOUNTEDSTRING         => ("wstring", LocationType::StaticUTF16String, 0),
        TDH_INTYPE_REVERSEDCOUNTEDANSISTRING     => ("string",  LocationType::StaticString, 0),

        // Non-null-terminated strings — scan for null as best effort.
        TDH_INTYPE_NONNULLTERMINATEDSTRING       => ("wstring", LocationType::StaticUTF16String, 0),
        TDH_INTYPE_NONNULLTERMINATEDANSISTRING   => ("string",  LocationType::StaticString, 0),

        // Variable-length: binary blobs, SID
        TDH_INTYPE_SID | TDH_INTYPE_BINARY      => ("binary", LocationType::Static, 0),

        // Unknown — treat as variable-length placeholder
        _ => ("unsupported", LocationType::Static, 0),
    }
}

/// Returns the type_name string for a TDH_INTYPE.
///
/// Delegates to [`intype_to_field_info`] and returns just the name.
const fn intype_to_type_name(in_type: i32) -> &'static str {
    intype_to_field_info(in_type, false).0
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::abi::EVENT_HEADER_EXTENDED_DATA_ITEM;

    #[test]
    fn type_name_scalars() {
        assert_eq!(intype_to_type_name(TDH_INTYPE_INT8), "s8");
        assert_eq!(intype_to_type_name(TDH_INTYPE_UINT32), "u32");
        assert_eq!(intype_to_type_name(TDH_INTYPE_DOUBLE), "double");
        assert_eq!(intype_to_type_name(TDH_INTYPE_GUID), "guid");
        assert_eq!(intype_to_type_name(TDH_INTYPE_UNICODESTRING), "wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_ANSISTRING), "string");
        assert_eq!(intype_to_type_name(TDH_INTYPE_BINARY), "binary");
        assert_eq!(intype_to_type_name(999), "unsupported");
    }

    /// Verify that the extended TDH_INTYPE values 300-305 are all
    /// recognised as string types.  Per the windows-sys 0.59 constants,
    /// odd values (301, 303, 305) are ANSI and even values (300, 302,
    /// 304) are UTF-16.
    #[test]
    fn type_name_extended_strings() {
        // Counted string variants (2-byte length prefix)
        assert_eq!(intype_to_type_name(TDH_INTYPE_COUNTEDSTRING), "counted_wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_COUNTEDANSISTRING), "counted_string");
        // Reversed-counted → null-scan fallback
        assert_eq!(intype_to_type_name(TDH_INTYPE_REVERSEDCOUNTEDSTRING), "wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_REVERSEDCOUNTEDANSISTRING), "string");
        // Non-null-terminated → null-scan fallback
        assert_eq!(intype_to_type_name(TDH_INTYPE_NONNULLTERMINATEDSTRING), "wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_NONNULLTERMINATEDANSISTRING), "string");
    }

    #[test]
    fn read_utf16_at_basic() {
        let buf: Vec<u8> = vec![0xFF, 0xFF, b'A', 0, b'B', 0, 0, 0];
        assert_eq!(read_utf16_at(&buf, 2), "AB");
    }

    #[test]
    fn read_utf16_at_zero_offset() {
        assert_eq!(read_utf16_at(&[0x41, 0x00, 0x00, 0x00], 0), "");
    }

    #[test]
    fn read_utf16_at_out_of_bounds() {
        assert_eq!(read_utf16_at(&[0x41, 0x00], 100), "");
    }

    // ── End-to-end TDH integration tests ────────────────────────────

    /// TL InType constants (same as TDH_INTYPE_* values).
    const TL_UINT32: u8 = 8;
    const TL_UINT64: u8 = 10;
    const TL_DOUBLE: u8 = 12;
    const TL_ANSISTRING: u8 = 2;
    const TL_UNICODESTRING: u8 = 1;

    /// Builds a TraceLogging schema metadata blob.
    fn build_tl_schema(
        provider_name: &str,
        event_name: &str,
        fields: &[(&str, u8)],
    ) -> Vec<u8> {
        let mut blob = Vec::new();
        let prov_size = 2u16 + provider_name.len() as u16 + 1;
        blob.extend_from_slice(&prov_size.to_le_bytes());
        blob.extend_from_slice(provider_name.as_bytes());
        blob.push(0);
        let mut event_body_len: usize = 1 + event_name.len() + 1;
        for (name, _) in fields {
            event_body_len += name.len() + 1 + 1;
        }
        let event_size = 2u16 + event_body_len as u16;
        blob.extend_from_slice(&event_size.to_le_bytes());
        blob.push(0);
        blob.extend_from_slice(event_name.as_bytes());
        blob.push(0);
        for (name, intype) in fields {
            blob.extend_from_slice(name.as_bytes());
            blob.push(0);
            blob.push(*intype);
        }
        blob
    }

    const EXT_TYPE_PROV_TRAITS: u16 = 12;

    fn build_test_record(
        prov_blob: &[u8],
        event_blob: &[u8],
        ext_items: &mut [EVENT_HEADER_EXTENDED_DATA_ITEM; 2],
        user_data: &[u8],
    ) -> EVENT_RECORD {
        ext_items[0] = unsafe { std::mem::zeroed() };
        ext_items[0].ExtType = EXT_TYPE_PROV_TRAITS;
        ext_items[0].DataSize = prov_blob.len() as u16;
        ext_items[0].DataPtr = prov_blob.as_ptr() as u64;
        ext_items[1] = unsafe { std::mem::zeroed() };
        ext_items[1].ExtType = EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL as u16;
        ext_items[1].DataSize = event_blob.len() as u16;
        ext_items[1].DataPtr = event_blob.as_ptr() as u64;
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.ExtendedDataCount = 2;
        record.ExtendedData = ext_items.as_mut_ptr();
        record.UserData = user_data.as_ptr() as *mut std::ffi::c_void;
        record.UserDataLength = user_data.len() as u16;
        record
    }

    fn split_tl_schema(blob: &[u8]) -> (&[u8], &[u8]) {
        let prov_size = u16::from_le_bytes([blob[0], blob[1]]) as usize;
        (&blob[..prov_size], &blob[prov_size..])
    }

    #[test]
    fn tdh_decode_single_u32() {
        let schema = build_tl_schema("TestProvider", "SingleU32", &[
            ("ProcessId", TL_UINT32),
        ]);
        let (prov, evt) = split_tl_schema(&schema);
        let user_data: Vec<u8> = 42u32.to_le_bytes().to_vec();
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        let _schema_id = result.schema_id;

        let fields = result.event_data.format().fields();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].size, 4);
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].location, LocationType::Static);
    }

    #[test]
    fn tdh_decode_multiple_scalars() {
        let schema = build_tl_schema("TestProvider", "MultiScalar", &[
            ("Code", TL_UINT32),
            ("Value", TL_DOUBLE),
            ("Count", TL_UINT64),
        ]);
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&100u32.to_le_bytes());
        user_data.extend_from_slice(&3.14f64.to_le_bytes());
        user_data.extend_from_slice(&999u64.to_le_bytes());

        let (prov, evt) = split_tl_schema(&schema);
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        let event_data = &result.event_data;

        let fields = event_data.format().fields();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "Code");
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].size, 4);
        assert_eq!(fields[1].name, "Value");
        assert_eq!(fields[1].offset, 4);
        assert_eq!(fields[1].size, 8);
        assert_eq!(fields[2].name, "Count");
        assert_eq!(fields[2].offset, 12);
        assert_eq!(fields[2].size, 8);
    }

    #[test]
    fn tdh_decode_with_ansi_string() {
        let schema = build_tl_schema("TestProvider", "WithString", &[
            ("Id", TL_UINT32),
            ("Message", TL_ANSISTRING),
            ("Flags", TL_UINT32),
        ]);
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&7u32.to_le_bytes());
        user_data.extend_from_slice(b"Hello\0");
        user_data.extend_from_slice(&0xFFu32.to_le_bytes());

        let (prov, evt) = split_tl_schema(&schema);
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        let event_data = &result.event_data;

        let fields = event_data.format().fields();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "Id");
        assert_eq!(fields[0].offset, 0);
        assert_eq!(fields[0].size, 4);
        assert_eq!(fields[0].location, LocationType::Static);
        // Message: variable-length string with size = 0
        assert_eq!(fields[1].name, "Message");
        assert_eq!(fields[1].offset, 4);
        assert_eq!(fields[1].size, 0);
        assert_eq!(fields[1].location, LocationType::StaticString);
        // Flags: after a variable field, offset = 0
        assert_eq!(fields[2].name, "Flags");
        assert_eq!(fields[2].offset, 0);
        assert_eq!(fields[2].size, 4);

        // Verify the framework's lazy resolution works: read the Message
        // field using try_get_field_data_closure.
        let format = event_data.format();
        let mut msg_closure = format.try_get_field_data_closure("Message")
            .expect("should produce closure for Message");
        let msg_bytes = msg_closure(event_data.event_data());
        assert_eq!(msg_bytes, b"Hello");

        // Read the Flags field (after the variable string)
        let mut flags_closure = format.try_get_field_data_closure("Flags")
            .expect("should produce closure for Flags");
        let flags_bytes = flags_closure(event_data.event_data());
        assert_eq!(flags_bytes, &0xFFu32.to_le_bytes());
    }

    #[test]
    fn tdh_decode_with_unicode_string() {
        let schema = build_tl_schema("TestProvider", "WithWString", &[
            ("Name", TL_UNICODESTRING),
            ("Code", TL_UINT32),
        ]);
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&[b'A', 0, b'B', 0, 0, 0]); // "AB\0" UTF-16LE
        user_data.extend_from_slice(&42u32.to_le_bytes());

        let (prov, evt) = split_tl_schema(&schema);
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        let event_data = &result.event_data;

        let fields = event_data.format().fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "Name");
        assert_eq!(fields[0].size, 0); // variable
        assert_eq!(fields[0].location, LocationType::StaticUTF16String);
        assert_eq!(fields[1].name, "Code");
        assert_eq!(fields[1].offset, 0); // after variable field

        // Verify lazy resolution
        let format = event_data.format();
        let mut name_closure = format.try_get_field_data_closure("Name")
            .expect("should produce closure for Name");
        let name_bytes = name_closure(event_data.event_data());
        // StaticUTF16String returns bytes up to (not including) the null
        assert_eq!(name_bytes, &[b'A', 0, b'B', 0]);
    }

    #[test]
    fn tdh_decode_event_name() {
        let schema = build_tl_schema("MyProvider", "ImportantEvent", &[
            ("X", TL_UINT32),
        ]);
        let (prov, evt) = split_tl_schema(&schema);
        let user_data = 1u32.to_le_bytes();
        let mut ext_items: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record = build_test_record(prov, evt, &mut ext_items, &user_data);

        let mut decoder = TdhDecoder::new();
        let result = decoder.decode(&record).expect("decode should succeed");
        assert_eq!(result.event_name, Some("ImportantEvent"));
    }

    #[test]
    fn tdh_decode_schema_cache_reuse() {
        let schema = build_tl_schema("TestProvider", "Cached", &[
            ("Val", TL_UINT32),
        ]);
        let (prov, evt) = split_tl_schema(&schema);

        let user_data_1 = 111u32.to_le_bytes();
        let mut ext_items_1: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record_1 = build_test_record(prov, evt, &mut ext_items_1, &user_data_1);

        let mut decoder = TdhDecoder::new();
        let r1 = decoder.decode(&record_1).expect("first decode");
        let id1 = r1.schema_id;
        assert_eq!(r1.event_data.format().fields()[0].size, 4);

        let user_data_2 = 222u32.to_le_bytes();
        let mut ext_items_2: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record_2 = build_test_record(prov, evt, &mut ext_items_2, &user_data_2);
        let r2 = decoder.decode(&record_2).expect("second decode (cached)");
        assert_eq!(r2.schema_id, id1, "cache hit should return same SchemaId");
        assert_eq!(r2.event_data.format().fields()[0].size, 4);
    }

    #[test]
    fn tdh_decode_not_found_without_schema_tl() {
        // An EVENT_RECORD with no extended data items should return
        // TdhDecodeError::NotFound — the public-API contract for
        // manifest-based events or records without TraceLogging metadata.
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.ExtendedDataCount = 0;
        record.ExtendedData = std::ptr::null_mut();

        let mut decoder = TdhDecoder::new();
        match decoder.decode(&record) {
            Err(TdhDecodeError::NotFound) => {} // expected
            Err(other) => panic!("expected NotFound, got: {other}"),
            Ok(_) => panic!("expected NotFound error, but decode succeeded"),
        }
    }

    #[test]
    fn tdh_decode_pointer_width_cache_split() {
        // The same TL schema bytes under 32-bit and 64-bit headers
        // must produce two distinct cache entries because pointer
        // fields have different sizes (4 vs 8 bytes).
        let schema = build_tl_schema("TestProvider", "PtrEvent", &[
            ("Val", TL_UINT32),
        ]);
        let (prov, evt) = split_tl_schema(&schema);
        let user_data = 1u32.to_le_bytes();

        // 64-bit decode (default — flag not set)
        let mut ext_items_64: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record_64 = build_test_record(prov, evt, &mut ext_items_64, &user_data);

        let mut decoder = TdhDecoder::new();
        let r64 = decoder.decode(&record_64).expect("64-bit decode");
        let id_64 = r64.schema_id;

        // 32-bit decode (set EVENT_HEADER_FLAG_32_BIT_HEADER)
        let mut ext_items_32: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let mut record_32 = build_test_record(prov, evt, &mut ext_items_32, &user_data);
        record_32.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER;

        let r32 = decoder.decode(&record_32).expect("32-bit decode");
        let id_32 = r32.schema_id;
        assert_ne!(id_64, id_32, "32-bit and 64-bit should get different SchemaIds");

        // Second 64-bit decode should return the same SchemaId
        let mut ext_items_64b: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let record_64b = build_test_record(prov, evt, &mut ext_items_64b, &user_data);
        let r64b = decoder.decode(&record_64b).expect("64-bit cache hit");
        assert_eq!(r64b.schema_id, id_64, "64-bit cache hit should return same ID");

        // Second 32-bit decode should return the same SchemaId
        let mut ext_items_32b: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let mut record_32b = build_test_record(prov, evt, &mut ext_items_32b, &user_data);
        record_32b.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER;
        let r32b = decoder.decode(&record_32b).expect("32-bit cache hit");
        assert_eq!(r32b.schema_id, id_32, "32-bit cache hit should return same ID");
    }
}
