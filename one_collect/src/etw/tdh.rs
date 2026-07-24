// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! # TDH-Based Dynamic Event Decoder
//!
//! This module provides [`TdhDecoder`], a runtime schema decoder for
//! TraceLogging, TraceLoggingDynamic, and manifest-based ETW events.  It
//! uses the Windows Trace Data Helper (TDH) APIs to discover event schemas
//! on the fly and converts them into the standard [`EventFormat`] /
//! [`EventData`] representation used throughout one_collect.
//!
//! ## Design
//!
//! The decoder caches the [`EventFormat`] directly.  TraceLogging schemas
//! are keyed by their raw inline schema bytes; manifest schemas by their
//! `(Provider GUID, Id, Version)` identity.  Both keyspaces are split by
//! pointer width and index into one shared, append-only arena of decoded
//! schemas.  Because the format uses the framework's standard `LocationType`
//! conventions (`StaticString`, `StaticUTF16String`, etc. with `size = 0`
//! for variable-length fields), the cached `EventFormat` is schema-stable:
//! it doesn't depend on any particular event's payload bytes.  A cache hit
//! collapses to a hashmap probe + `EventData::new`, effectively zero
//! per-event overhead.
//!
//! Source selection is transparent: [`TdhDecoder::decode`] takes the
//! TraceLogging path when an inline SCHEMA_TL item is present and the
//! manifest path otherwise.  `TdhGetEventInformation` is the same entry
//! point for both, so the byte-level decoding is entirely source-agnostic.
//!
//! Variable-length field resolution (scanning for null terminators, reading
//! length prefixes) is handled lazily by the framework's existing
//! `try_get_field_data_closure` skip-chain machinery in `event/mod.rs`.
//! Only fields the consumer actually reads incur scanning cost.
//!
//! ## Scope
//!
//! - **Supported**: TraceLogging, TraceLoggingDynamic, and manifest-based
//!   events, nested struct fields (flattened with dot-notation names), basic
//!   scalar and string property types, 32-bit and 64-bit event payloads.
//!
//! - **Not supported**: classic (MOF/WBEM) and WPP events (fast-rejected /
//!   returned as `Unsupported`).
//!
//! - **Not yet supported** (future work): map / enum value resolution,
//!   array-typed properties, and properties whose length or count is given
//!   by another property.
//!
//! ## "Manifest" here means *OS-registered*, not EventSource in-band
//!
//! The manifest path resolves schemas exclusively through
//! `TdhGetEventInformation`, which consults manifests registered with the OS
//! (`HKLM\...\WINEVT\Publishers`, the `wevtutil im` model, e.g.
//! `Microsoft-Windows-Kernel-*` and the .NET runtime providers).  It does
//! **not** support .NET `EventSource` providers running in their default
//! manifest mode, where the manifest is *not* OS-registered but is emitted
//! **in-band** as special chunked "manifest events" (`EVENT_DESCRIPTOR.Id ==
//! 0xFFFE`, `Opcode == 0xFE`).  For those providers `TdhGetEventInformation`
//! returns `ERROR_NOT_FOUND`, so `decode()` returns
//! [`TdhDecodeError::NotFound`].  Decoding them requires capturing and
//! reassembling the in-band manifest chunks and parsing the XML, a separate
//! subsystem tracked as future work.  Custom `EventSource` providers that use
//! *self-describing* (TraceLogging) mode are decoded via the TraceLogging
//! path and are unaffected.
//!
//! Manifest decoding requires the provider's manifest to be registered on
//! the *decoding* machine; if it isn't, `TdhGetEventInformation` returns
//! `ERROR_NOT_FOUND` and `decode()` returns [`TdhDecodeError::NotFound`].
//! Negative results are not cached, so a manifest registered after the
//! decoder starts is picked up on the next matching event.

use super::abi::{EVENT_RECORD, EventRecordExt};
use crate::Guid;
use crate::event::{EventData, EventField, EventFormat, LocationType};

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;
use tracing::{debug, trace, warn};
use twox_hash::XxHash64;

// ── windows-sys imports for TDH ─────────────────────────────────────

use windows_sys::Win32::System::Diagnostics::Etw::{
    TRACE_EVENT_INFO,
    EVENT_PROPERTY_INFO,
    TdhGetEventInformation,
    EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL,

    // Decoding-source discrimination (TraceLogging vs. manifest/WPP).
    DECODING_SOURCE,
    DecodingSourceTlg,
    DecodingSourceXMLFile,

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

/// `EVENT_HEADER_FLAG_CLASSIC_HEADER` from the Windows SDK.
///
/// Set for classic (MOF/WBEM) events, whose identity is an event-class
/// GUID + Opcode rather than the `(Provider, Id, Version)` tuple used for
/// manifest events.  Such events must never take the manifest path: their
/// `EVENT_DESCRIPTOR.Id` is commonly `0`, so multiple distinct classic
/// events from one provider would collapse onto the same `ManifestEventKey`.
const EVENT_HEADER_FLAG_CLASSIC_HEADER: u16 = 0x0100;

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
    /// No decodable schema was found for the event.
    ///
    /// For TraceLogging this means no inline
    /// `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` extended-data item was
    /// present.  For manifest events this also covers "manifest not
    /// registered on this machine" (`TdhGetEventInformation` returns
    /// `ERROR_NOT_FOUND`).
    NotFound,
    /// The event's schema source is recognised but not supported by this
    /// decoder (e.g. classic (MOF/WBEM) events, which are fast-rejected
    /// before the manifest path, or WPP and WBEM decoding sources reached
    /// via the manifest dispatch path).
    Unsupported,
    /// A Win32 error code was returned by `TdhGetEventInformation`.
    Win32(u32),
    /// The `TRACE_EVENT_INFO` returned by TDH is structurally invalid.
    Malformed(&'static str),
}

impl std::fmt::Display for TdhDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no decodable schema found for event"),
            Self::Unsupported => write!(f, "event schema source is not supported"),
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
    /// The event name (TraceLogging event name or manifest task name).
    event_name: String,
    /// Schema-stable `EventFormat`: field offsets are absolute for
    /// fixed-size fields, and the framework's skip chain handles
    /// variable-length fields lazily via `size = 0`.
    format: EventFormat,
    /// Monotonic ID assigned at insertion time.
    schema_id: SchemaId,
}

/// Hash builder using XxHash64, matching the rest of the ETW module.
type XxBuildHasher = BuildHasherDefault<XxHash64>;

/// Identity of a manifest-based event's schema.
///
/// Manifest events do not carry their layout inline; instead the OS holds a
/// registered manifest that pins the `(Provider GUID, Id, Version)` tuple to
/// a fixed layout.  That tuple is therefore the natural cache key, mirroring
/// how TraceLogging keys on its inline schema bytes.
///
/// Note: the derived `Hash` delegates to [`Guid`]'s `Hash` impl, which hashes
/// only the first three GUID fields (`data1`/`data2`/`data3`), not the
/// trailing `data4` bytes.  Equality is still full (derived `Eq` compares all
/// fields), so correctness is unaffected, but two provider GUIDs differing
/// only in their last 8 bytes share a hash bucket.  Provider GUIDs vary in
/// their leading fields in practice, so this is benign; it is called out here
/// so a future change to `Guid`'s `Hash` isn't made without weighing this key.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct ManifestEventKey {
    /// Provider GUID from `EVENT_HEADER.ProviderId`.
    provider: Guid,
    /// Event ID from `EVENT_DESCRIPTOR.Id`.
    id: u16,
    /// Manifest version from `EVENT_DESCRIPTOR.Version`.  A layout change
    /// bumps this, yielding a distinct key.
    version: u8,
}

/// Schema cache: one append-only `Vec` arena of decoded schemas shared by
/// both schema sources, indexed by per-source, per-pointer-width maps.
///
/// TraceLogging is keyed by its raw inline schema bytes; manifest events by
/// their `(Provider, Id, Version)` [`ManifestEventKey`].  The two sources use
/// different key *types*, so they need separate maps (a `HashMap` is
/// monomorphic in its key), but the decoded [`CachedSchema`] is source-
/// agnostic, so storage stays unified in one arena.  Because the arena is
/// append-only, an index handed out by any map stays valid for the life of
/// the cache, and TL and manifest entries can never alias the same slot.
///
/// Storing a `Copy` index (rather than the schema inline in the map) lets the
/// hot path hash the key exactly once: the index is copied out, ending the
/// map borrow, and the schema is then read from `schemas`.
struct SchemaCache {
    /// Decoded schemas, indexed by the maps below.  Append-only: entries are
    /// never removed, so an index stays valid for the life of the cache.
    schemas: Vec<CachedSchema>,
    /// TraceLogging schema bytes → arena index (64-bit / 32-bit payloads).
    tl_64: HashMap<Vec<u8>, usize, XxBuildHasher>,
    tl_32: HashMap<Vec<u8>, usize, XxBuildHasher>,
    /// Manifest `(Provider, Id, Version)` → arena index (64/32-bit payloads).
    manifest_64: HashMap<ManifestEventKey, usize, XxBuildHasher>,
    manifest_32: HashMap<ManifestEventKey, usize, XxBuildHasher>,
    /// Manifest keys whose decoding source is permanently unsupported
    /// (WPP / WBEM reached via the manifest dispatch path).  Caching these
    /// avoids a `TdhGetEventInformation` round trip on every subsequent event
    /// from a chatty unsupported provider.  Pointer-width independent: the
    /// decoding source is a property of the provider's registration, not the
    /// payload width.  Only *permanent* negatives live here; `NotFound` is
    /// never cached, since a manifest can register after the decoder starts.
    manifest_unsupported: HashSet<ManifestEventKey, XxBuildHasher>,
}

impl SchemaCache {
    fn new() -> Self {
        Self {
            schemas: Vec::new(),
            tl_64: HashMap::with_hasher(XxBuildHasher::default()),
            tl_32: HashMap::with_hasher(XxBuildHasher::default()),
            manifest_64: HashMap::with_hasher(XxBuildHasher::default()),
            manifest_32: HashMap::with_hasher(XxBuildHasher::default()),
            manifest_unsupported: HashSet::with_hasher(XxBuildHasher::default()),
        }
    }

    /// Returns the index of a cached TraceLogging schema, or `None` on a
    /// miss.  The key is hashed exactly once.
    fn index_of_tl(&self, key: &[u8], is_32bit: bool) -> Option<usize> {
        let map = if is_32bit { &self.tl_32 } else { &self.tl_64 };
        map.get(key).copied()
    }

    /// Returns the index of a cached manifest schema, or `None` on a miss.
    fn index_of_manifest(&self, key: &ManifestEventKey, is_32bit: bool) -> Option<usize> {
        let map = if is_32bit { &self.manifest_32 } else { &self.manifest_64 };
        map.get(key).copied()
    }

    /// Returns `true` if `key` has been recorded as permanently unsupported.
    fn is_manifest_unsupported(&self, key: &ManifestEventKey) -> bool {
        self.manifest_unsupported.contains(key)
    }

    /// Records `key` as permanently unsupported (WPP / WBEM decoding source).
    fn mark_manifest_unsupported(&mut self, key: ManifestEventKey) {
        self.manifest_unsupported.insert(key);
    }

    /// Maps a TraceLogging `key` to a schema index and returns it.  Intended
    /// for the cache miss path, where `key` is not yet present.
    ///
    /// The schema is only pushed onto `schemas` when the key is actually
    /// vacant, so a (contract-violating) duplicate key returns the existing
    /// index without orphaning a freshly built schema.  The key is hashed
    /// once via a single `entry` lookup.
    fn insert_tl(&mut self, key: Vec<u8>, is_32bit: bool, schema: CachedSchema) -> usize {
        use std::collections::hash_map::Entry;

        let idx = self.schemas.len();
        let map = if is_32bit { &mut self.tl_32 } else { &mut self.tl_64 };
        match map.entry(key) {
            // Already present: return the existing index and drop `schema`.
            Entry::Occupied(e) => *e.get(),
            Entry::Vacant(e) => {
                let assigned = *e.insert(idx); // ends the map borrow
                self.schemas.push(schema); // only push once actually indexed
                assigned
            }
        }
    }

    /// Maps a manifest `key` to a schema index and returns it.  See
    /// [`insert_tl`] for the vacancy / single-hash semantics.
    fn insert_manifest(&mut self, key: ManifestEventKey, is_32bit: bool, schema: CachedSchema) -> usize {
        use std::collections::hash_map::Entry;

        let idx = self.schemas.len();
        let map = if is_32bit { &mut self.manifest_32 } else { &mut self.manifest_64 };
        match map.entry(key) {
            Entry::Occupied(e) => *e.get(),
            Entry::Vacant(e) => {
                let assigned = *e.insert(idx); // ends the map borrow
                self.schemas.push(schema); // only push once actually indexed
                assigned
            }
        }
    }

    /// Reads a cached schema by its index.
    ///
    /// `idx` always comes from an `index_of_*` or `insert_*` call, and
    /// `schemas` is append-only (entries are never removed), so the index
    /// never dangles.
    fn get(&self, idx: usize) -> &CachedSchema {
        &self.schemas[idx]
    }
}

// ── TdhDecoder ──────────────────────────────────────────────────────

/// Result of a successful [`TdhDecoder::decode`] call.
///
/// Contains the decoded [`EventData`], the resolved `event_name`,
/// and a monotonic [`SchemaId`] that exporters can use as a cheap
/// lookup key for format registration.
#[non_exhaustive]
pub struct TdhDecodedEvent<'a> {
    /// The decoded event data.
    pub event_data: EventData<'a>,
    /// The resolved event name, or `None` if the schema has no name.
    ///
    /// For TraceLogging this is the event name (the primary identity, as
    /// the event ID is often 0); for manifest events it is the task name.
    /// Consumers can use this for OTEL log record naming without a second
    /// cache probe.
    ///
    /// Note: for manifest events this is the Task name, which is not unique
    /// per event (multiple events can share a Task, e.g. Start/Stop/Info
    /// under one Task all report the same name).  Identity-sensitive
    /// consumers (dedup, routing, record identity) should use `schema_id`
    /// (or the event's `Id`/`Opcode`) rather than treating the name as unique.
    pub event_name: Option<&'a str>,
    /// Monotonic identifier for this event's schema.
    ///
    /// Each distinct schema (identified by its inline TraceLogging bytes or
    /// its manifest `(Provider, Id, Version)` tuple, split by pointer width)
    /// gets a unique `SchemaId` on first insertion into the cache.  The same
    /// ID is returned on every subsequent cache hit.  Exporters can use this as
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

/// The schema source of an event, paired with the cache key used to look it
/// up and (on a miss) insert it.
///
/// Classifying the source up front lets [`TdhDecoder::decode`] own the entire
/// cache interaction — lookup, miss dispatch, and insert — in one place, so
/// the `decode_*` helpers are reached only when a *real* decode is required.
enum SchemaSource<'a> {
    /// Inline TraceLogging schema, keyed by its raw schema bytes.
    TraceLogging(&'a [u8]),
    /// Manifest event, keyed by its `(Provider, Id, Version)` identity.
    Manifest(ManifestEventKey),
}

/// Runtime decoder for TraceLogging, TraceLoggingDynamic, and
/// manifest-based ETW events.
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
    /// The schema source is selected automatically: an event carrying an
    /// inline `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` item takes the
    /// TraceLogging path; otherwise the event is treated as manifest-based
    /// and resolved through its `(Provider, Id, Version)` identity.  Both
    /// paths converge on the same `TdhGetEventInformation` walker and the
    /// same [`EventData`] construction.
    ///
    /// All cache interaction is centralized here: the source is classified,
    /// the cache is probed, and only on a miss is a `decode_*` helper called
    /// to perform a real decode.  The freshly built schema is then assigned a
    /// `SchemaId` and inserted — so the helpers never touch the positive
    /// cache themselves.  This keeps a single insertion point, which future
    /// sources (e.g. injected EventSource manifests) can reuse without going
    /// through a `decode_*` path.
    ///
    /// The returned [`TdhDecodedEvent`] contains the decoded
    /// [`EventData`], the resolved `event_name`, and a monotonic
    /// [`SchemaId`] that exporters can use as a cheap lookup key for
    /// format registration.
    pub fn decode<'a>(
        &'a mut self,
        record: &'a EVENT_RECORD,
    ) -> Result<TdhDecodedEvent<'a>, TdhDecodeError> {
        let is_32bit = (record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;

        // Classify the schema source and compute its cache key.  This borrows
        // only `record`, never `self`, so the mutable `self` borrows below are
        // unconstrained.
        //
        // Classic (MOF/WBEM) events are rejected here rather than in the
        // manifest path: their identity is a class GUID + Opcode, not the
        // `(Provider, Id, Version)` tuple (their `Id` is commonly `0`, so
        // multiple such events would collapse onto one key), so they can never
        // form a valid `ManifestEventKey`.
        let source = match find_schema_tl(record) {
            Some(schema_tl_bytes) => SchemaSource::TraceLogging(schema_tl_bytes),
            None => {
                if (record.EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0 {
                    return Err(TdhDecodeError::Unsupported);
                }
                let desc = &record.EventHeader.EventDescriptor;
                SchemaSource::Manifest(ManifestEventKey {
                    provider: record.provider_guid(),
                    id: desc.Id,
                    version: desc.Version,
                })
            }
        };

        // Centralized caching: a hit reuses the arena slot; a miss performs a
        // real decode, assigns a `SchemaId`, and inserts under the key.  The
        // `usize` index is `Copy`, so every `self` borrow ends before the
        // `self.cache.get(idx)` read below.
        let idx = match self.lookup_cached(&source, is_32bit)? {
            Some(idx) => idx,
            None => {
                let mut schema = match &source {
                    SchemaSource::TraceLogging(_) => self.decode_tracelogging(record, is_32bit)?,
                    SchemaSource::Manifest(key) => self.decode_manifest(record, is_32bit, key)?,
                };
                schema.schema_id = SchemaId(self.assign_schema_id());
                self.insert_cached(source, is_32bit, schema)
            }
        };

        let schema = self.cache.get(idx);

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

    /// Looks up a classified schema `source` in the cache.
    ///
    /// Returns `Ok(Some(idx))` on a hit, `Ok(None)` on a miss (the caller
    /// should perform a real decode), or `Err(Unsupported)` when a manifest
    /// key is present in the negative cache.  The negative cache is checked
    /// here so a chatty unsupported provider skips the `TdhGetEventInformation`
    /// round trip on every event after the first.
    fn lookup_cached(
        &self,
        source: &SchemaSource,
        is_32bit: bool,
    ) -> Result<Option<usize>, TdhDecodeError> {
        match source {
            SchemaSource::TraceLogging(bytes) => Ok(self.cache.index_of_tl(bytes, is_32bit)),
            SchemaSource::Manifest(key) => {
                if let Some(idx) = self.cache.index_of_manifest(key, is_32bit) {
                    Ok(Some(idx))
                } else if self.cache.is_manifest_unsupported(key) {
                    Err(TdhDecodeError::Unsupported)
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Inserts a freshly decoded `schema` under its `source` key and returns
    /// the assigned arena index.  This is the single positive-cache insertion
    /// point shared by every schema source.
    fn insert_cached(
        &mut self,
        source: SchemaSource,
        is_32bit: bool,
        schema: CachedSchema,
    ) -> usize {
        match source {
            SchemaSource::TraceLogging(bytes) => {
                self.cache.insert_tl(bytes.to_vec(), is_32bit, schema)
            }
            SchemaSource::Manifest(key) => self.cache.insert_manifest(key, is_32bit, schema),
        }
    }

    /// Performs a real TraceLogging decode after a cache miss, returning the
    /// freshly built (but not yet cached) schema.
    ///
    /// The caller assigns the `SchemaId` and inserts the schema; this helper
    /// only walks the event via `TdhGetEventInformation`.
    fn decode_tracelogging(
        &mut self,
        record: &EVENT_RECORD,
        is_32bit: bool,
    ) -> Result<CachedSchema, TdhDecodeError> {
        call_tdh_get_event_information(record, &mut self.tei_buf)?;
        let schema = build_cached_schema(self.tei_buf.as_bytes(), is_32bit)?;
        debug!(
            event_name = %schema.event_name,
            field_count = schema.format.fields().len(),
            is_32bit,
            "TDH schema cache miss — decoded new TraceLogging schema"
        );
        Ok(schema)
    }

    /// Performs a real manifest decode after a cache miss, returning the
    /// freshly built (but not yet cached) schema.
    ///
    /// The caller assigns the `SchemaId` and inserts the schema; this helper
    /// only walks the event via `TdhGetEventInformation` and enforces the
    /// decoding-source guard:
    ///
    /// After `TdhGetEventInformation`, only a `DecodingSourceXMLFile` result
    /// is a genuine XML manifest.  WPP and WBEM results are returned as
    /// [`TdhDecodeError::Unsupported`] and the key is recorded in the negative
    /// cache, so a chatty unsupported provider pays the round trip only once.
    /// `NotFound` (unregistered manifest) is *not* negatively cached, since it
    /// can flip once a manifest registers.
    fn decode_manifest(
        &mut self,
        record: &EVENT_RECORD,
        is_32bit: bool,
        key: &ManifestEventKey,
    ) -> Result<CachedSchema, TdhDecodeError> {
        call_tdh_get_event_information(record, &mut self.tei_buf)?;

        // Only genuine XML-manifest schemas are cached here.  A "not
        // TraceLogging" event can still be WPP/WBEM, whose identity semantics
        // differ from `ManifestEventKey`; those are unsupported.
        let decoding_source = read_decoding_source(self.tei_buf.as_bytes())?;
        if decoding_source != DecodingSourceXMLFile {
            debug!(decoding_source, "TDH manifest path — unsupported decoding source");
            self.cache.mark_manifest_unsupported(*key);
            return Err(TdhDecodeError::Unsupported);
        }

        let schema = build_cached_schema(self.tei_buf.as_bytes(), is_32bit)?;
        debug!(
            event_name = %schema.event_name,
            id = key.id,
            version = key.version,
            field_count = schema.format.fields().len(),
            is_32bit,
            "TDH schema cache miss — decoded new manifest schema"
        );
        Ok(schema)
    }

    /// Allocates the next monotonic `SchemaId` value.
    fn assign_schema_id(&mut self) -> u64 {
        let id = self.next_schema_id;
        self.next_schema_id = id.wrapping_add(1);
        id
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
///
/// Returns `None` when the event carries no (or an empty) SCHEMA_TL item,
/// which is the signal for [`TdhDecoder::decode`] to take the manifest path.
fn find_schema_tl(record: &EVENT_RECORD) -> Option<&[u8]> {
    let item_ptr = record
        .find_extended_data(EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL as u16)?;
    let item = unsafe { &*item_ptr };
    if item.DataPtr == 0 || item.DataSize == 0 {
        return None;
    }
    Some(unsafe {
        std::slice::from_raw_parts(item.DataPtr as *const u8, item.DataSize as usize)
    })
}

/// Reads `TRACE_EVENT_INFO.DecodingSource` from a filled TEI buffer.
///
/// Used by the manifest dispatch path to reject non-XML-manifest sources
/// (WPP / WBEM) before they are cached under a `ManifestEventKey`.
fn read_decoding_source(tei_buf: &[u8]) -> Result<DECODING_SOURCE, TdhDecodeError> {
    if tei_buf.len() < std::mem::size_of::<TRACE_EVENT_INFO>() {
        return Err(TdhDecodeError::Malformed("buffer smaller than TRACE_EVENT_INFO"));
    }
    // SAFETY: the cast to `*const TRACE_EVENT_INFO` requires the buffer to be
    // suitably aligned.  Callers pass the `AlignedTeiBuf` backing store, whose
    // element type satisfies `TRACE_EVENT_INFO`'s alignment (guaranteed by the
    // const assertion next to `AlignedTeiBuf`).
    let tei = unsafe { &*(tei_buf.as_ptr() as *const TRACE_EVENT_INFO) };
    Ok(tei.DecodingSource)
}

/// Backing element type for [`AlignedTeiBuf`].  Its alignment must satisfy
/// `TRACE_EVENT_INFO`'s (checked by the const assertion below).
type TeiBufElem = u64;

// Guarantees every `AlignedTeiBuf` data pointer is suitably aligned for the
// `*const TRACE_EVENT_INFO` casts in `read_decoding_source` and
// `build_cached_schema`, so those reads stay sound.  If the backing element
// type ever changes to something under-aligned, the build fails here.
const _: () = assert!(
    std::mem::align_of::<TeiBufElem>() >= std::mem::align_of::<TRACE_EVENT_INFO>(),
    "AlignedTeiBuf backing element must satisfy TRACE_EVENT_INFO alignment"
);

/// Aligned buffer for `TRACE_EVENT_INFO`.
struct AlignedTeiBuf {
    storage: Vec<TeiBufElem>,
    len: usize,
}

impl AlignedTeiBuf {
    fn new() -> Self {
        Self { storage: Vec::new(), len: 0 }
    }

    fn ensure_capacity(&mut self, byte_count: usize) {
        let elem_size = std::mem::size_of::<TeiBufElem>();
        let elem_count = (byte_count + elem_size - 1) / elem_size;
        if self.storage.len() < elem_count {
            self.storage.resize(elem_count, 0);
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
//
// Pin the union's layout to `u32`'s (both size *and* alignment) so the
// `tei.Anonymous1.EventNameOffset` read stays sound: a future `windows-sys`
// bump that grows the union or changes its alignment fails the build here
// rather than silently mis-reading the field.
const _: () = assert!(
    std::mem::size_of::<
        windows_sys::Win32::System::Diagnostics::Etw::TRACE_EVENT_INFO_0
    >() == std::mem::size_of::<u32>(),
    "TRACE_EVENT_INFO_0 union must stay the size of a u32",
);
const _: () = assert!(
    std::mem::align_of::<
        windows_sys::Win32::System::Diagnostics::Etw::TRACE_EVENT_INFO_0
    >() == std::mem::align_of::<u32>(),
    "TRACE_EVENT_INFO_0 union must stay u32-aligned",
);

/// Reads the event name from `TRACE_EVENT_INFO`, selecting the offset by
/// decoding source.
///
/// TraceLogging carries the name at `EventNameOffset`; manifest and WPP
/// events instead expose it as the task name at `TaskNameOffset`.  The
/// dispatch in [`TdhDecoder::decode`] only builds manifest schemas for
/// `DecodingSourceXMLFile`, so in practice this reads `EventNameOffset` for
/// TraceLogging and `TaskNameOffset` for manifest events.
fn read_event_name(tei_buf: &[u8], tei: &TRACE_EVENT_INFO) -> String {
    let name_offset = if tei.DecodingSource == DecodingSourceTlg {
        // SAFETY: Both arms of `TRACE_EVENT_INFO_0` are `u32` at the same
        // offset, so either arm always yields a valid bit pattern.  The
        // const assertion above guards the 4-byte size against future
        // `windows-sys` layout drift.
        unsafe { tei.Anonymous1.EventNameOffset as usize }
    } else {
        tei.TaskNameOffset as usize
    };
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
        TDH_INTYPE_UINT8                         => ("u8",   LocationType::Static, 1),
        TDH_INTYPE_INT16                         => ("s16",  LocationType::Static, 2),
        TDH_INTYPE_UINT16                        => ("u16",  LocationType::Static, 2),
        TDH_INTYPE_INT32 | TDH_INTYPE_HEXINT32  => ("s32",  LocationType::Static, 4),
        TDH_INTYPE_UINT32                        => ("u32",  LocationType::Static, 4),
        // `TDH_INTYPE_BOOLEAN` is a Win32 `BOOL` — a 32-bit value
        // (TraceLogging `bool32`).  It is **not** a 1-byte boolean:
        // mapping it as `u8` would mis-size every subsequent field in
        // the same event.  TraceLogging encodes 1-byte booleans as
        // `TDH_INTYPE_UINT8` with `OutType::Boolean` (`bool8`).
        TDH_INTYPE_BOOLEAN                       => ("u32",  LocationType::Static, 4),
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
        assert_eq!(intype_to_type_name(TDH_INTYPE_UINT8), "u8");
        assert_eq!(intype_to_type_name(TDH_INTYPE_UINT32), "u32");
        assert_eq!(intype_to_type_name(TDH_INTYPE_DOUBLE), "double");
        assert_eq!(intype_to_type_name(TDH_INTYPE_GUID), "guid");
        assert_eq!(intype_to_type_name(TDH_INTYPE_UNICODESTRING), "wstring");
        assert_eq!(intype_to_type_name(TDH_INTYPE_ANSISTRING), "string");
        assert_eq!(intype_to_type_name(TDH_INTYPE_BINARY), "binary");
        assert_eq!(intype_to_type_name(999), "unsupported");
    }

    /// `TDH_INTYPE_BOOLEAN` is a Win32 `BOOL`, a 32-bit value
    /// (TraceLogging `bool32`).  Mapping it as `u8` (its previous
    /// behaviour) would mis-size every subsequent field in the same
    /// event.  TraceLogging encodes 1-byte booleans as
    /// `TDH_INTYPE_UINT8` with `OutType::Boolean` (`bool8`), which is
    /// covered by the `u8` case in `type_name_scalars`.
    #[test]
    fn type_name_boolean_is_u32() {
        assert_eq!(intype_to_type_name(TDH_INTYPE_BOOLEAN), "u32");
        let (name, loc, size) = intype_to_field_info(TDH_INTYPE_BOOLEAN, false);
        assert_eq!(name, "u32");
        assert_eq!(loc, LocationType::Static);
        assert_eq!(size, 4);
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
    fn tdh_decode_distinct_schemas_interleaved() {
        // Exercises the index -> schema mapping introduced by the append-only
        // `schemas` Vec.  With multiple distinct schemas cached, a bug that
        // mixed up indices (e.g. always returning the last-inserted schema)
        // would be caught here but not by the single-schema cache tests.
        let schema_a = build_tl_schema("ProviderA", "EventA", &[
            ("A", TL_UINT32),
        ]);
        let schema_b = build_tl_schema("ProviderB", "EventB", &[
            ("B1", TL_UINT32),
            ("B2", TL_UINT32),
        ]);
        let (prov_a, evt_a) = split_tl_schema(&schema_a);
        let (prov_b, evt_b) = split_tl_schema(&schema_b);

        let mut decoder = TdhDecoder::new();

        // First decode of each schema populates the cache with two entries.
        let ud_a = 1u32.to_le_bytes();
        let mut ext_a: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let rec_a = build_test_record(prov_a, evt_a, &mut ext_a, &ud_a);
        let ra = decoder.decode(&rec_a).expect("decode A");
        let id_a = ra.schema_id;
        assert_eq!(ra.event_name, Some("EventA"));
        assert_eq!(ra.event_data.format().fields().len(), 1);

        let ud_b = [3u32.to_le_bytes(), 4u32.to_le_bytes()].concat();
        let mut ext_b: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let rec_b = build_test_record(prov_b, evt_b, &mut ext_b, &ud_b);
        let rb = decoder.decode(&rec_b).expect("decode B");
        let id_b = rb.schema_id;
        assert_eq!(rb.event_name, Some("EventB"));
        assert_eq!(rb.event_data.format().fields().len(), 2);
        assert_ne!(id_a, id_b, "distinct schemas must get distinct SchemaIds");

        // Re-decode in reversed order: both are cache hits and each must read
        // back its own schema, not the other's.
        let mut ext_b2: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let rec_b2 = build_test_record(prov_b, evt_b, &mut ext_b2, &ud_b);
        let rb2 = decoder.decode(&rec_b2).expect("cache hit B");
        assert_eq!(rb2.schema_id, id_b, "B cache hit should map to B's schema");
        assert_eq!(rb2.event_name, Some("EventB"));
        assert_eq!(rb2.event_data.format().fields().len(), 2);

        let mut ext_a2: [EVENT_HEADER_EXTENDED_DATA_ITEM; 2] = unsafe { std::mem::zeroed() };
        let rec_a2 = build_test_record(prov_a, evt_a, &mut ext_a2, &ud_a);
        let ra2 = decoder.decode(&rec_a2).expect("cache hit A");
        assert_eq!(ra2.schema_id, id_a, "A cache hit should map to A's schema");
        assert_eq!(ra2.event_name, Some("EventA"));
        assert_eq!(ra2.event_data.format().fields().len(), 1);
    }

    #[test]
    fn tdh_decode_not_found_without_schema_tl() {
        // A non-classic EVENT_RECORD with no SCHEMA_TL item takes the
        // manifest path.  With a zeroed (unregistered) provider GUID,
        // TdhGetEventInformation returns ERROR_NOT_FOUND, which surfaces as
        // TdhDecodeError::NotFound — the public-API contract for events
        // whose schema can't be resolved on this machine.
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

    // ── Manifest-path tests ─────────────────────────────────────────

    /// Classic (MOF/WBEM) events must be fast-rejected before any TDH call:
    /// their identity is a class GUID + Opcode, not `(Provider, Id, Version)`,
    /// and their `Id` is commonly 0, so routing them through the manifest
    /// cache would collapse distinct events onto one key.
    #[test]
    fn tdh_decode_classic_header_rejected_before_tdh() {
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.ExtendedDataCount = 0;
        record.ExtendedData = std::ptr::null_mut();
        record.EventHeader.Flags |= EVENT_HEADER_FLAG_CLASSIC_HEADER;

        let mut decoder = TdhDecoder::new();
        match decoder.decode(&record) {
            Err(TdhDecodeError::Unsupported) => {} // expected — rejected during source classification
            Err(other) => panic!("expected Unsupported for classic header, got: {other}"),
            Ok(_) => panic!("expected Unsupported error, but decode succeeded"),
        }
    }

    /// `read_event_name` must pick `EventNameOffset` for TraceLogging and
    /// `TaskNameOffset` for manifest events, selected by `DecodingSource`.
    #[test]
    fn read_event_name_selects_offset_by_decoding_source() {
        fn push_utf16(buf: &mut Vec<u8>, s: &str) {
            for u in s.encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&[0, 0]); // UTF-16 null terminator
        }

        // Layout: [TRACE_EVENT_INFO-sized header][EventName][TaskName].
        let mut buf = vec![0u8; std::mem::size_of::<TRACE_EVENT_INFO>()];
        let event_off = buf.len();
        push_utf16(&mut buf, "EventName");
        let task_off = buf.len();
        push_utf16(&mut buf, "TaskName");

        let mut tei: TRACE_EVENT_INFO = unsafe { std::mem::zeroed() };
        tei.TaskNameOffset = task_off as u32;
        // Writing a union field is safe; only reads are `unsafe`.
        tei.Anonymous1.EventNameOffset = event_off as u32;

        tei.DecodingSource = DecodingSourceTlg;
        assert_eq!(read_event_name(&buf, &tei), "EventName");

        tei.DecodingSource = DecodingSourceXMLFile;
        assert_eq!(read_event_name(&buf, &tei), "TaskName");
    }

    /// The manifest maps and the TraceLogging maps share one append-only
    /// arena but are indexed by different key types.  Verify that: entries
    /// never alias across sources, the 32-/64-bit split is honoured, and a
    /// duplicate manifest insert returns the existing index.
    #[test]
    fn manifest_cache_shared_arena_and_pointer_split() {
        let mk = |name: &str| CachedSchema {
            event_name: name.to_string(),
            format: EventFormat::new(),
            schema_id: SchemaId(0),
        };
        let key = ManifestEventKey {
            provider: Guid::from_u128(0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00),
            id: 5,
            version: 2,
        };

        let mut cache = SchemaCache::new();

        // 64-bit insert, then hit.
        let idx_a = cache.insert_manifest(key, false, mk("A"));
        assert_eq!(cache.index_of_manifest(&key, false), Some(idx_a));

        // The 32-bit map is a separate keyspace: same key misses there.
        assert_eq!(cache.index_of_manifest(&key, true), None);
        let idx_b = cache.insert_manifest(key, true, mk("B"));
        assert_ne!(idx_a, idx_b, "32-/64-bit split must yield distinct slots");

        // TraceLogging shares the arena but is indexed separately.
        let tl_idx = cache.insert_tl(vec![1, 2, 3], false, mk("C"));
        assert_ne!(tl_idx, idx_a);
        assert_ne!(tl_idx, idx_b);
        assert_eq!(cache.index_of_tl(&[1, 2, 3], false), Some(tl_idx));

        // Each index reads back its own schema — no cross-source aliasing.
        assert_eq!(cache.get(idx_a).event_name, "A");
        assert_eq!(cache.get(idx_b).event_name, "B");
        assert_eq!(cache.get(tl_idx).event_name, "C");

        // A duplicate manifest insert returns the existing index and drops
        // the freshly built schema (no arena orphan).
        let before = cache.schemas.len();
        assert_eq!(cache.insert_manifest(key, false, mk("dup")), idx_a);
        assert_eq!(cache.schemas.len(), before, "duplicate must not grow arena");
        assert_eq!(cache.get(idx_a).event_name, "A", "original schema preserved");
    }

    /// The negative cache records permanently-unsupported manifest keys and
    /// is pointer-width independent (the decoding source doesn't depend on
    /// payload width).  Verify a marked key reports unsupported regardless of
    /// the `is_32bit` probe and that an unmarked key does not.
    #[test]
    fn manifest_unsupported_negative_cache() {
        let key = ManifestEventKey {
            provider: Guid::from_u128(0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF),
            id: 7,
            version: 1,
        };
        let other = ManifestEventKey {
            provider: key.provider,
            id: 8,
            version: 1,
        };

        let mut cache = SchemaCache::new();
        assert!(!cache.is_manifest_unsupported(&key));

        cache.mark_manifest_unsupported(key);
        assert!(cache.is_manifest_unsupported(&key), "marked key must report unsupported");
        assert!(!cache.is_manifest_unsupported(&other), "distinct key unaffected");

        // Marking is not a positive-cache entry: index lookups still miss.
        assert_eq!(cache.index_of_manifest(&key, false), None);
        assert_eq!(cache.index_of_manifest(&key, true), None);
    }

    /// `read_decoding_source` must reject a buffer smaller than
    /// `TRACE_EVENT_INFO` (its bounds check guards the subsequent
    /// `*const TRACE_EVENT_INFO` cast) and, for a well-formed buffer,
    /// return the exact `DecodingSource` value stored in it.
    #[test]
    fn read_decoding_source_bounds_and_value() {
        // Under-sized buffer → Malformed, and (crucially) the cast is never
        // reached, so an unaligned `Vec<u8>` here is fine.
        let too_small = vec![0u8; std::mem::size_of::<TRACE_EVENT_INFO>() - 1];
        match read_decoding_source(&too_small) {
            Err(TdhDecodeError::Malformed(_)) => {} // expected
            other => panic!("expected Malformed for under-sized buffer, got: {other:?}"),
        }

        // Value path: build a real, properly-aligned `TRACE_EVENT_INFO` on the
        // stack, then view it as bytes.  Deriving the slice from the struct's
        // own address guarantees the alignment `read_decoding_source` requires.
        fn tei_bytes(tei: &TRACE_EVENT_INFO) -> &[u8] {
            // SAFETY: `tei` is a live `TRACE_EVENT_INFO`, so the pointer is
            // valid, aligned, and spans exactly `size_of::<TRACE_EVENT_INFO>()`
            // initialized bytes for the borrow's lifetime.
            unsafe {
                std::slice::from_raw_parts(
                    tei as *const TRACE_EVENT_INFO as *const u8,
                    std::mem::size_of::<TRACE_EVENT_INFO>(),
                )
            }
        }

        let mut tei: TRACE_EVENT_INFO = unsafe { std::mem::zeroed() };

        tei.DecodingSource = DecodingSourceXMLFile;
        assert_eq!(read_decoding_source(tei_bytes(&tei)).unwrap(), DecodingSourceXMLFile);

        tei.DecodingSource = DecodingSourceTlg;
        assert_eq!(read_decoding_source(tei_bytes(&tei)).unwrap(), DecodingSourceTlg);
    }

    /// TraceLogging inserts mirror the manifest single-hash vacancy semantics:
    /// a duplicate `insert_tl` returns the existing index without growing the
    /// arena (no orphaned schema), and the 32-/64-bit maps stay separate
    /// keyspaces for identical bytes.
    #[test]
    fn insert_tl_duplicate_key_returns_existing_index() {
        let mk = |name: &str| CachedSchema {
            event_name: name.to_string(),
            format: EventFormat::new(),
            schema_id: SchemaId(0),
        };

        let mut cache = SchemaCache::new();

        let idx = cache.insert_tl(vec![9, 8, 7], false, mk("first"));
        assert_eq!(cache.index_of_tl(&[9, 8, 7], false), Some(idx));

        // Duplicate insert returns the existing index and drops the freshly
        // built schema — the arena must not grow.
        let before = cache.schemas.len();
        assert_eq!(cache.insert_tl(vec![9, 8, 7], false, mk("dup")), idx);
        assert_eq!(cache.schemas.len(), before, "duplicate must not grow arena");
        assert_eq!(cache.get(idx).event_name, "first", "original schema preserved");

        // The 32-bit map is a separate keyspace: the same bytes miss there.
        assert_eq!(cache.index_of_tl(&[9, 8, 7], true), None);
    }
}
