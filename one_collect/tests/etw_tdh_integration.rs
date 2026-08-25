// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! End-to-end integration tests for the runtime TDH decoder.
//!
//! Most tests register a real TraceLogging ETW provider (using the
//! `tracelogging` and `tracelogging_dynamic` crates), emit known events
//! through ETW, capture them inside an [`EtwSession`], decode them with
//! [`TdhDecoder`], and assert that the decoded field values match what
//! was written.
//!
//! The final test ([`tdh_decodes_manifest_kernel_process_events`])
//! instead exercises the *manifest* decode path against a live,
//! always-registered OS provider (`Microsoft-Windows-Kernel-Process`).
//! It cannot fabricate a registered manifest, so it triggers real
//! process-lifetime events by spawning short-lived child processes and
//! asserts that they decode through `TdhGetEventInformation` into a real
//! `EventFormat` with a Task-derived event name.
//!
//! All tests are marked `#[ignore]` because the consumer side of ETW
//! requires administrative privileges (`SeSystemProfilePrivilege` /
//! `SeDebugPrivilege`).  Run manually from an elevated shell with:
//!
//! ```text
//! cargo test -p one_collect --test etw_tdh_integration -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` is required: each test starts its own ETW kernel
//! consumer session and registers the same TraceLogging provider GUID
//! in this process.  Running the tests concurrently would race on those
//! process- and system-global resources.

#![cfg(target_os = "windows")]

use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use one_collect::{Guid, Writable};
use one_collect::etw::{EtwSession, LEVEL_VERBOSE};
use one_collect::etw::tdh::TdhDecoder;
use one_collect::event::Event;
use one_collect::event::os::windows::WindowsEventExtension;

use tracelogging as tlg;
use tracelogging_dynamic as tld;

// ── Test fixtures ────────────────────────────────────────────────────

/// Keyword used by every event the tests emit (and the value the wide
/// event subscribes to via `MatchAnyKeyword`).
const TEST_KEYWORD: u64 = 0x1;

/// GUID of the always-registered `Microsoft-Windows-Kernel-Process`
/// manifest provider, `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`.
///
/// Used by the manifest-path integration test: it is present on every
/// supported Windows SKU, is a normal (non-legacy-kernel-logger) manifest
/// provider that a user-mode session can enable, and emits Task-bearing
/// `ProcessStart` / `ProcessStop` events that the test triggers on demand
/// by spawning child processes.
const KERNEL_PROCESS_PROVIDER: u128 = 0x22FB2CD6_0E7B_422B_A0C7_2FAD1FD0E716;

/// Task names the Kernel-Process manifest assigns to process-lifetime
/// events (Ids 1 and 2).  Both carry a Task, so the decoder's
/// `TaskNameOffset` path must surface them as the event name.
const KERNEL_PROCESS_TASKS: &[&str] = &["ProcessStart", "ProcessStop"];

/// Manifest event Ids for the process-lifetime events the manifest test
/// validates: `ProcessStart` (Id 1) and `ProcessStop` (Id 2).
///
/// These are watched at the *raw-record* level (via the pre-decode
/// observer), so the test can stop as soon as the events it asserts on are
/// physically present — regardless of whether TDH decode succeeds.  That
/// makes a broken decode surface as a clear assertion failure instead of a
/// `TEST_TIMEOUT` hang, and avoids depending on an arbitrary total event
/// count that may or may not include the events of interest.
const KERNEL_PROCESS_EVENT_IDS: &[u16] = &[1, 2];

/// Hard upper bound on a single test run — should never be reached when
/// running on a healthy ETW subsystem.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Expected u32 value in "EventNumbers".
///
/// `0xDEADBEEF` is chosen deliberately: every byte is distinct and the
/// value is asymmetric, so any byte-order or offset-by-one regression
/// in the decoder will fail the assertion (a palindromic or
/// repeated-byte constant could mask such bugs).  Do not change this
/// value without keeping that property.
const EXPECTED_U32: u32 = 0xDEADBEEF;
/// Expected u64 value in "EventNumbers".
///
/// Chosen with the same byte-distinctness property as `EXPECTED_U32`
/// (each byte 0x01..=0x08 is unique).
const EXPECTED_U64: u64 = 0x0102_0304_0506_0708;
/// Expected ANSI/UTF-8 string in "EventStrings".
const EXPECTED_STR8: &str = "hello-from-tdh";
/// Expected UTF-16 string in "EventStrings".
const EXPECTED_STR16: &[u16] = &[
    b'w' as u16, b'i' as u16, b'd' as u16, b'e' as u16,
    b'-' as u16, b'w' as u16, b'o' as u16, b'r' as u16,
    b'l' as u16, b'd' as u16,
];

/// Expected f32 (`InType::F32`) value in "EventScalars".
const EXPECTED_F32: f32 = std::f32::consts::PI;
/// Expected f64 (`InType::F64`) value in "EventScalars".
const EXPECTED_F64: f64 = std::f64::consts::E;
/// Expected bool8 (`InType::U8` + `OutType::Boolean`) value in "EventScalars".
///
/// TraceLogging encodes `true` as the byte `1` and `false` as `0`.
const EXPECTED_BOOL8: u8 = 1;
/// Expected bool32 (`InType::Bool32`, Win32 `BOOL`) value in "EventScalars".
///
/// `TDH_INTYPE_BOOLEAN` is a 4-byte signed integer where `0` is
/// `false` and any non-zero value is `true`.  We use `-1` (`0xFFFFFFFF`)
/// because it is asymmetric, sign-extends distinctly through the
/// `u32 as i32` round-trip, and shares no bytes with the surrounding
/// FILETIME / SYSTEMTIME / GUID payloads — making any byte-order or
/// offset-by-N regression unambiguous in the failure diff.
///
/// Note that the historical "decoded as 1 byte" bug is caught
/// independently of this value: a 1-byte field declaration causes
/// `get_u32` here to fail (it requires ≥ 4 bytes), and the 3 unconsumed
/// on-wire bytes shift every subsequent field's offset, which the
/// FILETIME assertion would catch on its own.
const EXPECTED_BOOL32: i32 = -1;
/// Expected FILETIME (`InType::FileTime`, 64-bit) value in "EventScalars".
///
/// 100-nanosecond intervals since 1601-01-01 UTC.  This value
/// corresponds to a real-but-arbitrary timestamp in mid-2021 and is
/// only used to verify byte-exact round-tripping.
const EXPECTED_FILETIME: i64 = 132_580_056_000_000_000;
/// Expected SYSTEMTIME (`InType::SystemTime`, 16-byte calendar form) value
/// in "EventScalars".
///
/// On the wire SYSTEMTIME is **8 packed little-endian `u16` fields** in
/// the order: `wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute,
/// wSecond, wMilliseconds`.  The decoder does not validate calendar
/// correctness — these bytes round-trip verbatim.
const EXPECTED_SYSTEMTIME: [u16; 8] = [2021, 7, 1, 5, 12, 34, 56, 789];
/// Expected GUID (`InType::Guid`, 16 bytes in Windows little-endian
/// COM layout) value in "EventScalars".
const EXPECTED_GUID: tlg::Guid = tlg::Guid::from_fields(
    0xDEAD_BEEF,
    0x1234,
    0x5678,
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
);

/// Expected u32 value for the outer top-level field in "EventNested".
const EXPECTED_NESTED_TOP: u32 = 100;
/// Expected u32 value for the first inner-struct field in "EventNested".
const EXPECTED_NESTED_INNER_A: u32 = 200;
/// Expected u64 value for the second inner-struct field in "EventNested".
const EXPECTED_NESTED_INNER_B: u64 = 300;
/// Expected u32 value for the second top-level field in "EventNested".
const EXPECTED_NESTED_BOTTOM: u32 = 400;

/// A decoded event captured by the wide-event callback.
struct CapturedEvent {
    name: String,
    field_names: Vec<String>,
    field_types: Vec<String>,
    payload: Vec<u8>,
    format: one_collect::event::EventFormat,
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Converts a `tracelogging::Guid` into the framework's `one_collect::Guid`.
///
/// Both crates store the GUID using the same in-memory layout (Microsoft
/// COM `DataN`-style fields), and their `to_u128`/`from_u128` helpers
/// agree on bit positions, so a round trip through `u128` is the
/// well-defined conversion.
fn tlg_guid_to_oc(g: tlg::Guid) -> Guid {
    Guid::from_u128(g.to_u128())
}

/// Builds an [`EtwSession`] configured to capture every event from
/// `provider_guid` and run `on_decoded` for each successful TDH decode.
///
/// Returns the session ready to be parsed by [`EtwSession::parse_until`].
fn build_capturing_session<F>(
    provider_guid: Guid,
    wide_name: &str,
    on_decoded: F,
) -> EtwSession
where
    F: FnMut(&one_collect::etw::tdh::TdhDecodedEvent<'_>) + 'static,
{
    // Most tests don't care about raw-record identity, only successful
    // decodes — pass a no-op record observer.
    build_capturing_session_observed(provider_guid, wide_name, on_decoded, |_id| {})
}

/// Like [`build_capturing_session`], but also invokes `on_record` with the
/// event Id of *every* record before it is decoded.
///
/// The pre-decode observer fires regardless of whether TDH decode later
/// succeeds, so a test can watch for the presence of specific events (by
/// Id) even when it cannot rely on those events decoding cleanly.
fn build_capturing_session_observed<F, R>(
    provider_guid: Guid,
    wide_name: &str,
    mut on_decoded: F,
    mut on_record: R,
) -> EtwSession
where
    F: FnMut(&one_collect::etw::tdh::TdhDecodedEvent<'_>) + 'static,
    R: FnMut(u16) + 'static,
{
    let mut session = EtwSession::new();
    let ancillary = session.ancillary_data();
    let decoder = Rc::new(RefCell::new(TdhDecoder::new()));

    let mut event = Event::for_etw(
        0,
        wide_name.to_string(),
        provider_guid,
        LEVEL_VERBOSE,
        // MatchAnyKeyword — capture every keyword bit this provider uses.
        u64::MAX,
    );

    event.set_id_wild_card_flag();

    event.add_callback(move |_data| {
        let ancillary_ref = ancillary.borrow();
        let record = match ancillary_ref.record() {
            Some(r) => r,
            None => return Ok(()),
        };

        // Observe the raw record identity before attempting a decode, so
        // callers can detect that an event of interest arrived even if the
        // decode below fails.
        on_record(ancillary_ref.id());

        let mut decoder = decoder.borrow_mut();

        // TraceLogging providers shouldn't emit non-TraceLogging events,
        // but be defensive: don't fail the session callback on a stray
        // decode error (that would propagate and stop processing for
        // every subsequent event).  Surface it via `eprintln!` so it's
        // still visible in `--nocapture` output for debugging.
        match decoder.decode(record) {
            Ok(decoded) => on_decoded(&decoded),
            Err(e) => eprintln!("WARN: TDH decode failed for a record: {e:?}"),
        }

        Ok(())
    });

    session.add_event(event, None);
    session
}

/// Builds the captured-events sink, an event counter, and the callback
/// that drives both.
///
/// The sink is a `Writable<Vec<CapturedEvent>>` (which is `Rc`-based and
/// therefore single-threaded) — that is safe because the wide-event
/// callback runs on the same thread as `EtwSession::parse_until` (the
/// test thread).
///
/// The counter is a cross-thread atomic shared with the `parse_until`
/// predicate, which runs on the parse worker thread.
fn make_capture_sink() -> (
    Writable<Vec<CapturedEvent>>,
    Arc<AtomicUsize>,
    impl FnMut(&one_collect::etw::tdh::TdhDecodedEvent<'_>) + 'static,
) {
    let captured: Writable<Vec<CapturedEvent>> = Writable::new(Vec::new());
    let counter = Arc::new(AtomicUsize::new(0));
    let captured_for_cb = captured.clone();
    let counter_for_cb = counter.clone();

    let callback = move |decoded: &one_collect::etw::tdh::TdhDecodedEvent<'_>| {
        let name = decoded.event_name.unwrap_or("").to_string();
        let format = decoded.event_data.format();

        // Snapshot the schema + raw payload bytes so we can assert on
        // them after `parse_until` returns and the original `EVENT_RECORD`
        // is long gone.
        let field_names: Vec<String> =
            format.fields().iter().map(|f| f.name.clone()).collect();
        let field_types: Vec<String> =
            format.fields().iter().map(|f| f.type_name.clone()).collect();
        let payload = decoded.event_data.event_data().to_vec();
        let format_clone = format.clone();

        captured_for_cb.borrow_mut().push(CapturedEvent {
            name,
            field_names,
            field_types,
            payload,
            format: format_clone,
        });
        counter_for_cb.fetch_add(1, Ordering::Relaxed);
    };

    (captured, counter, callback)
}

/// Polls `is_enabled` every 10 ms until it returns `true` or
/// `TEST_TIMEOUT` elapses.  On timeout, logs a `WARN` so the resulting
/// 0-event capture failure has an obvious explanation.
///
/// `what` is a short label used only in the warning message.
fn wait_until_enabled(what: &str, is_enabled: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !is_enabled() {
        if Instant::now() >= deadline {
            eprintln!(
                "WARN: {what} never became enabled — \
                 the test will fail at assertion time"
            );
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

/// Returns the index of the first captured event with the given name.
/// Panics with a descriptive message if no such event exists.
fn find_event<'a>(
    captured: &'a [CapturedEvent],
    name: &str,
) -> &'a CapturedEvent {
    captured
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| {
            let names: Vec<&str> =
                captured.iter().map(|e| e.name.as_str()).collect();
            panic!(
                "expected to capture an event named {name:?}, but only saw {names:?}"
            );
        })
}

/// Drives `session` until `stop` returns `true` (or `TEST_TIMEOUT`
/// elapses), then returns a borrowed snapshot of the captured events.
///
/// `stop` runs on the `parse_until` worker thread (see
/// [`EtwSession::parse_until`]), so it must only read cross-thread-safe
/// state — e.g. an `Arc<AtomicUsize>`/`Arc<AtomicBool>` updated from the
/// capture callback.  Takes `session` by value because `parse_until`
/// consumes `self`.
fn drive_until<'a>(
    session: EtwSession,
    session_name: &str,
    captured: &'a Writable<Vec<CapturedEvent>>,
    stop: impl Fn() -> bool + Send + 'static,
) -> std::cell::Ref<'a, Vec<CapturedEvent>> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    session
        .parse_until(session_name, move || {
            stop() || Instant::now() >= deadline
        })
        .expect("parse_until failed (is the test running elevated?)");

    captured.borrow()
}

/// Runs `session` until `expected` events have been captured (or
/// `TEST_TIMEOUT` elapses), then asserts the minimum count and returns a
/// borrowed snapshot of the captured events.
///
/// Centralises the `parse_until` + deadline + minimum-count assertion
/// pattern shared by the TraceLogging tests in this file.
fn drive_to_completion<'a>(
    session: EtwSession,
    session_name: &str,
    captured: &'a Writable<Vec<CapturedEvent>>,
    counter: Arc<AtomicUsize>,
    expected: usize,
) -> std::cell::Ref<'a, Vec<CapturedEvent>> {
    let snapshot = drive_until(session, session_name, captured, move || {
        counter.load(Ordering::Relaxed) >= expected
    });

    assert!(
        snapshot.len() >= expected,
        "expected at least {expected} captured events, got {} ({:?})",
        snapshot.len(),
        snapshot.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
    snapshot
}

/// Asserts the captured event has exactly the given field names and
/// type-names in the given order.
///
/// Compares as `&str` slices so call sites don't have to write
/// `vec!["X".to_string(), ...]`.
fn assert_schema(
    event: &CapturedEvent,
    expected_names: &[&str],
    expected_types: &[&str],
    ctx: &str,
) {
    let actual_names: Vec<&str> =
        event.field_names.iter().map(|s| s.as_str()).collect();
    let actual_types: Vec<&str> =
        event.field_types.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        actual_names, expected_names,
        "{ctx} field-name layout"
    );
    assert_eq!(
        actual_types, expected_types,
        "{ctx} field-type layout"
    );
}

/// Reads exactly `N` raw bytes from the named field, panicking with a
/// clear message if the field is missing or has a different on-wire
/// length.  Used for fixed-size in-types that have no typed accessor
/// on `EventFormat` (f32, f64, SYSTEMTIME, GUID, ...).
fn read_fixed<const N: usize>(
    event: &CapturedEvent,
    name: &str,
) -> [u8; N] {
    let field_ref = event.format.get_field_ref(name)
        .unwrap_or_else(|| panic!("{name} field should exist"));
    let bytes = event.format.get_data(field_ref, &event.payload);
    bytes.try_into().unwrap_or_else(|_| {
        panic!("{name} field should be {N} bytes, got {}", bytes.len())
    })
}

/// Asserts every field value in an "EventNumbers" event matches the
/// constants written by the producer.
fn assert_numbers_event(event: &CapturedEvent) {
    assert_schema(
        event,
        &["Count", "BigCount"],
        &["u32", "u64"],
        "numbers event",
    );

    let count_ref = event.format.get_field_ref("Count")
        .expect("Count field should exist");
    let big_ref = event.format.get_field_ref("BigCount")
        .expect("BigCount field should exist");

    let count = event.format.get_u32(count_ref, &event.payload)
        .expect("Count should decode as u32");
    let big_count = event.format.get_u64(big_ref, &event.payload)
        .expect("BigCount should decode as u64");

    assert_eq!(count, EXPECTED_U32, "u32 field round-trip mismatch");
    assert_eq!(big_count, EXPECTED_U64, "u64 field round-trip mismatch");
}

/// Asserts every field value in an "EventStrings" event matches the
/// constants written by the producer.
///
/// "Message" is a TraceLogging *counted* ANSI string (str8), which the
/// TDH decoder maps to `LocationType::StaticLenPrefixArray` with a
/// 2-byte length prefix.  "Name" is a *null-terminated* UTF-16 string
/// (cstr16), which maps to `LocationType::StaticUTF16String`.
fn assert_strings_event(event: &CapturedEvent) {
    assert_schema(
        event,
        &["Message", "Name"],
        &["counted_string", "wstring"],
        "strings event",
    );

    let message = event.format
        .fields_with_data(&event.payload)
        .find(|(field, _)| field.name == "Message")
        .map(|(_, bytes)| bytes)
        .expect("Message accessor should exist");

    assert_eq!(
        message,
        EXPECTED_STR8.as_bytes(),
        "ANSI counted string round-trip mismatch"
    );

    // UTF-16 fields are returned as raw little-endian bytes (excluding
    // the trailing NUL).  Decode to verify code units round-trip.
    let name_bytes = event.format
        .fields_with_data(&event.payload)
        .find(|(field, _)| field.name == "Name")
        .map(|(_, bytes)| bytes)
        .expect("Name accessor should exist");
    assert_eq!(
        name_bytes.len(),
        EXPECTED_STR16.len() * 2,
        "UTF-16 byte length mismatch"
    );
    let name_units: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(
        name_units, EXPECTED_STR16,
        "UTF-16 code units round-trip mismatch"
    );
}

/// Asserts every field value in an "EventScalars" event matches the
/// constants written by the producer.
///
/// Exercises the seven fixed-size in-types not covered by the integer
/// tests:
///
/// * `f32` → `TDH_INTYPE_FLOAT`  → `("float",  Static, 4)`
/// * `f64` → `TDH_INTYPE_DOUBLE` → `("double", Static, 8)`
/// * `bool8` (TLG `InType::U8` + `OutType::Boolean`) → `TDH_INTYPE_UINT8`
///   → `("u8", Static, 1)` (TLG encodes `bool8` as a 1-byte integer with
///   a `Boolean` out-type hint, so it shares the `u8` decoder path)
/// * `bool32` (TLG `InType::Bool32`) → `TDH_INTYPE_BOOLEAN`
///   → `("u32", Static, 4)` (Win32 `BOOL` is a 32-bit value; a previous
///   decoder bug mapped this to `("u8", Static, 1)`, which would
///   mis-size every field after it in the same event)
/// * `filetime`   → `TDH_INTYPE_FILETIME`   → `("filetime",   Static, 8)`
/// * `systemtime` → `TDH_INTYPE_SYSTEMTIME` → `("systemtime", Static, 16)`
/// * `guid`       → `TDH_INTYPE_GUID`       → `("guid",       Static, 16)`
fn assert_scalars_event(event: &CapturedEvent) {
    assert_schema(
        event,
        &["Pi", "E", "Flag", "WideFlag", "Created", "When", "Id"],
        &["float", "double", "u8", "u32", "filetime", "systemtime", "guid"],
        "scalars event",
    );

    // f32 / f64 — read raw bytes and decode manually since `EventFormat`
    // does not expose typed float accessors.  `read_fixed` enforces the
    // 4/8-byte on-wire length.
    let pi = f32::from_le_bytes(read_fixed::<4>(event, "Pi"));
    assert_eq!(
        pi.to_bits(), EXPECTED_F32.to_bits(),
        "f32 field round-trip mismatch (exact bit pattern)"
    );
    let e = f64::from_le_bytes(read_fixed::<8>(event, "E"));
    assert_eq!(
        e.to_bits(), EXPECTED_F64.to_bits(),
        "f64 field round-trip mismatch (exact bit pattern)"
    );

    // bool8 — single byte, 0 = false, 1 = true.
    let flag_ref = event.format.get_field_ref("Flag")
        .expect("Flag field should exist");
    let flag = event.format.get_u8(flag_ref, &event.payload)
        .expect("Flag should decode as u8");
    assert_eq!(flag, EXPECTED_BOOL8, "bool8 field round-trip mismatch");

    // bool32 — Win32 `BOOL` (4 bytes, signed).  Decoded as `u32` and
    // reinterpreted as `i32` to compare against the original `-1`
    // (`0xFFFFFFFF`) value.  This implicitly verifies the 4-byte
    // on-wire size: if the decoder were to truncate to 1 byte (the
    // historical bug), the subsequent FILETIME field would shift by
    // 3 bytes and its assertion would fail.
    let wide_flag_ref = event.format.get_field_ref("WideFlag")
        .expect("WideFlag field should exist");
    let wide_flag = event.format.get_u32(wide_flag_ref, &event.payload)
        .expect("WideFlag should decode as u32");
    assert_eq!(
        wide_flag as i32, EXPECTED_BOOL32,
        "bool32 field round-trip mismatch"
    );

    // FILETIME — signed 64-bit integer, little-endian on the wire.
    let created = i64::from_le_bytes(read_fixed::<8>(event, "Created"));
    assert_eq!(
        created, EXPECTED_FILETIME,
        "FILETIME field round-trip mismatch"
    );

    // SYSTEMTIME — 8 packed little-endian u16 fields (16 bytes total).
    let when_bytes = read_fixed::<16>(event, "When");
    let when_units: [u16; 8] = std::array::from_fn(|i| {
        u16::from_le_bytes([when_bytes[2 * i], when_bytes[2 * i + 1]])
    });
    assert_eq!(
        when_units, EXPECTED_SYSTEMTIME,
        "SYSTEMTIME field round-trip mismatch"
    );

    // GUID — 16 bytes in Windows little-endian COM layout.
    assert_eq!(
        read_fixed::<16>(event, "Id"),
        EXPECTED_GUID.to_bytes_le(),
        "GUID field round-trip mismatch"
    );
}

/// Asserts every field value in an "EventNested" event matches the
/// constants written by the producer.
///
/// Verifies the decoder's struct-flattening behavior:
///
/// * The struct property itself is **not** emitted as a field.
/// * Inner field names are **qualified with the outer struct name**
///   using dot notation (e.g. `"Inner.InnerA"`).
/// * Top-level fields outside the struct keep their bare names.
/// * The four fields appear in declaration order in the flat field list.
fn assert_nested_event(event: &CapturedEvent) {
    assert_schema(
        event,
        &["Top", "Inner.InnerA", "Inner.InnerB", "Bottom"],
        &["u32", "u32", "u64", "u32"],
        "nested event",
    );

    // Resolve dotted-name field references and verify each scalar.
    let top_ref = event.format.get_field_ref("Top")
        .expect("Top field should exist");
    let inner_a_ref = event.format.get_field_ref("Inner.InnerA")
        .expect("Inner.InnerA field should exist (dot notation)");
    let inner_b_ref = event.format.get_field_ref("Inner.InnerB")
        .expect("Inner.InnerB field should exist (dot notation)");
    let bottom_ref = event.format.get_field_ref("Bottom")
        .expect("Bottom field should exist");

    let top = event.format.get_u32(top_ref, &event.payload)
        .expect("Top should decode as u32");
    let inner_a = event.format.get_u32(inner_a_ref, &event.payload)
        .expect("Inner.InnerA should decode as u32");
    let inner_b = event.format.get_u64(inner_b_ref, &event.payload)
        .expect("Inner.InnerB should decode as u64");
    let bottom = event.format.get_u32(bottom_ref, &event.payload)
        .expect("Bottom should decode as u32");

    assert_eq!(top, EXPECTED_NESTED_TOP, "Top round-trip mismatch");
    assert_eq!(
        inner_a, EXPECTED_NESTED_INNER_A,
        "Inner.InnerA round-trip mismatch"
    );
    assert_eq!(
        inner_b, EXPECTED_NESTED_INNER_B,
        "Inner.InnerB round-trip mismatch"
    );
    assert_eq!(
        bottom, EXPECTED_NESTED_BOTTOM,
        "Bottom round-trip mismatch"
    );
}

// ── Test A: tracelogging_dynamic (runtime-defined provider) ──────────

/// Verifies the TDH decoder produces correct field values for events
/// emitted by the runtime-schema `tracelogging_dynamic` crate.
#[ignore]
#[test]
fn tdh_decodes_tracelogging_dynamic_events() {
    let provider_name = "OneCollect.TdhIntegration.Dynamic";
    let provider_guid = tlg_guid_to_oc(tld::Provider::guid_from_name(provider_name));

    // `Provider` is `!Unpin` (it stores an async ETW callback) so it
    // must live at a stable address from `register` to `unregister`.
    // Leaking onto the heap pins it for the lifetime of the test
    // process — which is fine for a test: the OS unregisters on exit.
    let provider: &'static tld::Provider = Box::leak(Box::new(
        tld::Provider::new(provider_name, &tld::Provider::options()),
    ));
    unsafe {
        Pin::new_unchecked(provider).register();
    }

    let (captured, counter, callback) = make_capture_sink();

    let mut session = build_capturing_session(
        provider_guid,
        "OneCollect.TdhIntegration.Dynamic.Wide",
        callback,
    );

    // Spawn the event writer once the session is up and our provider
    // has been enabled.  `started_callback` is invoked on the parse
    // worker thread *after* `EnableTraceEx2` returns for our provider,
    // so a writer that polls `provider.enabled()` is guaranteed to
    // make progress.
    //
    // Events emitted by this test (all under keyword `TEST_KEYWORD`):
    //
    //   EventNumbers
    //       Count    : u32       = EXPECTED_U32       (0xDEADBEEF)
    //       BigCount : u64       = EXPECTED_U64       (0x01020304_05060708)
    //
    //   EventStrings
    //       Message  : str8      = EXPECTED_STR8      ("hello-from-tdh")
    //       Name     : cstr16    = EXPECTED_STR16     (UTF-16 "wide-world")
    //
    //   EventScalars
    //       Pi       : f32       = EXPECTED_F32       (π)
    //       E        : f64       = EXPECTED_F64       (e)
    //       Flag     : bool8     = EXPECTED_BOOL8     (true → 0x01)
    //       WideFlag : bool32    = EXPECTED_BOOL32    (i32 -1 → 0xFFFFFFFF)
    //       Created  : FILETIME  = EXPECTED_FILETIME  (i64, 100 ns since 1601)
    //       When     : SYSTEMTIME= EXPECTED_SYSTEMTIME([u16; 8] calendar form)
    //       Id       : GUID      = EXPECTED_GUID      (16-byte COM layout)
    session.add_started_callback(move |_ctx| {
        std::thread::spawn(move || {
            if !wait_until_enabled("dynamic provider", || {
                provider.enabled(tlg::Level::Verbose, TEST_KEYWORD)
            }) {
                return;
            }

            let mut builder = tld::EventBuilder::new();

            // EventNumbers: u32 + u64.
            builder
                .reset("EventNumbers", tlg::Level::Verbose, TEST_KEYWORD, 0)
                .add_u32("Count", EXPECTED_U32, tlg::OutType::Default, 0)
                .add_u64("BigCount", EXPECTED_U64, tlg::OutType::Default, 0)
                .write(provider, None, None);

            // EventStrings: counted ANSI + null-terminated UTF-16.
            builder
                .reset("EventStrings", tlg::Level::Verbose, TEST_KEYWORD, 0)
                .add_str8(
                    "Message",
                    EXPECTED_STR8.as_bytes(),
                    tlg::OutType::Default,
                    0,
                )
                .add_cstr16("Name", EXPECTED_STR16, tlg::OutType::Default, 0)
                .write(provider, None, None);

            // EventScalars: f32 + f64 + bool8 + bool32 + FILETIME + SYSTEMTIME + GUID.
            //
            // `add_u8(name, value, OutType::Boolean, 0)` is the dynamic
            // equivalent of the static `bool8(name, &val)` macro keyword:
            // both produce `InType::U8` with `OutType::Boolean`.
            //
            // `add_bool32` takes an `i32` and emits `InType::Bool32`
            // (`TDH_INTYPE_BOOLEAN`) — a 4-byte Win32 `BOOL`.
            builder
                .reset("EventScalars", tlg::Level::Verbose, TEST_KEYWORD, 0)
                .add_f32("Pi", EXPECTED_F32, tlg::OutType::Default, 0)
                .add_f64("E", EXPECTED_F64, tlg::OutType::Default, 0)
                .add_u8("Flag", EXPECTED_BOOL8, tlg::OutType::Boolean, 0)
                .add_bool32("WideFlag", EXPECTED_BOOL32, tlg::OutType::Default, 0)
                .add_filetime(
                    "Created",
                    EXPECTED_FILETIME,
                    tlg::OutType::Default,
                    0,
                )
                .add_systemtime(
                    "When",
                    &EXPECTED_SYSTEMTIME,
                    tlg::OutType::Default,
                    0,
                )
                .add_guid("Id", &EXPECTED_GUID, tlg::OutType::Default, 0)
                .write(provider, None, None);
        });
    });

    let captured = drive_to_completion(
        session,
        "one_collect_tdh_dynamic",
        &captured,
        counter,
        3,
    );

    assert_numbers_event(find_event(&captured, "EventNumbers"));
    assert_strings_event(find_event(&captured, "EventStrings"));
    assert_scalars_event(find_event(&captured, "EventScalars"));
}

// ── Test B: tracelogging (compile-time provider via macros) ──────────

tlg::define_provider!(STATIC_PROV, "OneCollect.TdhIntegration.Static");

/// Verifies the TDH decoder produces correct field values for events
/// emitted by the compile-time-schema `tracelogging` crate.
#[ignore]
#[test]
fn tdh_decodes_tracelogging_static_events() {
    // Provider GUID is `Guid::from_name(provider_name)` for both
    // crates when no explicit id() is supplied to define_provider!.
    let provider_guid = tlg_guid_to_oc(
        tlg::Guid::from_name("OneCollect.TdhIntegration.Static"),
    );

    // SAFETY: `STATIC_PROV` is a true `'static` item, so it lives at a
    // fixed address forever — the pinning requirement of
    // `Provider::register` is trivially satisfied.  The OS unregisters
    // automatically on process exit.
    unsafe {
        STATIC_PROV.register();
    }

    let (captured, counter, callback) = make_capture_sink();

    let mut session = build_capturing_session(
        provider_guid,
        "OneCollect.TdhIntegration.Static.Wide",
        callback,
    );

    // Events emitted by this test (mirror of the dynamic test, but
    // written through the compile-time-schema `tracelogging` crate):
    //
    //   EventNumbers
    //       Count    : u32       = EXPECTED_U32       (0xDEADBEEF)
    //       BigCount : u64       = EXPECTED_U64       (0x01020304_05060708)
    //
    //   EventStrings
    //       Message  : str8      = EXPECTED_STR8      ("hello-from-tdh")
    //       Name     : cstr16    = EXPECTED_STR16     (UTF-16 "wide-world")
    //
    //   EventScalars
    //       Pi       : f32       = EXPECTED_F32       (π)
    //       E        : f64       = EXPECTED_F64       (e)
    //       Flag     : bool8     = true               (TLG `bool8` keyword)
    //       WideFlag : bool32    = EXPECTED_BOOL32    (TLG `bool32` keyword, i32 -1)
    //       Created  : FILETIME  = EXPECTED_FILETIME  (i64, 100 ns since 1601)
    //       When     : SYSTEMTIME= EXPECTED_SYSTEMTIME([u16; 8] calendar form)
    //       Id       : GUID      = EXPECTED_GUID      (16-byte COM layout)
    session.add_started_callback(move |_ctx| {
        std::thread::spawn(move || {
            if !wait_until_enabled("static provider", || {
                STATIC_PROV.enabled(tlg::Level::Verbose, TEST_KEYWORD)
            }) {
                return;
            }

            // EventNumbers: u32 + u64.
            let _ = tlg::write_event!(
                STATIC_PROV,
                "EventNumbers",
                level(Verbose),
                keyword(TEST_KEYWORD),
                u32("Count", &EXPECTED_U32),
                u64("BigCount", &EXPECTED_U64),
            );

            // EventStrings: counted ANSI + null-terminated UTF-16.
            let _ = tlg::write_event!(
                STATIC_PROV,
                "EventStrings",
                level(Verbose),
                keyword(TEST_KEYWORD),
                str8("Message", EXPECTED_STR8),
                cstr16("Name", EXPECTED_STR16),
            );

            // EventScalars: f32 + f64 + bool8 + bool32 + FILETIME + SYSTEMTIME + GUID.
            //
            // The `bool8` macro keyword is the static crate's name for
            // `InType::U8` + `OutType::Boolean`; `bool32` emits the
            // 4-byte Win32 `BOOL` (`InType::Bool32` →
            // `TDH_INTYPE_BOOLEAN`); `win_filetime` is its name for
            // `InType::FileTime` from a raw `i64`; and `win_systemtime`
            // is the 16-byte `InType::SystemTime` from an `&[u16; 8]`
            // (the static `systemtime` keyword, despite its name,
            // actually emits an 8-byte FILETIME).
            let _ = tlg::write_event!(
                STATIC_PROV,
                "EventScalars",
                level(Verbose),
                keyword(TEST_KEYWORD),
                f32("Pi", &EXPECTED_F32),
                f64("E", &EXPECTED_F64),
                bool8("Flag", &true),
                bool32("WideFlag", &EXPECTED_BOOL32),
                win_filetime("Created", &EXPECTED_FILETIME),
                win_systemtime("When", &EXPECTED_SYSTEMTIME),
                guid("Id", &EXPECTED_GUID),
            );
        });
    });

    let captured = drive_to_completion(
        session,
        "one_collect_tdh_static",
        &captured,
        counter,
        3,
    );

    assert_numbers_event(find_event(&captured, "EventNumbers"));
    assert_strings_event(find_event(&captured, "EventStrings"));
    assert_scalars_event(find_event(&captured, "EventScalars"));
}

// ── Test C: nested struct (dynamic) ──────────────────────────────────

/// Verifies the TDH decoder flattens nested TraceLogging structs into
/// dot-notation field names when emitted from the runtime-schema
/// `tracelogging_dynamic` crate.
#[ignore]
#[test]
fn tdh_decodes_tracelogging_dynamic_nested_struct() {
    let provider_name = "OneCollect.TdhIntegration.Dynamic.Struct";
    let provider_guid = tlg_guid_to_oc(tld::Provider::guid_from_name(provider_name));

    let provider: &'static tld::Provider = Box::leak(Box::new(
        tld::Provider::new(provider_name, &tld::Provider::options()),
    ));
    unsafe {
        Pin::new_unchecked(provider).register();
    }

    let (captured, counter, callback) = make_capture_sink();

    let mut session = build_capturing_session(
        provider_guid,
        "OneCollect.TdhIntegration.Dynamic.Struct.Wide",
        callback,
    );

    // Events emitted by this test (a single event with a nested struct):
    //
    //   EventNested
    //       Top          : u32   = EXPECTED_NESTED_TOP      (100)   — outer
    //       Inner.InnerA : u32   = EXPECTED_NESTED_INNER_A  (200)   — nested
    //       Inner.InnerB : u64   = EXPECTED_NESTED_INNER_B  (300)   — nested
    //       Bottom       : u32   = EXPECTED_NESTED_BOTTOM   (400)   — outer
    //
    // The TDH decoder is expected to flatten the `Inner` struct into
    // dot-prefixed field names (`Inner.InnerA`, `Inner.InnerB`) and
    // omit the struct property itself from the field list.
    session.add_started_callback(move |_ctx| {
        std::thread::spawn(move || {
            if !wait_until_enabled("dynamic struct provider", || {
                provider.enabled(tlg::Level::Verbose, TEST_KEYWORD)
            }) {
                return;
            }

            // EventNested layout:
            //
            //     u32  Top
            //     struct Inner {
            //         u32  InnerA
            //         u64  InnerB
            //     }
            //     u32  Bottom
            //
            // `add_struct("Inner", 2, 0)` declares that the *next 2*
            // added fields are members of the `Inner` struct; the field
            // after that returns to the outer scope.
            let mut builder = tld::EventBuilder::new();
            builder
                .reset("EventNested", tlg::Level::Verbose, TEST_KEYWORD, 0)
                .add_u32("Top", EXPECTED_NESTED_TOP, tlg::OutType::Default, 0)
                .add_struct("Inner", 2, 0)
                .add_u32(
                    "InnerA",
                    EXPECTED_NESTED_INNER_A,
                    tlg::OutType::Default,
                    0,
                )
                .add_u64(
                    "InnerB",
                    EXPECTED_NESTED_INNER_B,
                    tlg::OutType::Default,
                    0,
                )
                .add_u32(
                    "Bottom",
                    EXPECTED_NESTED_BOTTOM,
                    tlg::OutType::Default,
                    0,
                )
                .write(provider, None, None);
        });
    });

    let captured = drive_to_completion(
        session,
        "one_collect_tdh_dynamic_struct",
        &captured,
        counter,
        1,
    );

    assert_nested_event(find_event(&captured, "EventNested"));
}

// ── Test D: nested struct (static) ───────────────────────────────────

tlg::define_provider!(
    STATIC_STRUCT_PROV,
    "OneCollect.TdhIntegration.Static.Struct"
);

/// Verifies the TDH decoder flattens nested TraceLogging structs into
/// dot-notation field names when emitted from the compile-time-schema
/// `tracelogging` crate.
#[ignore]
#[test]
fn tdh_decodes_tracelogging_static_nested_struct() {
    let provider_guid = tlg_guid_to_oc(
        tlg::Guid::from_name("OneCollect.TdhIntegration.Static.Struct"),
    );

    unsafe {
        STATIC_STRUCT_PROV.register();
    }

    let (captured, counter, callback) = make_capture_sink();

    let mut session = build_capturing_session(
        provider_guid,
        "OneCollect.TdhIntegration.Static.Struct.Wide",
        callback,
    );

    // Events emitted by this test (mirror of the dynamic struct test,
    // but written through the compile-time-schema `tracelogging` crate):
    //
    //   EventNested
    //       Top          : u32   = EXPECTED_NESTED_TOP      (100)   — outer
    //       Inner.InnerA : u32   = EXPECTED_NESTED_INNER_A  (200)   — nested
    //       Inner.InnerB : u64   = EXPECTED_NESTED_INNER_B  (300)   — nested
    //       Bottom       : u32   = EXPECTED_NESTED_BOTTOM   (400)   — outer
    session.add_started_callback(move |_ctx| {
        std::thread::spawn(move || {
            if !wait_until_enabled("static struct provider", || {
                STATIC_STRUCT_PROV.enabled(tlg::Level::Verbose, TEST_KEYWORD)
            }) {
                return;
            }

            // The `struct(name, { ... })` macro syntax automatically
            // counts the nested members — no explicit field count is
            // required, unlike the dynamic crate's `add_struct`.
            let _ = tlg::write_event!(
                STATIC_STRUCT_PROV,
                "EventNested",
                level(Verbose),
                keyword(TEST_KEYWORD),
                u32("Top", &EXPECTED_NESTED_TOP),
                struct("Inner", {
                    u32("InnerA", &EXPECTED_NESTED_INNER_A),
                    u64("InnerB", &EXPECTED_NESTED_INNER_B),
                }),
                u32("Bottom", &EXPECTED_NESTED_BOTTOM),
            );
        });
    });

    let captured = drive_to_completion(
        session,
        "one_collect_tdh_static_struct",
        &captured,
        counter,
        1,
    );

    assert_nested_event(find_event(&captured, "EventNested"));
}

// ── Test E: manifest decoding (live OS provider) ─────────────────────

/// Verifies the TDH decoder resolves and decodes *manifest-based* events
/// end-to-end against a live, OS-registered provider.
///
/// Unlike the TraceLogging tests, a manifest schema cannot be fabricated
/// in-process — it lives in an XML manifest registered with the OS.  This
/// test therefore uses `Microsoft-Windows-Kernel-Process`, which is
/// always registered, and triggers real `ProcessStart` / `ProcessStop`
/// events by spawning short-lived child processes.
///
/// The capture sink only records events that `TdhDecoder::decode`
/// returns `Ok` for, so every captured event is proof the manifest path
/// (classic-header reject → `TdhGetEventInformation` → `DecodingSource ==
/// DecodingSourceXMLFile` → schema build) succeeded.  The assertions
/// additionally prove:
///
/// * the manifest resolved to a real field layout (non-empty fields), and
/// * the `TaskNameOffset` event-name path works (a `ProcessStart` /
///   `ProcessStop` Task name is surfaced).
///
/// For reliability the test does not wait for an arbitrary total event
/// count: it watches the raw records for the process-lifetime events it
/// actually validates (`ProcessStart` Id 1 / `ProcessStop` Id 2) and stops
/// the moment one is observed.  Because that watch fires *before* decode,
/// a broken decode fails the assertions below with a clear message instead
/// of spinning until `TEST_TIMEOUT`.
#[ignore]
#[test]
fn tdh_decodes_manifest_kernel_process_events() {
    let provider_guid = Guid::from_u128(KERNEL_PROCESS_PROVIDER);

    let (captured, _counter, callback) = make_capture_sink();

    // Set once a ProcessStart/ProcessStop record is seen on the wire
    // (independent of decode success), and used as the parse stop
    // condition below.
    let saw_target = Arc::new(AtomicBool::new(false));
    let saw_target_for_cb = saw_target.clone();

    let mut session = build_capturing_session_observed(
        provider_guid,
        "OneCollect.TdhIntegration.Manifest.Wide",
        callback,
        move |id| {
            if KERNEL_PROCESS_EVENT_IDS.contains(&id) {
                saw_target_for_cb.store(true, Ordering::Relaxed);
            }
        },
    );

    // Trigger process-lifetime events once the session has enabled the
    // provider.  `started_callback` fires on the parse worker thread
    // after `EnableTraceEx2` returns for the Kernel-Process provider, so
    // any child process spawned afterwards is guaranteed to be observed.
    //
    // Kernel-Process emits (among others):
    //
    //   ProcessStart (Id 1, Task "ProcessStart") — manifest event with
    //       fields such as ProcessID, ImageName, ...
    //   ProcessStop  (Id 2, Task "ProcessStop")
    //
    // A shared stop flag lets the spawner exit the instant capture is
    // done, so we spawn only a handful of processes instead of hundreds.
    // The `TEST_TIMEOUT` deadline remains as a backstop.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    session.add_started_callback(move |_ctx| {
        let stop = stop_for_thread.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + TEST_TIMEOUT;
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                let _ = std::process::Command::new("cmd.exe")
                    .args(["/c", "exit"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                std::thread::sleep(Duration::from_millis(25));
            }
        });
    });

    // Drive until a ProcessStart/ProcessStop record has actually been
    // observed (or `TEST_TIMEOUT` elapses), rather than waiting for an
    // arbitrary number of unrelated Kernel-Process events that may not
    // include the ones this test validates.
    let captured = drive_until(
        session,
        "one_collect_tdh_manifest",
        &captured,
        move || saw_target.load(Ordering::Relaxed),
    );

    // Capture is complete; signal the spawner to stop immediately.
    stop.store(true, Ordering::Relaxed);

    // Every captured event already proves an `Ok` manifest decode; assert
    // at least one resolved to a real manifest field layout.
    assert!(
        captured.iter().any(|e| !e.field_names.is_empty()),
        "expected at least one manifest event with a resolved field layout; \
         saw names: {:?}",
        captured.iter().map(|e| &e.name).collect::<Vec<_>>()
    );

    // Assert the `TaskNameOffset` path surfaced a Task-derived name for a
    // known process-lifetime event.  This is the manifest-specific
    // event-name branch (`DecodingSource != DecodingSourceTlg`).
    assert!(
        captured
            .iter()
            .any(|e| KERNEL_PROCESS_TASKS.contains(&e.name.as_str())),
        "expected a Task-named ProcessStart/ProcessStop manifest event; \
         saw names: {:?}",
        captured.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

// ── Test F: manifest decoding of a compiled-at-test-time manifest ─────
//
// Unlike Test E (which drives a live OS provider), this test owns its
// provider end to end: it compiles the checked-in WES manifest
// (`test_assets/manifest/one_collect_test.man`) with the Windows SDK
// (`mc.exe` -> `rc.exe` -> `link.exe`), registers it with the OS
// (`wevtutil im`), emits one event per template through the live ETW
// runtime via `EventRegister`/`EventWrite`, and asserts that every inType
// the decoder supports round-trips through the manifest path.
//
// This is the comprehensive counterpart to Test E and is the only test
// that exercises the manifest counted-string inTypes
// (`win:CountedUnicodeString` / `win:CountedAnsiString` ->
// `TDH_INTYPE_MANIFEST_COUNTEDSTRING`/`ANSISTRING`).
//
// It requires elevation (for `wevtutil im` and the ETW consumer session)
// and the Windows SDK + MSVC tools on `PATH`.  When those tools are
// absent it prints a `SKIP` line and returns `Ok` rather than failing, so
// a non-elevated / SDK-less dev box still passes `cargo test`.  CI puts
// the tools on `PATH` (see `msvc-dev-cmd` in the ETW integration job) and
// runs elevated as `runneradmin`.
//
// Scope: x64 only.  The link step hard-codes `/MACHINE:X64` and the
// payload assumes an 8-byte `win:Pointer`, matching the x64 Windows CI
// runner; a 32-bit build would need a different machine flag and pointer
// width.

use std::path::{Path, PathBuf};
use std::process::Command;
use windows_sys::Win32::System::Diagnostics::Etw::{
    EventRegister, EventUnregister, EventWrite,
    EVENT_DATA_DESCRIPTOR, EVENT_DESCRIPTOR,
};

/// `u128` form of the test provider GUID, used to build the framework
/// `Guid` the capturing session subscribes to.
const TEST_MANIFEST_PROVIDER: u128 = 0x4948EF3B_4F28_4747_9BB9_649008E2EDEF;

/// `windows_sys` form of the same GUID, used by `EventRegister`.
const PROVIDER_GUID_SYS: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x4948EF3B,
    data2: 0x4F28,
    data3: 0x4747,
    data4: [0x9B, 0xB9, 0x64, 0x90, 0x08, 0xE2, 0xED, 0xEF],
};

// Expected field values (byte-distinct where practical, so any
// offset/endianness slip fails loudly).
const EXP_I8: i8 = -2;
const EXP_U8: u8 = 0xAB;
const EXP_I16: i16 = -12_345;
const EXP_U16: u16 = 0xABCD;
const EXP_I32: i32 = -1_234_567;
const EXP_U32: u32 = 0xDEAD_BEEF;
const EXP_I64: i64 = -1_234_567_890_123;
const EXP_U64: u64 = 0x0102_0304_0506_0708;
const EXP_H32: u32 = 0xCAFE_F00D;
const EXP_H64: u64 = 0x1122_3344_5566_7788;
const EXP_F32: f32 = std::f32::consts::PI;
const EXP_F64: f64 = std::f64::consts::E;
const EXP_BOOL: u32 = 1;
/// On-wire bytes of GUID `{11223344-5566-7788-99AA-BBCCDDEEFF00}`:
/// Data1/2/3 little-endian, Data4 as-is.
const EXP_GUID_BYTES: [u8; 16] = [
    0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
];
const EXP_FILETIME: u64 = 0x01D9_AABB_CCDD_EEFF;
/// SYSTEMTIME fields: year, month, dayOfWeek, day, hour, minute, second,
/// milliseconds (each a little-endian `u16`).
const EXP_SYSTIME: [u16; 8] = [2026, 8, 0, 9, 12, 34, 56, 789];
const EXP_PTR: u64 = 0x0000_7FF6_1234_5678;
const EXP_COUNTEDW: &str = "counted-wide";
const EXP_COUNTEDA: &str = "counted-ansi";
const EXP_ANSI: &str = "ansi-string";
const EXP_UNICODE: &str = "unicode-string";
const EXP_SENTINEL: u32 = 0x5A5A_5A5A;
const EXP_BLOB: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

const SCALARS_NAMES: [&str; 17] = [
    "I8", "U8", "I16", "U16", "I32", "U32", "I64", "U64",
    "H32", "H64", "F32", "F64", "Bool", "Guid", "FileTime",
    "SysTime", "Ptr",
];
const SCALARS_TYPES: [&str; 17] = [
    "s8", "u8", "s16", "u16", "s32", "u32", "s64", "u64",
    "s32", "s64", "float", "double", "u32", "guid", "filetime",
    "systemtime", "pointer",
];
const STRINGS_NAMES: [&str; 5] =
    ["CountedW", "CountedA", "Ansi", "Unicode", "Sentinel"];
const STRINGS_TYPES: [&str; 5] =
    ["counted_wstring", "counted_string", "string", "wstring", "u32"];
const BLOB_NAMES: [&str; 1] = ["Blob"];
const BLOB_TYPES: [&str; 1] = ["binary"];

/// Absolute path to the checked-in manifest asset.
fn manifest_asset_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_assets")
        .join("manifest")
        .join("one_collect_test.man")
}

/// Runs an external tool in `cwd`, mapping a missing executable to a
/// skip-reason and a non-zero exit to a descriptive error.
fn run_tool(name: &str, args: &[&str], cwd: &Path) -> Result<(), String> {
    let output = match Command::new(name).args(args).current_dir(cwd).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "`{name}` not found on PATH (Windows SDK / MSVC dev \
                 environment required)"
            ));
        }
        Err(e) => return Err(format!("failed to launch `{name}`: {e}")),
    };
    if !output.status.success() {
        return Err(format!(
            "`{name} {}` failed ({}):\nstdout: {}\nstderr: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    // Surface output on success too, so `--nocapture` runs show what each
    // build/registration step did.
    eprintln!(
        "`{name} {}` ok\nstdout: {}\nstderr: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

/// A registered manifest whose `Drop` unregisters it (`wevtutil um`) and
/// removes the temp build directory, so cleanup happens even on panic.
struct RegisteredManifest {
    man: PathBuf,
    workdir: PathBuf,
}

impl Drop for RegisteredManifest {
    fn drop(&mut self) {
        let man = self.man.to_string_lossy();
        if let Err(e) =
            run_tool("wevtutil.exe", &["um", &man], &self.workdir)
        {
            eprintln!("WARN: manifest unregister failed: {e}");
        }
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

/// Compiles the manifest asset into a resource-only DLL and registers it
/// with the OS.  Returns a guard that cleans up on drop, or a skip-reason
/// string when the SDK tools are unavailable.  The temp build directory is
/// removed on every early-return path, not just success.
fn compile_and_register_manifest() -> Result<RegisteredManifest, String> {
    let src = manifest_asset_path();
    if !src.exists() {
        return Err(format!("manifest asset missing: {}", src.display()));
    }

    let workdir = std::env::temp_dir()
        .join(format!("one_collect_manifest_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir)
        .map_err(|e| format!("create workdir {}: {e}", workdir.display()))?;

    // Every fallible step below runs through this closure so a failure can
    // remove `workdir` before propagating, rather than leaking it.
    let build = || -> Result<PathBuf, String> {
        let man = workdir.join("one_collect_test.man");
        std::fs::copy(&src, &man).map_err(|e| format!("copy manifest: {e}"))?;

        // 1. Message Compiler: manifest -> header + .rc + resource .bin files.
        run_tool("mc.exe", &["one_collect_test.man"], &workdir)?;
        // 2. Resource Compiler: .rc -> .res.
        run_tool(
            "rc.exe",
            &["/nologo", "/fo", "one_collect_test.res", "one_collect_test.rc"],
            &workdir,
        )?;
        // 3. Linker: .res -> resource-only DLL (no code, no entry point).
        run_tool(
            "link.exe",
            &[
                "/NOLOGO", "/DLL", "/NOENTRY", "/MACHINE:X64",
                "/OUT:one_collect_test.dll", "one_collect_test.res",
            ],
            &workdir,
        )?;
        // 4. Register (requires admin); point both resource + message files
        //    at the freshly built DLL by absolute path.
        let dll = workdir.join("one_collect_test.dll");
        let rf = format!("/rf:{}", dll.display());
        let mf = format!("/mf:{}", dll.display());
        run_tool(
            "wevtutil.exe",
            &["im", "one_collect_test.man", &rf, &mf],
            &workdir,
        )?;
        Ok(man)
    };

    match build() {
        Ok(man) => Ok(RegisteredManifest {
            man,
            workdir,
        }),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&workdir);
            Err(e)
        }
    }
}

/// Thin RAII wrapper over an ETW provider registration used to emit the
/// manifest events.
struct ManifestEmitter {
    handle: u64,
}

impl ManifestEmitter {
    fn register() -> Result<Self, u32> {
        let mut handle: u64 = 0;
        // SAFETY: `PROVIDER_GUID_SYS` outlives the call; no enable
        // callback or context is supplied.
        let status = unsafe {
            EventRegister(
                &PROVIDER_GUID_SYS as *const windows_sys::core::GUID,
                None,
                std::ptr::null(),
                &mut handle,
            )
        };
        if status == 0 {
            Ok(Self { handle })
        } else {
            Err(status)
        }
    }

    /// Writes one manifest event.  The entire payload is supplied as a
    /// single contiguous buffer (TDH sees the concatenated `UserData`
    /// regardless of how it is split across data descriptors).
    fn write(&self, id: u16, task: u16, payload: &[u8]) -> u32 {
        let desc = EVENT_DESCRIPTOR {
            Id: id,
            Version: 0,
            Channel: 0,
            Level: 5, // win:Verbose
            Opcode: 0,
            Task: task,
            Keyword: 0,
        };
        let data = EVENT_DATA_DESCRIPTOR {
            Ptr: payload.as_ptr() as u64,
            Size: payload.len() as u32,
            // SAFETY: the `Reserved`/anonymous union is zero-initialised,
            // as required by the ETW ABI for caller-supplied descriptors.
            Anonymous: unsafe { std::mem::zeroed() },
        };
        // SAFETY: `handle` is a live registration; `desc` and `data`
        // outlive the call; `payload` outlives `data`.  `REGHANDLE` is a
        // signed 64-bit handle, so the `u64` handle is cast to `i64`.
        unsafe {
            EventWrite(
                self.handle as i64,
                &desc as *const EVENT_DESCRIPTOR,
                1,
                &data as *const EVENT_DATA_DESCRIPTOR,
            )
        }
    }
}

impl Drop for ManifestEmitter {
    fn drop(&mut self) {
        // SAFETY: `handle` was returned by a successful `EventRegister`.
        unsafe {
            EventUnregister(self.handle as i64);
        }
    }
}

/// Builds a length-prefixed UTF-16LE counted string (u16 byte-count
/// prefix + content, no terminator).
fn counted_utf16(s: &str) -> Vec<u8> {
    let units: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (units.len() * 2) as u16;
    let mut v = byte_len.to_le_bytes().to_vec();
    for u in units {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

/// Builds a length-prefixed ANSI counted string (u16 byte-count prefix +
/// content, no terminator).
fn counted_ansi(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut v = (bytes.len() as u16).to_le_bytes().to_vec();
    v.extend_from_slice(bytes);
    v
}

/// Packs the `ScalarsT` template payload in declared field order.
fn scalars_payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.push(EXP_I8 as u8);
    p.push(EXP_U8);
    p.extend_from_slice(&EXP_I16.to_le_bytes());
    p.extend_from_slice(&EXP_U16.to_le_bytes());
    p.extend_from_slice(&EXP_I32.to_le_bytes());
    p.extend_from_slice(&EXP_U32.to_le_bytes());
    p.extend_from_slice(&EXP_I64.to_le_bytes());
    p.extend_from_slice(&EXP_U64.to_le_bytes());
    p.extend_from_slice(&EXP_H32.to_le_bytes());
    p.extend_from_slice(&EXP_H64.to_le_bytes());
    p.extend_from_slice(&EXP_F32.to_le_bytes());
    p.extend_from_slice(&EXP_F64.to_le_bytes());
    p.extend_from_slice(&EXP_BOOL.to_le_bytes());
    p.extend_from_slice(&EXP_GUID_BYTES);
    p.extend_from_slice(&EXP_FILETIME.to_le_bytes());
    for v in EXP_SYSTIME {
        p.extend_from_slice(&v.to_le_bytes());
    }
    p.extend_from_slice(&EXP_PTR.to_le_bytes());
    p
}

/// Packs the `StringsT` template payload in declared field order.
fn strings_payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&counted_utf16(EXP_COUNTEDW));
    p.extend_from_slice(&counted_ansi(EXP_COUNTEDA));
    p.extend_from_slice(EXP_ANSI.as_bytes());
    p.push(0); // ANSI NUL terminator
    for u in EXP_UNICODE.encode_utf16() {
        p.extend_from_slice(&u.to_le_bytes());
    }
    p.extend_from_slice(&0u16.to_le_bytes()); // UTF-16 NUL terminator
    p.extend_from_slice(&EXP_SENTINEL.to_le_bytes());
    p
}

/// Packs the `BlobT` template payload (a fixed 4-byte binary).
fn blob_payload() -> Vec<u8> {
    EXP_BLOB.to_vec()
}

/// Returns a captured event's decoded bytes for `name`, resolving the
/// full (possibly variable-length) field layout.
fn field_bytes(event: &CapturedEvent, name: &str) -> Vec<u8> {
    event
        .format
        .fields_with_data(&event.payload)
        .find(|(f, _)| f.name == name)
        .map(|(_, b)| b.to_vec())
        .unwrap_or_else(|| panic!("field {name:?} not found in decoded event"))
}

/// Reads exactly `N` bytes for `name`, asserting the on-wire size.
fn exact<const N: usize>(event: &CapturedEvent, name: &str) -> [u8; N] {
    let b = field_bytes(event, name);
    assert_eq!(b.len(), N, "{name} on-wire size");
    b.try_into().unwrap()
}

/// Locates the first captured event whose first field has the given name.
///
/// Matching on the schema (rather than the decoded event name) keeps the
/// lookup robust even if the manifest task name were ever surfaced
/// differently; the task name is asserted separately.
fn find_by_first_field<'a>(
    captured: &'a [CapturedEvent],
    first: &str,
) -> &'a CapturedEvent {
    captured
        .iter()
        .find(|e| e.field_names.first().map(|s| s.as_str()) == Some(first))
        .unwrap_or_else(|| {
            let seen: Vec<(&String, &Vec<String>)> =
                captured.iter().map(|e| (&e.name, &e.field_names)).collect();
            panic!(
                "no captured event whose first field is {first:?}; saw {seen:?}"
            )
        })
}

#[ignore]
#[test]
fn tdh_decodes_compiled_manifest_all_types() {
    let _guard = match compile_and_register_manifest() {
        Ok(g) => g,
        Err(skip) => {
            eprintln!(
                "SKIP tdh_decodes_compiled_manifest_all_types: {skip}"
            );
            return;
        }
    };

    let provider_guid = Guid::from_u128(TEST_MANIFEST_PROVIDER);
    let (captured, _counter, callback) = make_capture_sink();

    // Track which of the three event Ids we've observed on the wire.
    let seen = Arc::new([
        AtomicBool::new(false),
        AtomicBool::new(false),
        AtomicBool::new(false),
    ]);
    let seen_cb = seen.clone();

    let mut session = build_capturing_session_observed(
        provider_guid,
        "OneCollect.TdhIntegration.Manifest.All",
        callback,
        move |id| {
            if (1..=3).contains(&id) {
                seen_cb[(id - 1) as usize].store(true, Ordering::Relaxed);
            }
        },
    );

    // Emit the events once the provider is enabled.  `started_callback`
    // fires after `EnableTraceEx2` returns, so writes afterward are
    // delivered to this session.  Emit in a loop until capture is done to
    // absorb any startup race.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    session.add_started_callback(move |_ctx| {
        let stop = stop_thread.clone();
        std::thread::spawn(move || {
            let emitter = match ManifestEmitter::register() {
                Ok(e) => e,
                Err(code) => {
                    eprintln!("WARN: EventRegister failed with {code}");
                    return;
                }
            };
            let scalars = scalars_payload();
            let strings = strings_payload();
            let blob = blob_payload();
            // Report the first nonzero EventWrite status only, so a genuine
            // write failure is diagnosable without spamming the retry loop.
            let mut warned = false;
            let deadline = Instant::now() + TEST_TIMEOUT;
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                for (id, payload) in
                    [(1u16, &scalars), (2, &strings), (3, &blob)]
                {
                    let status = emitter.write(id, id, payload);
                    if status != 0 && !warned {
                        eprintln!(
                            "WARN: EventWrite for event {id} failed with {status}"
                        );
                        warned = true;
                    }
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
    });

    let seen_drive = seen.clone();
    let captured = drive_until(
        session,
        "one_collect_tdh_manifest_all",
        &captured,
        move || seen_drive.iter().all(|b| b.load(Ordering::Relaxed)),
    );
    stop.store(true, Ordering::Relaxed);

    // ── Scalars ─────────────────────────────────────────────────────
    let ev = find_by_first_field(&captured, "I8");
    assert_eq!(ev.name, "Scalars", "scalars task name");
    assert_schema(ev, &SCALARS_NAMES, &SCALARS_TYPES, "manifest scalars");
    assert_eq!(i8::from_le_bytes(exact::<1>(ev, "I8")), EXP_I8);
    assert_eq!(u8::from_le_bytes(exact::<1>(ev, "U8")), EXP_U8);
    assert_eq!(i16::from_le_bytes(exact::<2>(ev, "I16")), EXP_I16);
    assert_eq!(u16::from_le_bytes(exact::<2>(ev, "U16")), EXP_U16);
    assert_eq!(i32::from_le_bytes(exact::<4>(ev, "I32")), EXP_I32);
    assert_eq!(u32::from_le_bytes(exact::<4>(ev, "U32")), EXP_U32);
    assert_eq!(i64::from_le_bytes(exact::<8>(ev, "I64")), EXP_I64);
    assert_eq!(u64::from_le_bytes(exact::<8>(ev, "U64")), EXP_U64);
    assert_eq!(u32::from_le_bytes(exact::<4>(ev, "H32")), EXP_H32);
    assert_eq!(u64::from_le_bytes(exact::<8>(ev, "H64")), EXP_H64);
    assert_eq!(
        f32::from_le_bytes(exact::<4>(ev, "F32")).to_bits(),
        EXP_F32.to_bits()
    );
    assert_eq!(
        f64::from_le_bytes(exact::<8>(ev, "F64")).to_bits(),
        EXP_F64.to_bits()
    );
    assert_eq!(u32::from_le_bytes(exact::<4>(ev, "Bool")), EXP_BOOL);
    assert_eq!(field_bytes(ev, "Guid"), EXP_GUID_BYTES);
    assert_eq!(u64::from_le_bytes(exact::<8>(ev, "FileTime")), EXP_FILETIME);
    let systime: Vec<u8> =
        EXP_SYSTIME.iter().flat_map(|v| v.to_le_bytes()).collect();
    assert_eq!(field_bytes(ev, "SysTime"), systime);
    assert_eq!(u64::from_le_bytes(exact::<8>(ev, "Ptr")), EXP_PTR);

    // ── Strings ─────────────────────────────────────────────────────
    let ev = find_by_first_field(&captured, "CountedW");
    assert_eq!(ev.name, "Strings", "strings task name");
    assert_schema(ev, &STRINGS_NAMES, &STRINGS_TYPES, "manifest strings");
    let cw = field_bytes(ev, "CountedW");
    let cw_units: Vec<u16> =
        cw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    assert_eq!(String::from_utf16(&cw_units).unwrap(), EXP_COUNTEDW);
    assert_eq!(field_bytes(ev, "CountedA"), EXP_COUNTEDA.as_bytes());
    assert_eq!(field_bytes(ev, "Ansi"), EXP_ANSI.as_bytes());
    let uni = field_bytes(ev, "Unicode");
    let uni_units: Vec<u16> =
        uni.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    assert_eq!(String::from_utf16(&uni_units).unwrap(), EXP_UNICODE);
    // The sentinel proves the four preceding variable-length string fields
    // each consumed exactly their bytes and kept the following offset
    // aligned (the counted-string length-prefix regression guard).
    assert_eq!(u32::from_le_bytes(exact::<4>(ev, "Sentinel")), EXP_SENTINEL);

    // ── Blob ────────────────────────────────────────────────────────
    let ev = find_by_first_field(&captured, "Blob");
    assert_eq!(ev.name, "Blobs", "blobs task name");
    assert_schema(ev, &BLOB_NAMES, &BLOB_TYPES, "manifest blob");
    assert_eq!(field_bytes(ev, "Blob"), EXP_BLOB);
}

