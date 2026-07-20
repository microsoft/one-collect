// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! End-to-end integration tests for ETW session loss metrics
//! (`EtwSession` / `one_collect::etw::query_stats`).
//!
//! These tests start a real ETW kernel consumer session, register a real
//! TraceLogging provider (via the `tracelogging` crate), and assert on the
//! live loss/health counters returned by [`one_collect::etw::query_stats`].
//!
//! Both tests are marked `#[ignore]` because the consumer side of ETW
//! requires administrative privileges (`SeSystemProfilePrivilege` /
//! `SeDebugPrivilege`).  Run manually from an elevated shell with:
//!
//! ```text
//! cargo test -p one_collect --test etw_stats_integration -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` is required: each test starts its own ETW kernel
//! consumer session.  Running them concurrently would race on those
//! system-global resources.
//!
//! ## Why these tests assert what they assert
//!
//! The exact loss *counts* are not deterministic — they depend on kernel
//! scheduling, the (undocumented) real-time delivery queue size, and how
//! events pack into per-CPU buffers.  So we never assert an exact non-zero
//! count.  Instead:
//!
//! * The **healthy** test asserts the deterministic zero case: a draining
//!   consumer with default buffers drops nothing, so `events_lost == 0`
//!   and `real_time_buffers_lost == 0`.
//! * The **loss** test makes loss *inevitable* (not racy) by fully
//!   **blocking** the `ProcessTrace` consumer on its first event while a
//!   writer thread floods events into tiny buffers.  A bounded queue fed by
//!   an unbounded producer with zero drain must overflow.  It then asserts
//!   only invariants that hold regardless of hardware: loss is observed
//!   (`> 0`), the counter is **non-decreasing** across polls, and a large
//!   additional batch of writes drives `events_lost` **strictly higher**
//!   ("more logs written => more dropped").

#![cfg(target_os = "windows")]

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use one_collect::Guid;
use one_collect::etw::{query_stats, EtwSession, SessionStats, LEVEL_VERBOSE};
use one_collect::event::Event;
use one_collect::event::os::windows::WindowsEventExtension;

use tracelogging as tlg;

/// Keyword used by every event the tests emit (and the value the wide
/// event subscribes to via `MatchAnyKeyword`).
const TEST_KEYWORD: u64 = 0x1;

/// Hard upper bound on a single test run.  Loss is guaranteed to occur
/// under a blocked consumer; this only bounds how long we wait for it so a
/// broken environment fails instead of hanging forever.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Converts a `tracelogging::Guid` into the framework's `one_collect::Guid`
/// via the well-defined `u128` round trip (both crates agree on bit order).
fn tlg_guid_to_oc(g: tlg::Guid) -> Guid {
    Guid::from_u128(g.to_u128())
}

/// Polls `is_enabled` every 10 ms until it returns `true` or
/// `TEST_TIMEOUT` elapses.  Returns `false` on timeout.
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

// ── Test A: healthy session reports zero loss ────────────────────────

tlg::define_provider!(HEALTHY_PROV, "OneCollect.StatsIntegration.Healthy");

/// A draining consumer with default buffers must not drop anything, so
/// `query_stats` should report zero loss.  Also verifies the query works
/// from a freshly spawned thread (the handle is a `Send` `u64`).
#[ignore]
#[test]
fn query_stats_reports_zero_loss_for_healthy_session() {
    const EVENTS: usize = 50;

    let provider_guid =
        tlg_guid_to_oc(tlg::Guid::from_name("OneCollect.StatsIntegration.Healthy"));

    // SAFETY: `HEALTHY_PROV` is a true `'static` item, so it lives at a
    // fixed address forever.  The OS unregisters it on process exit.
    unsafe {
        HEALTHY_PROV.register();
    }

    let counter = Arc::new(AtomicUsize::new(0));
    let stats_slot: Arc<Mutex<Option<SessionStats>>> = Arc::new(Mutex::new(None));
    let offthread_ok = Arc::new(AtomicBool::new(false));

    let mut session = EtwSession::new();

    // Wide event whose callback just counts captured events on the
    // `ProcessTrace` thread.
    let mut event = Event::for_etw(
        0,
        "healthy_wide".to_string(),
        provider_guid,
        LEVEL_VERBOSE,
        u64::MAX,
    );
    event.set_id_wild_card_flag();
    {
        let counter = counter.clone();
        event.add_callback(move |_data| {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
    }
    session.add_event(event, None);

    // Once the provider is enabled, gently emit a small number of events
    // (1 ms apart) so the consumer trivially keeps up and nothing drops.
    session.add_started_callback(move |_ctx| {
        std::thread::spawn(|| {
            if !wait_until_enabled("healthy provider", || {
                HEALTHY_PROV.enabled(tlg::Level::Verbose, TEST_KEYWORD)
            }) {
                return;
            }
            for i in 0..EVENTS as u32 {
                let _ = tlg::write_event!(
                    HEALTHY_PROV,
                    "Healthy",
                    level(Verbose),
                    keyword(TEST_KEYWORD),
                    u32("n", &i),
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        });
    });

    // When the session is stopping (all events captured), query the live
    // counters from a *freshly spawned thread* to prove off-thread access,
    // and stash the result for assertions on the main test thread.
    {
        let stats_slot = stats_slot.clone();
        let offthread_ok = offthread_ok.clone();
        session.add_stopping_callback(move |ctx| {
            let handle = ctx.handle();
            let stats_slot = stats_slot.clone();
            let offthread_ok = offthread_ok.clone();
            let worker = std::thread::spawn(move || {
                if let Ok(stats) = query_stats(handle) {
                    *stats_slot.lock().unwrap() = Some(stats);
                    offthread_ok.store(true, Ordering::SeqCst);
                }
            });
            let _ = worker.join();
        });
    }

    let deadline = Instant::now() + TEST_TIMEOUT;
    let until_counter = counter.clone();
    session
        .parse_until("one_collect_stats_healthy", move || {
            until_counter.load(Ordering::Relaxed) >= EVENTS
                || Instant::now() >= deadline
        })
        .expect("parse_until failed (is the test running elevated?)");

    assert!(
        offthread_ok.load(Ordering::SeqCst),
        "query_stats should succeed from a spawned thread"
    );
    assert!(
        counter.load(Ordering::Relaxed) >= 1,
        "expected to capture at least one event"
    );

    let stats = stats_slot
        .lock()
        .unwrap()
        .expect("stopping callback should have captured stats");

    eprintln!(
        "healthy test: events_lost={}, real_time_buffers_lost={}, \
         buffers_written={}",
        stats.events_lost, stats.real_time_buffers_lost, stats.buffers_written
    );

    assert_eq!(
        stats.events_lost, 0,
        "a draining consumer must not drop events"
    );
    assert_eq!(
        stats.real_time_buffers_lost, 0,
        "a draining consumer must not drop buffers"
    );
}

// ── Test B: blocked consumer makes loss inevitable ───────────────────

tlg::define_provider!(LOSS_PROV, "OneCollect.StatsIntegration.Loss");

/// Blocks the `ProcessTrace` consumer on its first event while a writer
/// thread floods events into tiny buffers, making loss inevitable, then
/// asserts the reliable invariants:
///
/// * loss is observed (`events_lost > 0`),
/// * `events_lost` is non-decreasing across polls, and
/// * a large additional batch of writes drives `events_lost` strictly
///   higher (the "more logs => more dropped" property).
///
/// The blocked consumer is released in the stopping callback so
/// `ProcessTrace` can unwind and the session shuts down cleanly.
#[ignore]
#[test]
fn query_stats_observes_loss_under_blocked_consumer() {
    /// Additional `events_lost` required after the baseline to prove a
    /// strict increase.  Large enough that the kernel's counter must move
    /// once the queue is past overflow and every write is lost.
    const DELTA: u64 = 1_000;

    let provider_guid =
        tlg_guid_to_oc(tlg::Guid::from_name("OneCollect.StatsIntegration.Loss"));

    // SAFETY: see the healthy test above.
    unsafe {
        LOSS_PROV.register();
    }

    // Shared control state.
    let handle_slot = Arc::new(AtomicU64::new(0));
    let already_parked = Arc::new(AtomicBool::new(false));
    let release_consumer = Arc::new(AtomicBool::new(false));
    let stop_writer = Arc::new(AtomicBool::new(false));

    // Observed results (written by the poller on the control thread, read
    // by assertions on the main test thread).
    let loss_observed = Arc::new(AtomicBool::new(false));
    let monotonic_ok = Arc::new(AtomicBool::new(true));
    let strict_increase = Arc::new(AtomicBool::new(false));
    let baseline_lost = Arc::new(AtomicU64::new(0));

    // Tiny per-CPU buffers so the bounded delivery queue overflows almost
    // immediately once the consumer stops draining.
    let mut session = EtwSession::new().with_per_cpu_buffer_bytes(1024);

    // Wide event: park the consumer on the *first* event so `ProcessTrace`
    // stops draining entirely.  Subsequent invocations (after release) just
    // return so the session can unwind.
    let mut event = Event::for_etw(
        0,
        "loss_wide".to_string(),
        provider_guid,
        LEVEL_VERBOSE,
        u64::MAX,
    );
    event.set_id_wild_card_flag();
    {
        let already_parked = already_parked.clone();
        let release_consumer = release_consumer.clone();
        event.add_callback(move |_data| {
            if !already_parked.swap(true, Ordering::SeqCst) {
                // Block the ProcessTrace consumer until the stopping
                // callback releases it.  With no drain, the writer flood
                // overflows the buffer pool and delivery queue.
                while !release_consumer.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Ok(())
        });
    }
    session.add_event(event, None);

    // Started: capture the handle (demonstrating the `AtomicU64` capture
    // pattern) and spawn the flood writer.
    {
        let handle_slot = handle_slot.clone();
        let stop_writer = stop_writer.clone();
        session.add_started_callback(move |ctx| {
            handle_slot.store(ctx.handle(), Ordering::SeqCst);
            let stop_writer = stop_writer.clone();
            std::thread::spawn(move || {
                if !wait_until_enabled("loss provider", || {
                    LOSS_PROV.enabled(tlg::Level::Verbose, TEST_KEYWORD)
                }) {
                    return;
                }
                let mut i: u32 = 0;
                while !stop_writer.load(Ordering::Relaxed) {
                    let _ = tlg::write_event!(
                        LOSS_PROV,
                        "Flood",
                        level(Verbose),
                        keyword(TEST_KEYWORD),
                        u32("n", &i),
                    );
                    i = i.wrapping_add(1);
                }
            });
        });
    }

    // Stopping: release the parked consumer so `ProcessTrace` can return.
    {
        let release_consumer = release_consumer.clone();
        session.add_stopping_callback(move |_ctx| {
            release_consumer.store(true, Ordering::SeqCst);
        });
    }

    // The `until` predicate doubles as the off-thread poller: it runs on
    // the control thread (separate from the blocked consumer) and queries
    // the live counters by handle.
    let deadline = Instant::now() + TEST_TIMEOUT;
    let until = {
        let handle_slot = handle_slot.clone();
        let loss_observed = loss_observed.clone();
        let monotonic_ok = monotonic_ok.clone();
        let strict_increase = strict_increase.clone();
        let baseline_lost = baseline_lost.clone();
        let last_seen = AtomicU64::new(0);
        move || {
            if Instant::now() >= deadline {
                return true;
            }

            let handle = handle_slot.load(Ordering::SeqCst);
            if handle == 0 {
                return false; // session handle not captured yet
            }

            let lost = match query_stats(handle) {
                Ok(stats) => stats.events_lost as u64,
                Err(_) => return false,
            };

            // Non-decreasing invariant across polls.
            let prev = last_seen.swap(lost, Ordering::SeqCst);
            if lost < prev {
                monotonic_ok.store(false, Ordering::SeqCst);
            }

            // Phase A: wait for the first observed loss, record it.
            if !loss_observed.load(Ordering::SeqCst) {
                if lost > 0 {
                    baseline_lost.store(lost, Ordering::SeqCst);
                    loss_observed.store(true, Ordering::SeqCst);
                }
                return false;
            }

            // Phase B: wait for a large additional batch of losses, proving
            // a strict increase, then stop.
            let baseline = baseline_lost.load(Ordering::SeqCst);
            if lost >= baseline + DELTA {
                strict_increase.store(true, Ordering::SeqCst);
                return true;
            }

            false
        }
    };

    session
        .parse_until("one_collect_stats_loss", until)
        .expect("parse_until failed (is the test running elevated?)");

    // Tell the (detached) flood writer to stop; it exits on its next loop.
    stop_writer.store(true, Ordering::SeqCst);

    assert!(
        already_parked.load(Ordering::SeqCst),
        "the consumer should have parked on the first event"
    );
    assert!(
        loss_observed.load(Ordering::SeqCst),
        "a blocked consumer under flood must produce events_lost > 0"
    );
    assert!(
        monotonic_ok.load(Ordering::SeqCst),
        "events_lost must be non-decreasing across polls"
    );
    assert!(
        strict_increase.load(Ordering::SeqCst),
        "writing more events must drive events_lost strictly higher"
    );

    eprintln!(
        "loss test: baseline_events_lost={}",
        baseline_lost.load(Ordering::SeqCst)
    );
}
