// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Live mixed-session regression test. Requires system-tracing permissions
//! and SeSystemProfilePrivilege; run from an elevated shell in CI.

#![cfg(target_os = "windows")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use one_collect::Guid;
use one_collect::etw::{EtwSession, LEVEL_VERBOSE, PROPERTY_STACK_TRACE};
use one_collect::etw::tdh::TdhDecoder;
use one_collect::event::Event;
use one_collect::event::os::windows::WindowsEventExtension;

use tracelogging as tlg;
use windows_sys::Win32::Foundation::ERROR_TIMEOUT;

tlg::define_provider!(MIXED_PROV, "OneCollect.SessionIntegration.Mixed");
tlg::define_provider!(CAPTURE_PROV, "OneCollect.SessionIntegration.CaptureStop");

#[test]
#[ignore = "requires ETW session permissions"]
fn stop_after_consuming_provider_events_drains_the_last_records() {
    const RECORDS: u32 = 4096;
    const TAIL: u32 = 128;
    let guid = Guid::from_u128(tlg::Guid::from_name("OneCollect.SessionIntegration.CaptureStop").to_u128());
    unsafe { assert_eq!(CAPTURE_PROV.register(), 0); }
    for notified in [false, true] {
        let mut session = EtwSession::new();
        let (started, ready) = std::sync::mpsc::channel();
        session.add_started_callback(move |_| { started.send(()).unwrap(); });
        let (delivered, ack) = std::sync::mpsc::channel();
        let total = Arc::new(AtomicU32::new(0));
        let seen = total.clone();
        let mut event = Event::for_etw(0, "CaptureStop::Sample".into(), guid, LEVEL_VERBOSE, 1);
        event.set_id_wild_card_flag();
        event.add_callback(move |_| {
            if seen.fetch_add(1, Ordering::Relaxed) + 1 == RECORDS / 2 {
                delivered.send(())?;
            }
            Ok(())
        });
        session.add_event(event, None);
        let (stop, token) = one_collect::StopHandle::pair().unwrap();
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let check = flag.clone();
        let name = format!("one_collect_capture_stop_{}_{}", std::process::id(), notified);
        std::thread::scope(|scope| {
            let sender = scope.spawn(move || {
                let write = |i: u32| tlg::write_event!(CAPTURE_PROV, "Sample",
                    level(Verbose), keyword(1), u32("sequence", &i));
                // Always signal stop, including if an expected callback never arrives.
                let emitted = (|| -> anyhow::Result<()> {
                    ready.recv_timeout(Duration::from_secs(10))
                        .map_err(|e| anyhow::anyhow!("session did not start: {e}"))?;
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !CAPTURE_PROV.enabled(tlg::Level::Verbose, 1) {
                        anyhow::ensure!(Instant::now() < deadline, "provider was not enabled");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    for i in 0..RECORDS {
                        anyhow::ensure!(write(i) == 0, "event write failed");
                        if i % 64 == 63 { std::thread::sleep(Duration::from_millis(5)); }
                    }
                    ack.recv_timeout(Duration::from_secs(10))
                        .map_err(|e| anyhow::anyhow!("no acknowledgement of delivered events: {e}"))?;
                    for i in RECORDS..RECORDS + TAIL {
                        anyhow::ensure!(write(i) == 0, "tail write failed");
                    }
                    Ok(())
                })();
                if notified { stop.request_stop(); } else { flag.store(true, Ordering::Release); }
                emitted
            });
            let result = if notified {
                session.parse_until_stop_requested(&name, token)
            } else {
                session.parse_until(&name, move || check.load(Ordering::Acquire))
            };
            sender.join().unwrap().unwrap_or_else(|e| panic!("{e} (notified={notified}, received={})",
                total.load(Ordering::Relaxed)));
            result.unwrap();
            assert_eq!(total.load(Ordering::Relaxed), RECORDS + TAIL);
        });
    }
    assert_eq!(CAPTURE_PROV.unregister(), 0);
}

#[test]
fn pre_stopped_token_skips_etw_and_hooks() {
    let (handle, token) = one_collect::StopHandle::pair().unwrap();
    handle.request_stop();
    let mut session = EtwSession::new();
    session.add_built_callback(|_| panic!("must not configure a skipped capture"));
    session.add_completed_callback(|_| panic!("a skipped capture has no statistics"));
    let error = session.parse_until_stop_requested("unused", token).unwrap_err();
    assert!(error.is::<one_collect::ParseCancelledBeforeStart>());
}

#[test]
#[ignore = "requires ETW session permissions"]
fn stop_during_startup_cleans_up_and_allows_same_name_restart() {
    let name = format!("one_collect_stop_test_{}", std::process::id());
    let completions = Arc::new(AtomicUsize::new(0));
    let stopping = Arc::new(AtomicUsize::new(0));
    let (first, token) = one_collect::StopHandle::pair().unwrap();
    let mut session = EtwSession::new();
    let during_setup = first.clone();
    session.add_built_callback(move |_| {
        during_setup.request_stop();
        Ok(())
    });
    let count = completions.clone();
    session.add_completed_callback(move |_| { count.fetch_add(1, Ordering::Relaxed); });
    let count = stopping.clone();
    session.add_stopping_callback(move |_| { count.fetch_add(1, Ordering::Relaxed); });
    let result = session.parse_until_stop_requested(&name, token);
    if let Err(err) = &result {
        assert!(err.to_string().starts_with("ProcessTrace failed with "), "{err}");
    }
    assert_eq!(stopping.load(Ordering::Relaxed), 1);
    assert_eq!(completions.load(Ordering::Relaxed), usize::from(result.is_ok()));

    // Starting by name would stop a pre-existing session. Check absence first
    // so the restart itself cannot mask a leaked logger.
    use windows_sys::Win32::Foundation::ERROR_WMI_INSTANCE_NOT_FOUND;
    use windows_sys::Win32::System::Diagnostics::Etw::{
        CONTROLTRACE_HANDLE, EVENT_TRACE_PROPERTIES, QueryTraceW,
    };
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    #[repr(C)]
    struct Query { properties: EVENT_TRACE_PROPERTIES, logger_name: [u16; 1024] }
    let mut query: Query = unsafe { std::mem::zeroed() };
    query.properties.Wnode.BufferSize = std::mem::size_of::<Query>() as u32;
    query.properties.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    let status = unsafe {
        QueryTraceW(CONTROLTRACE_HANDLE { Value: 0 }, wide.as_ptr(), &mut query.properties)
    };
    assert_eq!(status, ERROR_WMI_INSTANCE_NOT_FOUND);

    let (second, token) = one_collect::StopHandle::pair().unwrap();
    let (started, rx) = std::sync::mpsc::channel();
    let mut session = EtwSession::new();
    session.add_started_callback(move |_| { started.send(()).unwrap(); });
    let sender = std::thread::spawn(move || {
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        first.request_stop();
        // Exercise a running, empty replacement, not a second startup cancellation.
        std::thread::sleep(Duration::from_millis(100));
        second.request_stop();
    });
    session.parse_until_stop_requested(&name, token).unwrap();
    sender.join().unwrap();
}

#[test]
#[ignore = "requires ETW session permissions"]
fn externally_stopped_consumer_waits_for_controller_rundown() {
    use windows_sys::Win32::System::Diagnostics::Etw::{
        ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
    };
    let name = format!("one_collect_external_stop_{}", std::process::id());
    let (handle, token) = one_collect::StopHandle::pair().unwrap();
    let (tx, status) = std::sync::mpsc::channel();
    let mut session = EtwSession::new();
    session.add_started_callback(move |ctx| {
        // End ProcessTrace without requesting stop. The consumer must wake the controller.
        #[repr(C)]
        struct Properties { trace: EVENT_TRACE_PROPERTIES, name: [u16; 1024] }
        let mut props: Properties = unsafe { std::mem::zeroed() };
        props.trace.Wnode.BufferSize = std::mem::size_of::<Properties>() as u32;
        let result = unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: ctx.handle() },
            std::ptr::null(), &mut props.trace, EVENT_TRACE_CONTROL_STOP) };
        tx.send(result).unwrap();
        if result != 0 { handle.request_stop(); } // Do not strand the consumer on test failure.
    });
    let (rundown, finished) = std::sync::mpsc::channel();
    session.add_rundown_callback(move |ctx| {
        std::thread::sleep(Duration::from_millis(50));
        rundown.send(ctx.handle()).unwrap();
    });
    session.add_stopped_callback(move |_| {
        let handle = finished.try_recv().expect("stopped callback ran before rundown finished");
        assert_eq!(handle, 0, "rundown was given an externally stopped handle");
    });
    // The controller's own stop is too late to obtain final statistics.
    assert!(session.parse_until_stop_requested(&name, token).is_err());
    assert_eq!(status.try_recv().unwrap(), 0);
}

#[test]
#[ignore = "requires ETW session permissions"]
fn legacy_idle_capture_still_stops_by_predicate() {
    let name = format!("one_collect_predicate_test_{}", std::process::id());
    let start = Instant::now();
    EtwSession::new().parse_until(&name, move || start.elapsed() >= Duration::from_millis(100))
        .unwrap();
}

#[ignore]
#[test]
fn system_session_captures_kernel_stacks_and_user_events() {
    // SAFETY: The provider is static and remains registered until process exit.
    unsafe {
        assert_eq!(MIXED_PROV.register(), 0, "ETW provider registration failed");
    }

    let user_count = Arc::new(AtomicUsize::new(0));
    let kernel_count = Arc::new(AtomicUsize::new(0));
    let stack_count = Arc::new(AtomicUsize::new(0));
    let write_status = Arc::new(AtomicU32::new(u32::MAX));
    let mut session = EtwSession::new();

    let mut event = Event::for_etw(
        0, "Mixed::User".into(),
        Guid::from_u128(tlg::Guid::from_name("OneCollect.SessionIntegration.Mixed").to_u128()),
        LEVEL_VERBOSE, 1);
    event.set_id_wild_card_flag();
    let count = user_count.clone();
    let ancillary = session.ancillary_data();
    let mut decoder = TdhDecoder::new();
    event.add_callback(move |_| {
        let ancillary = ancillary.borrow();
        let record = ancillary.record()
            .ok_or_else(|| anyhow::anyhow!("missing raw user event record"))?;
        let decoded = decoder.decode(record)?;
        let data = &decoded.event_data;
        let value = data.format().get_field_ref("Value")
            .ok_or_else(|| anyhow::anyhow!("missing Value in user event"))?;
        anyhow::ensure!(data.format().get_u32(value, data.event_data())? == 42,
            "unexpected user event payload");
        count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    session.add_event(event, None);

    // Select system mode late, exercising on-demand configuration callbacks.
    let count = kernel_count.clone();
    let stacks = stack_count.clone();
    session.add_built_callback(move |session| {
        let count = count.clone();
        session.cswitch_event(Some(PROPERTY_STACK_TRACE)).add_callback(move |_| {
            count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        let stacks = stacks.clone();
        let event = session.callstack_event();
        let process = event.format().get_field_ref("StackProcess")
            .ok_or_else(|| anyhow::anyhow!("missing StackProcess field"))?;
        event.add_callback(move |data| {
            if data.format().get_u32(process, data.event_data())? == std::process::id() {
                anyhow::ensure!(data.event_data().len() >= 24,
                    "kernel stack event has no complete stack frame");
                stacks.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        });
        Ok(())
    });
    let status_slot = write_status.clone();
    session.add_started_callback(move |_| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !MIXED_PROV.enabled(tlg::Level::Verbose, 1) {
            if Instant::now() >= deadline {
                status_slot.store(ERROR_TIMEOUT, Ordering::Relaxed);
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let status = tlg::write_event!(
            MIXED_PROV, "UserEvent", level(Verbose), keyword(1), u32("Value", &42u32));
        status_slot.store(status, Ordering::Relaxed);
    });

    let until_user = user_count.clone();
    let until_kernel = kernel_count.clone();
    let until_stack = stack_count.clone();
    let deadline = Instant::now() + Duration::from_secs(30);
    let result = session.parse_until("one_collect_mixed_session_integration", move || {
        (until_user.load(Ordering::Relaxed) > 0
            && until_kernel.load(Ordering::Relaxed) > 0
            && until_stack.load(Ordering::Relaxed) > 0)
            || Instant::now() >= deadline
    });
    assert_eq!(MIXED_PROV.unregister(), 0, "ETW provider unregistration failed");
    result.expect("mixed ETW session failed; system-tracing permissions are required");

    assert_eq!(write_status.load(Ordering::Relaxed), 0,
        "provider enablement timed out or ETW event write failed");
    assert!(user_count.load(Ordering::Relaxed) > 0, "no user event captured");
    assert!(kernel_count.load(Ordering::Relaxed) > 0, "no context-switch event captured");
    assert!(stack_count.load(Ordering::Relaxed) > 0,
        "no non-empty classic kernel stack captured for the test process");
}
