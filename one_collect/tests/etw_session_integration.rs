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

tlg::define_provider!(MIXED_PROV, "OneCollect.SessionIntegration.Mixed");

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

    assert_eq!(write_status.load(Ordering::Relaxed), 0, "ETW event write failed");
    assert!(user_count.load(Ordering::Relaxed) > 0, "no user event captured");
    assert!(kernel_count.load(Ordering::Relaxed) > 0, "no context-switch event captured");
    assert!(stack_count.load(Ordering::Relaxed) > 0,
        "no non-empty classic kernel stack captured for the test process");
}
