use one_collect::perf_event::{
    RingBufBuilder,
    RingBufSessionBuilder
};

use one_collect::helpers::uprobe::*;
use one_collect::event::Event;
use one_collect::tracefs::*;
use one_collect::Writable;

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<_> = std::env::args().collect();

    if args.len() != 2 {
        println!("Usage: {} <PID>", args[0]);
        return Ok(());
    }

    let pid: u32 = args[1].parse()?;
    let duration = std::time::Duration::from_secs(1);
    let need_permission = "Need permission (run via sudo?)";

    /* Options for tracepoint (uprobe) data */
    let tracepoints = RingBufBuilder::for_tracepoint();

    /* Build a session with those events */
    let mut session = RingBufSessionBuilder::new()
        .with_page_count(32)
        .with_tracepoint_events(tracepoints)
        .with_target_pid(pid as i32)
        .build()
        .expect(need_permission);

    let tracefs = TraceFS::open().expect(need_permission);
    let mut alloc_event: Option<Event> = None;

    /* Ensure we cleanup from last time */
    let _ = tracefs.unregister_uprobe("uprobe_alloc", "libc_malloc");

    /* Find modules within the process */
    enum_uprobe_modules(pid, |module| {
        if alloc_event.is_some() { return; }

        /* Look for a libc */
        if let Some(_) = module.find("libc.so") {
            /* Look for malloc */
            let _ = enum_uprobes(module, |uprobe| {
                if uprobe.name() == "malloc" {
                    /* Register probe for malloc */
                    if let Ok(event) = tracefs.register_uprobe(
                        "uprobe_alloc",
                        "libc_malloc",
                        module,
                        uprobe.address() as usize,
                        "size=%di:u64") {
                        alloc_event = Some(event);
                    }
                }
            });
        }
    });

    /* We couldn't find anything in that process */
    if alloc_event.is_none() {
        println!("Oops, couldn't find any libc malloc in that process!");
        return Ok(());
    }

    let mut alloc_event = alloc_event.unwrap();
    let total = Writable::<u64>::new(0);
    let swap = total.clone();
    let size_ref = alloc_event.format().get_field_ref_unchecked("size");

    alloc_event.add_callback(move |_full_data,format,event_data| {
        let size = format.get_u64(size_ref, event_data)?;
        total.write(|value| { *value += size; });
        Ok(())
    });

    session.add_event(alloc_event).expect("Add should work");
    session.enable().expect(need_permission);
    for i in 0..{
        session.parse_for_duration(duration).expect(need_permission);

        swap.write(|value| {
            println!("+{}: {} bytes", i, value);
            *value = 0;
        });
    }
    session.disable().expect(need_permission);

    let _ = tracefs.unregister_uprobe("uprobe_alloc", "libc_malloc");

    println!("Done");

    Ok(())
}
