use one_collect::event::Event;
use one_collect::perf_event::*;

fn main() {
    let args: Vec<_> = std::env::args().collect();

    if args.len() == 1 {
        println!("Usage: {} <path to bpf map (/sys/fs/bpf/...)>", args[0]);
        return;
    }

    let map_path = &args[1];

    let duration = std::time::Duration::from_secs(30);
    let need_permission = "Need permission (run via sudo?)";

    let bpf = RingBufBuilder::for_bpf();

    let mut builder = RingBufSessionBuilder::new()
        .with_page_count(256)
        .with_bpf_events(bpf);

    let mut session = builder.build().unwrap();

    let mut event = Event::new(0, "eBPF".into());
    let ancillary = session.ancillary_data();
    let pid_field = session.pid_field_ref();
    let time_field = session.time_data_ref();

    event.add_callback(move |full_data, _format, event_data| {
        println!("CPU={}, PID={}, Time={}, Data={} Bytes:",
            ancillary.borrow().cpu(),
            pid_field.get_u32(full_data)?,
            time_field.get_u64(full_data)?,
            event_data.len());

        /* Pretty print out hex/ascii */
        for chunk in event_data.chunks(16) {
            /* Hex */
            for b in chunk {
                print!("{:02X} ", b);
            }

            if chunk.len() < 16 {
                let padding = 16 - chunk.len();

                for _ in 0..padding {
                    print!("   ");
                }
            }

            /* ASCII */
            for b in chunk {
                let b = *b;
                if b > 31 && b < 127 {
                    print!("{}", b as char);
                } else {
                    print!(".");
                }
            }

            println!();
        }

        println!();

        Ok(())
    });

    session.attach_to_bpf_map_path(
        map_path,
        event).expect("Attach should work");

    session.lost_event().add_callback(|_,_,_| {
        println!("WARN: Lost event data");

        Ok(())
    });

    session.lost_samples_event().add_callback(|_,_,_| {
        println!("WARN: Lost samples data");

        Ok(())
    });

    println!("Collecting...");
    session.enable().expect(need_permission);
    session.parse_for_duration(duration).unwrap();
    session.disable().expect(need_permission);
}
