use one_collect::perf_event::{
    self,
    RingBufBuilder,
    RingBufSessionBuilder
};

use one_collect::state::ProcessTrackingOptions;
use one_collect::Writable;

use std::io::{Write, BufWriter};
use std::fs::File;

fn main() {
    let file = File::create("output.json").expect("Output.json could not be opened");
    let mut output = BufWriter::new(file);

    let duration = std::time::Duration::from_secs(10);
    let need_permission = "Need permission (run via sudo?)";

    /* We need to know comm/task names and when they switch */
    let kernel = RingBufBuilder::for_kernel()
        .with_comm_records()
        .with_task_records()
        .with_cswitch_records();

    /* Auto-track names */
    let tracking = ProcessTrackingOptions::new()
        .with_process_names();

    /* Build a session with those events */
    let mut session = RingBufSessionBuilder::new()
        .with_page_count(4)
        .with_kernel_events(kernel)
        .track_process_state(tracking)
        .build()
        .expect(need_permission);

    /* Hook cswitch events */
    let misc = session.misc_data_ref();
    let time = session.time_data_ref();
    let state = session.session_state();
    let cswitch = session.cswitch_event();
    let format = cswitch.format();
    let next_prev_pid = format.get_field_ref_unchecked("next_prev_pid");
    let next_prev_tid = format.get_field_ref_unchecked("next_prev_tid");

    write!(&mut output, "{{ \"traceEvents\": [\n").expect("Write failed!");

    let output = Writable::new(output);
    let final_output = output.clone();
    let mut i = 0u64;

    cswitch.add_callback(move |full_data,format,event_data| {
        let pid = format.get_u32(next_prev_pid, event_data)?;

        if pid == 0 {
            return Ok(());
        }

        let time = time.get_u64(full_data)? as f64 / 1000.0;
        let tid = format.get_u32(next_prev_tid, event_data)?;
        let misc = misc.get_u16(full_data)?;
        let switch_out = misc & perf_event::abi::PERF_RECORD_MISC_SWITCH_OUT ==
            perf_event::abi::PERF_RECORD_MISC_SWITCH_OUT;

        state.read(|state| {
            let comm = match state.process(pid) {
                Some(state) => { state.name() },
                None => { "" },
            };

            output.write(|output| {
                if i > 0 {
                    write!(output, ",\n").expect("Write failed!");
                }

                if switch_out {
                    write!(
                        output,
                        "{{\"name\": \"{}\", \"cat\": \"PERF\", \"ph\": \"B\", \"pid\": {}, \"tid\": {}, \"ts\": {} }}",
                        comm, pid, tid, time).expect("Write failed!");
                } else {
                    write!(
                        output,
                        "{{\"name\": \"{}\", \"cat\": \"PERF\", \"ph\": \"E\", \"pid\": {}, \"tid\": {}, \"ts\": {} }}",
                        comm, pid, tid, time).expect("Write failed!");
                }

                i += 1;
            });
        });

        Ok(())
    });

    /* Need to capture existing process names, etc */
    session.capture_environment();

    /* Run */
    println!("Capturing to output.json...");

    session.set_read_timeout(std::time::Duration::from_millis(8));
    session.enable().expect(need_permission);
    session.parse_for_duration(duration).expect(need_permission);
    session.disable().expect(need_permission);

    /* Close up log */
    final_output.write(|output| {
        write!(output, "\n]}}\n").expect("Write failed!");
    });

    println!("Done");
}
