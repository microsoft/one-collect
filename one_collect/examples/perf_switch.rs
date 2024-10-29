use one_collect::Writable;

use std::io::{Write, BufWriter};
use std::fs::File;

#[cfg(target_os = "linux")]
fn main() {
    use std::collections::HashMap;

    use one_collect::perf_event::{
        self,
        RingBufBuilder,
        RingBufSessionBuilder
    };

    let file = File::create("output.json").expect("Output.json could not be opened");
    let mut output = BufWriter::new(file);

    let duration = std::time::Duration::from_secs(10);
    let need_permission = "Need permission (run via sudo?)";

    /* We need to know comm/task names and when they switch */
    let kernel = RingBufBuilder::for_kernel()
        .with_comm_records()
        .with_task_records()
        .with_cswitch_records();

    /* Build a session with those events */
    let mut session = RingBufSessionBuilder::new()
        .with_page_count(4)
        .with_kernel_events(kernel)
        .build()
        .expect(need_permission);

    let state: HashMap<u32, String> = HashMap::new();
    let state = Writable::new(state);

    /* Hook comm event */
    let comm_event = session.comm_event();
    let comm_event_format = comm_event.format();
    let pid_field = comm_event_format.get_field_ref_unchecked("pid");
    let tid_field = comm_event_format.get_field_ref_unchecked("tid");
    let comm_field = comm_event_format.get_field_ref_unchecked("comm[]");
    let event_state = state.clone();

    comm_event.add_callback(move |data| {
        let format = data.format();
        let event_data = data.event_data();

        let pid = format.get_u32(pid_field, event_data)?;
        let tid = format.get_u32(tid_field, event_data)?;

        if (pid == tid) && (pid != 0) {
            let proc_name = format.get_str(comm_field, event_data)?;

            event_state.borrow_mut().insert(pid, proc_name.to_owned());
        }

        Ok(())
    });

    /* Hook fork event */
    let fork_event = session.fork_event();
    let fork_event_format = fork_event.format();
    let pid_field = fork_event_format.get_field_ref_unchecked("pid");
    let ppid_field = fork_event_format.get_field_ref_unchecked("ppid");
    let event_state = state.clone();

    fork_event.add_callback(move |data| {
        let format = data.format();
        let event_data = data.event_data();

        let pid = format.get_u32(pid_field, event_data)?;
        let ppid = format.get_u32(ppid_field, event_data)?;

        let mut event_state = event_state.borrow_mut();
        let mut parent_name = None;

        if let Some(proc_name) = event_state.get(&ppid) {
            parent_name = Some(proc_name.to_owned());
        }

        if let Some(parent_name) = parent_name {
            event_state.insert(pid, parent_name);
        }

        Ok(())
    });

    /* Hook exit event */
    let exit_event = session.exit_event();
    let exit_event_format = exit_event.format();
    let pid_field = exit_event_format.get_field_ref_unchecked("pid");
    let event_state = state.clone();

    exit_event.add_callback(move |data| {
        let format = data.format();
        let event_data = data.event_data();

        let pid = format.get_u32(pid_field, event_data)?;

        event_state.borrow_mut().remove(&pid);

        Ok(())
    });

    /* Hook cswitch events */
    let misc = session.misc_data_ref();
    let time = session.time_data_ref();
    let cswitch = session.cswitch_event();
    let format = cswitch.format();
    let next_prev_pid = format.get_field_ref_unchecked("next_prev_pid");
    let next_prev_tid = format.get_field_ref_unchecked("next_prev_tid");

    write!(&mut output, "{{ \"traceEvents\": [\n").expect("Write failed!");

    let output = Writable::new(output);
    let final_output = output.clone();
    let mut i = 0u64;

    cswitch.add_callback(move |data| {
        let full_data = data.full_data();
        let format = data.format();
        let event_data = data.event_data();

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
            let comm = match state.get(&pid) {
                Some(proc_name) => { proc_name },
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

#[cfg(target_os = "windows")]
fn main() {
    println!("Coming soon");
}
