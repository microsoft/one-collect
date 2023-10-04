use one_collect::{session::{SessionBuilder, Session, SessionEgress}, state::ProcessTrackingOptions, perf_event::PerfSession};

pub(crate) struct DebugConsoleSession<'a> {
    session: Session<'a>,
}

impl<'a> DebugConsoleSession<'a> {
    pub(crate) fn new() -> Self {
        
        // Setup the PerfSession.
        let options = ProcessTrackingOptions::new()
                .with_process_names();

        let builder = SessionBuilder::new(SessionEgress::Live)
            .with_profiling(1000)
            .track_process_state(options);

        let session = builder.build().unwrap_or_else( |error| {
            println!("Error building perf_events session: {}", error);
            std::process::exit(1);
        });

        let mut console_session = Self {
            session,
        };

        // Hook events.
        console_session.hook_comm_event();
        console_session.hook_exit_event();
        console_session.hook_cpu_profile_event();
        console_session.hook_lost_event();
        console_session.hook_lost_samples_event();

        console_session
    }

    pub(crate) fn run(&mut self) {
        self.session.enable().unwrap_or_else( |error| {
            println!("Error enabling perf_events session: {}", error);
            std::process::exit(1);
        });
        
        self.session.parse_all().unwrap_or_else(|error| {
            println!("Error processing perf_events: {}", error);
            std::process::exit(1); 
        });
    }

    fn hook_comm_event(&mut self) {
        let perf_session = self.perf_session_mut();

        let ancillary = perf_session.ancillary_data().clone();
        let time_data = perf_session.time_data_ref().clone();

        let comm_event = perf_session.comm_event();
        let comm_event_format = comm_event.format();
        let comm_pid_ref = comm_event_format.get_field_ref_unchecked("pid");
        let comm_tid_ref = comm_event_format.get_field_ref_unchecked("tid");
        let comm_comm_ref = comm_event_format.get_field_ref_unchecked("comm[]");

        comm_event.add_callback( move |full_data,format,event_data| {

            // timestamp
            let time = time_data.get_u64(full_data)? as usize;

            // cpu
            let mut cpu = 0;
            ancillary.read( |values| {
                cpu = values.cpu();
            });

            // pid
            let pid = format.get_u32(comm_pid_ref, event_data)?;

            // tid
            let tid = format.get_u32(comm_tid_ref, event_data)?;

            // comm
            let comm_value = format.get_str(comm_comm_ref, event_data)?;

            println!("timestamp: {time}, event: comm, cpu: {cpu}, pid: {pid}, tid: {tid}, comm: {comm_value}");

            Ok(())
        });
    }

    fn hook_exit_event(&mut self) {
        let perf_session = self.perf_session_mut();

        let ancillary = perf_session.ancillary_data();
        let time_data = perf_session.time_data_ref();

        let exit_event = perf_session.exit_event();
        let exit_event_format = exit_event.format();
        let exit_pid_ref = exit_event_format.get_field_ref_unchecked("pid");
        let exit_tid_ref = exit_event_format.get_field_ref_unchecked("tid");

        exit_event.add_callback( move |full_data,format,event_data| {

            // timestamp
            let time = time_data.get_u64(full_data)? as usize;

            // cpu
            let mut cpu = 0;
            ancillary.read( |values| {
                cpu = values.cpu();
            });

            // pid
            let pid = format.get_u32(exit_pid_ref, event_data)?;

            // tid
            let tid = format.get_u32(exit_tid_ref, event_data)?;

            println!("timestamp: {time}, event: exit, cpu: {cpu}, pid: {pid}, tid: {tid}");

            Ok(())
        });
    }

    fn hook_cpu_profile_event(&mut self) {
        let perf_session = self.perf_session_mut();

        let session_state = perf_session.session_state();
        let time_data = perf_session.time_data_ref();
        let ancillary = perf_session.ancillary_data();
        let pid_field = perf_session.pid_field_ref();
        let tid_field = perf_session.tid_data_ref();

        perf_session.cpu_profile_event().add_callback( move |full_data,_format,_event_data| {

            // timestamp
            let time = time_data.get_u64(full_data)? as usize;

            // cpu
            let mut cpu = 0;
            ancillary.read( |values| {
                cpu = values.cpu();
            });

            // pid
            let pid = pid_field.get_u32(full_data)?;

            // tid
            let tid = tid_field.get_u32(full_data)?;

            // session state
            // NOTE: This is what will be required in order to consume tracked state.
            // I expect that if the user doesn't ask for session state (not yet possible),
            // then session_state will still exist, but all calls to SessionState::process will return None.
            session_state.read(|state| {
                if let Some(proc) = state.process(pid) {
                    let name = proc.name();
                    println!("timestamp: {time}, event: cpu_profile, cpu: {cpu}, pid: {pid}, comm: {name}, tid: {tid}");
                }
                else {
                    println!("timestamp: {time}, event: cpu_profile, cpu: {cpu}, pid: {pid}, tid: {tid}");
                }
            });

            Ok(())
        });
    }

    fn hook_lost_event(&mut self) {
        let perf_session = self.perf_session_mut();

        let time_data = perf_session.time_data_ref();
        let ancillary = perf_session.ancillary_data();
        let lost_event = perf_session.lost_event();
        let lost_event_format = lost_event.format();
        let id_field = lost_event_format.get_field_ref_unchecked("id");
        let lost_field = lost_event_format.get_field_ref_unchecked("lost");

        lost_event.add_callback(move |full_data,format,event_data| {

            // timestamp
            let time = time_data.get_u64(full_data)? as usize;

            // cpu
            let mut cpu = 0;
            ancillary.read( |values| {
                cpu = values.cpu();
            });

            // id
            let id = format.get_u64(id_field, event_data)?;

            // lost
            let lost = format.get_u64(lost_field, event_data)?;

            println!("timestamp: {time}, event: lost, cpu: {cpu}, id: {id}, lost: {lost}");

            Ok(())
        });
    }

    fn hook_lost_samples_event(&mut self) {
        let perf_session = self.perf_session_mut();

        let time_data = perf_session.time_data_ref();
        let ancillary = perf_session.ancillary_data();
        let lost_samples_event = perf_session.lost_samples_event();
        let lost_samples_event_format = lost_samples_event.format();
        let lost_field = lost_samples_event_format.get_field_ref_unchecked("lost");

        lost_samples_event.add_callback(move |full_data,format,event_data| {

            // timestamp
            let time = time_data.get_u64(full_data)? as usize;

            // cpu
            let mut cpu = 0;
            ancillary.read( |values| {
                cpu = values.cpu();
            });

            // lost
            let lost = format.get_u64(lost_field, event_data)?;

            println!("timestamp: {time}, event: lost, cpu: {cpu}, lost: {lost}");

            Ok(())
        });
    }

    fn perf_session_mut(&mut self) -> &mut PerfSession {
        self.session.perf_session_mut().as_mut().unwrap()
    }
}
