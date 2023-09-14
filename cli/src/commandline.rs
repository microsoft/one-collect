use clap::{Arg, command, Command, value_parser};
use one_collect::{session::{SessionBuilder, SessionEgress, FileSessionEgress}, state::ProcessTrackingOptions};

pub (crate) struct CommandLineParser{
    cmd : Command,
}

impl CommandLineParser{
    pub fn build() -> Self {
        
        // Build out the parser.
        let cmd = command!()
            .subcommand_required(true)
            .subcommand(
                Command::new("collect")
                    .about("Collects a trace")
                    .arg(Arg::new("path")
                            .required(true)
                            .help("Path to store the collected trace")))
            .subcommand(
                Command::new("debug")
                    .about("Prints raw trace data to the console")
                    .arg(Arg::new("seconds")
                            .short('s')
                            .long("seconds")
                            .help("Specify the duration of the session in seconds")
                            .value_parser(value_parser!(u64))
                            .default_value("1")));
        
        CommandLineParser {
            cmd,
        }
    }

    pub fn parse(self) {
        let matches = self.cmd.get_matches();

        if let Some(subcommand) = matches.subcommand_matches("collect") {
            let path = subcommand.get_one::<String>("path").unwrap();
            let builder = SessionBuilder::new(SessionEgress::File(FileSessionEgress::new(path)));

            let session = builder.build().unwrap_or_else( |error| {
                println!("Error building perf_events session: {}", error);
                std::process::exit(1);
            });
            let egress_info = session.egress_info();
            if let SessionEgress::File(f) = egress_info {
                println!("Requested session egress - file: {}", f.path());
            }
            else {
                unreachable!("egress_info == SessionEgress::Live");
            }
        }

        if let Some(subcommand) = matches.subcommand_matches("debug") {
            let seconds = subcommand.get_one::<u64>("seconds").expect("required");
            let options = ProcessTrackingOptions::new()
                .with_process_names();

            let builder = SessionBuilder::new(SessionEgress::Live)
                .with_profiling(1000)
                .track_process_state(options);

            let mut session = builder.build().unwrap_or_else( |error| {
                println!("Error building perf_events session: {}", error);
                std::process::exit(1);
            });

            if let Some(perf_session) = session.perf_session_mut() {

                let ancillary = perf_session.ancillary_data().clone();
                let time_data = perf_session.time_data_ref().clone();

                let comm_event_format = perf_session.comm_event().format();
                let comm_pid_ref = comm_event_format.get_field_ref_unchecked("pid");
                let comm_tid_ref = comm_event_format.get_field_ref_unchecked("tid");
                let comm_comm_ref = comm_event_format.get_field_ref_unchecked("comm[]");

                perf_session.comm_event().add_callback( move |full_data,format,event_data| {

                    // timestamp
                    let time = time_data.try_get_u64(full_data).unwrap_or(0) as usize;

                    // cpu
                    let mut cpu = 0;
                    ancillary.read( |values| {
                        cpu = values.cpu();
                    });

                    // pid
                    let pid = format.try_get_u32(comm_pid_ref, event_data).unwrap_or(0);

                    // tid
                    let tid = format.try_get_u32(comm_tid_ref, event_data).unwrap_or(0);

                    // comm
                    let comm_value = format.try_get_str(comm_comm_ref, event_data).unwrap_or("");

                    println!("timestamp: {time}, event: comm, cpu: {cpu}, pid: {pid}, tid: {tid}, comm: {comm_value}");
                });

                let ancillary = perf_session.ancillary_data();
                let time_data = perf_session.time_data_ref();

                let exit_event_format = perf_session.exit_event().format();
                let exit_pid_ref = exit_event_format.get_field_ref_unchecked("pid");
                let exit_tid_ref = exit_event_format.get_field_ref_unchecked("tid");

                perf_session.exit_event().add_callback( move |full_data,format,event_data| {

                    // timestamp
                    let time = time_data.try_get_u64(full_data).unwrap_or(0) as usize;

                    // cpu
                    let mut cpu = 0;
                    ancillary.read( |values| {
                        cpu = values.cpu();
                    });

                    // pid
                    let pid = format.try_get_u32(exit_pid_ref, event_data).unwrap_or(0);

                    // tid
                    let tid = format.try_get_u32(exit_tid_ref, event_data).unwrap_or(0);

                    println!("timestamp: {time}, event: exit, cpu: {cpu}, pid: {pid}, tid: {tid}");
                });

                let session_state = perf_session.session_state();
                let time_data = perf_session.time_data_ref();
                let ancillary = perf_session.ancillary_data();
                let pid_field = perf_session.pid_field_ref();
                let tid_field = perf_session.tid_data_ref();

                perf_session.cpu_profile_event().add_callback( move |full_data,_format,_event_data| {

                    // timestamp
                    let time = time_data.try_get_u64(full_data).unwrap_or(0) as usize;

                    // cpu
                    let mut cpu = 0;
                    ancillary.read( |values| {
                        cpu = values.cpu();
                    });

                    // pid
                    let pid = pid_field.try_get_u32(full_data).unwrap_or(0);

                    // tid
                    let tid = tid_field.try_get_u32(full_data).unwrap_or(0);

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
                });

                session.enable().unwrap_or_else( |error| {
                    println!("Error enabling perf_events session: {}", error);
                    std::process::exit(1);
                });

                session.parse_for_duration(
                    std::time::Duration::from_secs(*seconds)).unwrap();
                session.disable().unwrap();
            }
            else {
                unreachable!("perf_session == None");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::commandline::CommandLineParser;

    // Most testing can be done via a call to debug_assert() per
    // https://docs.rs/clap/latest/clap/_tutorial/index.html#testing
    #[test]
    fn verify_cmd() {
        CommandLineParser::build().cmd.debug_assert();
    }
}