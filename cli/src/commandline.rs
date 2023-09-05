use clap::{Arg, command, Command, value_parser};
use one_collect::session::{SessionBuilder, SessionEgress, FileSessionEgress};

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
            let builder = SessionBuilder::new(SessionEgress::Live)
                .with_profiling(1000);

            let mut session = builder.build().unwrap_or_else( |error| {
                println!("Error building perf_events session: {}", error);
                std::process::exit(1);
            });

            if let Some(perf_session) = session.perf_session_mut() {

                let ancillary = perf_session.ancillary_data().clone();
                let time_data = perf_session.time_data_ref().clone();

                perf_session.comm_event().add_callback( move |full_data,format,_event_data| {

                    // timestamp
                    let time = time_data.try_get_u64(full_data).unwrap_or(0) as usize;

                    // cpu
                    let mut cpu = 0;
                    ancillary.read( |values| {
                        cpu = values.cpu();
                    });

                    // pid
                    let pid_ref = format.get_field_ref_unchecked("pid");
                    let pid_data = format.get_data(pid_ref, _event_data);
                    let pid = u32::from_ne_bytes(<[u8; 4]>::try_from(pid_data)
                                    .unwrap_or([0, 0, 0, 0]));

                    // tid
                    let tid_ref = format.get_field_ref_unchecked("tid");
                    let tid_data = format.get_data(tid_ref, _event_data);
                    let tid = u32::from_ne_bytes(<[u8; 4]>::try_from(tid_data)
                                    .unwrap_or([0, 0, 0, 0]));

                    // comm
                    let comm_ref = format.get_field_ref_unchecked("comm[]");
                    let comm_data = format.get_data(comm_ref, _event_data);
                    let mut vec : Vec<u8> = Vec::new();
                    vec.extend_from_slice(comm_data);
                    let comm_value = String::from_utf8(vec).unwrap_or_else(|_error |{
                        String::from("<Unknown>")
                    });

                    println!("timestamp: {time}, event: comm, cpu: {cpu}, pid: {pid}, tid: {tid}, comm: {comm_value}");
                });

                let time_data = perf_session.time_data_ref();
                let ancillary = perf_session.ancillary_data();

                perf_session.cpu_profile_event().add_callback( move |full_data,_format,_event_data| {

                    // timestamp
                    let time = time_data.try_get_u64(full_data).unwrap_or(0) as usize;

                    // cpu
                    let mut cpu = 0;
                    ancillary.read( |values| {
                        cpu = values.cpu();
                    });

                    println!("timestamp: {time}, event: cpu_profile, cpu: {cpu}");
                });

                perf_session.enable().unwrap_or_else( |error| {
                    println!("Error enabling perf_events session: {}", error);
                    std::process::exit(1);
                });

                perf_session.parse_for_duration(
                    std::time::Duration::from_secs(*seconds)).unwrap();
                perf_session.disable().unwrap();
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