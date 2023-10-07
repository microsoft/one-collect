use clap::{Arg, command, Command, value_parser};
use one_collect::session::{SessionBuilder, SessionEgress, FileSessionEgress};

use crate::debug::DebugConsoleSession;

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
                        .default_value("0")));
        
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
            let mut session = DebugConsoleSession::new();

            if *seconds > 0 {
                session.run_for_duration(std::time::Duration::from_secs(*seconds));
            }
            else {
                session.run();
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