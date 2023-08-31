use clap::{Arg, command, Command};
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
                            .help("Path to store the collected trace"))
            );
        
        CommandLineParser {
            cmd,
        }
    }

    pub fn parse(self) {
        let matches = self.cmd.get_matches();

        if let Some(subcommand) = matches.subcommand_matches("collect") {
            let path = subcommand.get_one::<String>("path").unwrap();
            let builder = SessionBuilder::new(SessionEgress::File(FileSessionEgress::new(path)));

            let session = builder.build();
            let egress_info = session.egress_info();
            if let SessionEgress::File(f) = egress_info {
                println!("Requested session egress - file: {}", f.path());
            }
            else {
                unreachable!("egress_info == SessionEgress::Live");
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