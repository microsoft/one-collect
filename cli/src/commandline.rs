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
                            .required(false)
                            .help("Path to store the collected trace"))
            );
        
        CommandLineParser {
            cmd,
        }
    }

    pub fn parse(self) {
        let matches = self.cmd.get_matches();

        if let Some(_subcommand) = matches.subcommand_matches("collect") {
            let builder;
            if let Some(path) = _subcommand.get_one::<String>("path") {
                builder = SessionBuilder::new(SessionEgress::File(FileSessionEgress::new(path)));
            }
            else {
                builder = SessionBuilder::new(SessionEgress::Live);
            }

            let session = builder.build();
            match session.get_egress_info() {
                SessionEgress::File(f) => {
                    println!("Requested session egress - file: {}", f.get_path());
                }
                SessionEgress::Live => {
                    println!("Requested session egress - live");
                }
            }
        }
    }
}