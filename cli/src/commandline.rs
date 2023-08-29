use clap::{Arg, command, Command};
use one_collect::configuration::{OneCollectSession, SessionStorage, FileSessionArgs};

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
            let config;
            if let Some(path) = _subcommand.get_one::<String>("path") {
                config = OneCollectSession::new(SessionStorage::File(FileSessionArgs::new(path)));
            }
            else {
                config = OneCollectSession::new(SessionStorage::InMemory);
            }

            match config.get_storage() {
                SessionStorage::File(args) => {
                    println!("[FileSession] path = {}", args.get_path());
                }
                SessionStorage::InMemory => {
                    println!("[InMemorySession] no path");
                }
            }
        };
    }
}