use clap::Parser;
use std::env;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    out: Option<String>,

    #[arg(long)]
    on_cpu: bool,
}

#[derive(Debug)]
pub (crate) struct RecordArgs {
    output_path: PathBuf,
    on_cpu: bool,
}

impl RecordArgs {
    pub fn parse() -> Self {
        let command_args = Args::parse();
        
        // If --out isn't specified, default to the current working directory.
        let output_path = match command_args.out {
            Some(path) => {
                let path = PathBuf::from(path);
                if path.exists() && !path.is_dir() {
                    eprintln!("{} is not a directory.", path.display());
                    process::exit(1);
                }
                else if !path.exists() {
                    eprintln!("{} does not exist.", path.display());
                    process::exit(1);
                }

                path
            },
            None => {
                match env::current_dir() {
                    Ok(current_dir) => current_dir,
                    Err(e) => panic!("{}", format!("Unable to get current working directory: {}", e))
                }
            }
        };

        let args =Self {
            output_path: output_path,
            on_cpu: command_args.on_cpu,
        };

        // Cross-argument validation.
        if !args.on_cpu {
            eprintln!("No events selected. Exiting.");
            process::exit(1);
        }

        args
    }

    pub (crate) fn output_path(&self) -> &PathBuf {
        &self.output_path
    }

    pub (crate) fn on_cpu(&self) -> bool {
        self.on_cpu
    }
}