use clap::Parser;
use std::env;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, help = "Output directory")]
    out: Option<String>,

    #[arg(long, help = "Enable capture of CPU samples")]
    on_cpu: bool,

    #[arg(long = "pid", help = "Capture data for the specified process ID.  Multiple pids can be specified, one per usage of --pid")]
    target_pids: Option<Vec<i32>>,
}

#[derive(Debug)]
pub (crate) struct RecordArgs {
    output_path: PathBuf,
    on_cpu: bool,
    target_pids: Option<Vec<i32>>,
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

        let args = Self {
            output_path: output_path,
            on_cpu: command_args.on_cpu,
            target_pids: command_args.target_pids,
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

    pub (crate) fn target_pids(&self) -> &Option<Vec<i32>> {
        &self.target_pids
    }
}