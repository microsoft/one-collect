use clap::{Parser, ValueEnum};
use std::env;
use std::fmt;
use std::path::PathBuf;
use std::process;

use crate::export::{Exporter, NetTraceExporter, PerfViewExporter};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, help = "Output directory")]
    out: Option<String>,

    #[arg(long, default_value_t = Format::Nettrace, help = "Output format")]
    format: Format,

    #[arg(long, help = "Capture CPU samples")]
    on_cpu: bool,

    #[arg(long, help = "Capture context switches")]
    off_cpu: bool,

    #[arg(long, help = "Display samples live")]
    live: bool,

    #[arg(long = "pid", help = "Capture data for the specified process ID.  Multiple pids can be specified, one per usage of --pid")]
    target_pids: Option<Vec<i32>>,

    #[arg(long, help = "Script snippet to run to enable complex configurations")]
    script: Option<String>,

    #[arg(long, help = "Script file to run to enable complex configurations")]
    script_file: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Format {
    Nettrace,
    PerfviewXML,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Nettrace => write!(f, "nettrace"),
            Format::PerfviewXML => write!(f, "perfview-xml"),
        }
    }
}

#[derive(Debug)]
pub (crate) struct RecordArgs {
    output_path: PathBuf,
    format: Format,
    on_cpu: bool,
    off_cpu: bool,
    live: bool,
    target_pids: Option<Vec<i32>>,
    script: Option<String>,
}

impl RecordArgs {
    pub fn parse() -> Self {
        let command_args = Args::parse();
        
        // If --out isn't specified, default to the current working directory.
        let output_path = match command_args.out {
            Some(path) => { PathBuf::from(path) },
            None => {
                match env::current_dir() {
                    Ok(current_dir) => current_dir,
                    Err(e) => panic!("{}", format!("Unable to get current working directory: {}", e))
                }
            }
        };

        let script = match command_args.script_file {
            Some(script_file) => {
                match std::fs::read_to_string(script_file) {
                    Ok(script) => { Some(script) },
                    Err(e) => panic!("{}", format!("Unable to read script file: {}", e))
                }
            },
            None => { command_args.script },
        };

        let args = Self {
            output_path,
            format: command_args.format,
            on_cpu: command_args.on_cpu,
            off_cpu: command_args.off_cpu,
            live: command_args.live,
            target_pids: command_args.target_pids,
            script,
        };

        // Cross-argument validation.
        if !args.on_cpu && !args.off_cpu && args.script.is_none() {
            eprintln!("No events or scripts selected. Exiting.");
            process::exit(1);
        }

        args
    }

    pub (crate) fn output_path(&self) -> &PathBuf {
        &self.output_path
    }

    pub (crate) fn format(&self) -> Box<dyn Exporter> {
        match self.format {
            Format::Nettrace => Box::new(NetTraceExporter::new()),
            Format::PerfviewXML => Box::new(PerfViewExporter::new()),
        }
    }

    pub (crate) fn on_cpu(&self) -> bool {
        self.on_cpu
    }

    pub (crate) fn off_cpu(&self) -> bool {
        self.off_cpu
    }

    pub (crate) fn live(&self) -> bool {
        self.live
    }

    pub (crate) fn target_pids(&self) -> &Option<Vec<i32>> {
        &self.target_pids
    }

    pub (crate) fn script(&self) -> &Option<String> {
        &self.script
    }
}
