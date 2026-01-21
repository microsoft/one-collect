// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use tracing::{error, info, debug};

use clap::{crate_version, Parser, ValueEnum};
use std::env;
use std::fmt;
use std::path::PathBuf;
use std::ffi::OsString;
use std::process;

use crate::export::{Exporter, NetTraceExporter, PerfViewExporter};

#[derive(Parser)]
#[command(name = "record-trace", version = crate_version!(), about, long_about = None)]
struct Args {
    #[arg(long, help = "Output directory")]
    out: Option<String>,

    #[arg(long, default_value_t = Format::Nettrace, help = "Output format")]
    format: Format,

    #[arg(long, help = "Capture CPU samples")]
    on_cpu: bool,

    #[arg(long, help = "Capture context switches")]
    off_cpu: bool,

    #[arg(long, help = "Capture soft page faults")]
    soft_page_faults: bool,

    #[arg(long, help = "Capture hard page faults")]
    hard_page_faults: bool,

    #[arg(long, help = "Display samples live")]
    live: bool,

    #[arg(long = "pid", help = "Capture data for the specified process ID.  Multiple pids can be specified, one per usage of --pid")]
    target_pids: Option<Vec<i32>>,

    #[arg(long = "cpu", help = "Capture data for the specified CPU.  Multiple cpus can be specified, one per usage of --cpu")]
    target_cpus: Option<Vec<u16>>,

    #[arg(long, help = "Script snippet to run to enable complex configurations")]
    script: Option<String>,

    #[arg(long, help = "Script file to run to enable complex configurations")]
    script_file: Option<String>,

    #[arg(long, help = "Log filter configuration (e.g., 'target1=info,target2=debug')")]
    log_filter: Option<String>,

    #[arg(long, help = "Log file path")]
    log_path: Option<String>,

    #[arg(long, default_value_t = LogMode::File, help = "Log mode: 'disabled', 'console', or 'file'")]
    log_mode: LogMode,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LogMode {
    Disabled,
    Console,
    File,
}

impl fmt::Display for LogMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogMode::Disabled => write!(f, "disabled"),
            LogMode::Console => write!(f, "console"),
            LogMode::File => write!(f, "file"),
        }
    }
}

#[derive(Debug)]
pub struct RecordArgs {
    output_path: PathBuf,
    format: Format,
    on_cpu: bool,
    off_cpu: bool,
    soft_page_faults: bool,
    hard_page_faults: bool,
    live: bool,
    target_pids: Option<Vec<i32>>,
    target_cpus: Option<Vec<u16>>,
    script: Option<String>,
    log_filter: Option<String>,
    log_path: Option<String>,
    log_mode: LogMode,
}

impl RecordArgs {
    pub fn parse<I, T>(args: I) -> Self 
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone {
        let command_args = Args::parse_from(args);
        
        // If --out isn't specified, default to the current working directory.
        let output_path = match command_args.out {
            Some(path) => { 
                debug!("Output path specified: path={}", path);
                PathBuf::from(path) 
            },
            None => {
                match env::current_dir() {
                    Ok(current_dir) => {
                        debug!("Using current working directory: path={}", current_dir.display());
                        current_dir
                    },
                    Err(e) => panic!("{}", format!("Unable to get current working directory: {}", e))
                }
            }
        };

        let script = match command_args.script_file {
            Some(script_file) => {
                debug!("Loading script from file: path={}", script_file);
                match std::fs::read_to_string(script_file) {
                    Ok(script) => { 
                        debug!("Script loaded successfully");
                        Some(script) 
                    },
                    Err(e) => panic!("{}", format!("Unable to read script file: {}", e))
                }
            },
            None => { 
                command_args.script 
            },
        };

        let args = Self {
            output_path,
            format: command_args.format,
            on_cpu: command_args.on_cpu,
            off_cpu: command_args.off_cpu,
            soft_page_faults: command_args.soft_page_faults,
            hard_page_faults: command_args.hard_page_faults,
            live: command_args.live,
            target_pids: command_args.target_pids,
            target_cpus: command_args.target_cpus,
            script,
            log_filter: command_args.log_filter,
            log_path: command_args.log_path,
            log_mode: command_args.log_mode,
        };

        // Cross-argument validation.
        if !args.on_cpu && !args.off_cpu &&
            !args.soft_page_faults && !args.hard_page_faults &&
            args.script.is_none() {
            error!("No events or scripts selected");
            eprintln!("No events or scripts selected. Exiting.");
            process::exit(1);
        }

        args
    }

    pub fn output_path(&self) -> &PathBuf {
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

    pub (crate) fn soft_page_faults(&self) -> bool {
        self.soft_page_faults
    }

    pub (crate) fn hard_page_faults(&self) -> bool {
        self.hard_page_faults
    }

    pub (crate) fn live(&self) -> bool {
        self.live
    }

    pub (crate) fn target_pids(&self) -> &Option<Vec<i32>> {
        &self.target_pids
    }

    pub (crate) fn target_cpus(&self) -> &Option<Vec<u16>> {
        &self.target_cpus
    }

    pub (crate) fn script(&self) -> &Option<String> {
        &self.script
    }

    pub fn log_filter(&self) -> &Option<String> {
        &self.log_filter
    }

    pub fn log_path(&self) -> &Option<String> {
        &self.log_path
    }

    pub fn log_mode(&self) -> LogMode {
        self.log_mode
    }

    pub fn write_to_log(&self) {
        info!("Arguments parsed: output_path={}", self.output_path.display());
        info!("Arguments parsed: format={}", self.format);
        info!("Arguments parsed: on_cpu={}", self.on_cpu);
        info!("Arguments parsed: off_cpu={}", self.off_cpu);
        info!("Arguments parsed: soft_page_faults={}", self.soft_page_faults);
        info!("Arguments parsed: hard_page_faults={}", self.hard_page_faults);
        info!("Arguments parsed: live={}", self.live);
        if let Some(ref pids) = self.target_pids {
            info!("Arguments parsed: target_pids={:?}", pids);
        }
        if let Some(ref cpus) = self.target_cpus {
            info!("Arguments parsed: target_cpus={:?}", cpus);
        }
        if let Some(ref filter) = self.log_filter {
            info!("Arguments parsed: log_filter={}", filter);
        }
        if let Some(ref path) = self.log_path {
            info!("Arguments parsed: log_path={}", path);
        }
        info!("Arguments parsed: log_mode={}", self.log_mode);
        if let Some(ref script) = self.script {
            info!("Arguments parsed: script start");
            info!("{}", script);
            info!("Arguments parsed: script end");
        }
    }
}
