use crate::commandline::RecordArgs;
use crate::export::{Exporter, PerfViewExporter};
use one_collect::helpers::dotnet::UniversalDotNetHelp;
use one_collect::helpers::{dotnet::universal::UniversalDotNetHelper, exporting::ExportSettings};
use one_collect::helpers::exporting::universal::UniversalExporter;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use ctrlc;
use std::process;

const DEFAULT_CPU_FREQUENCY: u64 = 1000;

pub (crate) struct Recorder {
    args: RecordArgs,
}

impl Recorder {
    pub (crate) fn new(args: RecordArgs) -> Self {
        Self {
            args,
        }
    }

    pub (crate) fn run(&mut self) {
        let mut settings = ExportSettings::default();

        // CPU sampling.
        if self.args.on_cpu() {
            settings = settings.with_cpu_profiling(DEFAULT_CPU_FREQUENCY);
        }

        // Context switches.
        if self.args.off_cpu() {
            settings = settings.with_cswitches();
        }

        // Filter pids.
        if let Some(target_pids) = self.args.target_pids() {
            for target_pid in target_pids {
                settings = settings.with_target_pid(*target_pid);
            }
        }

        let dotnet = UniversalDotNetHelper::default()
            .with_dynamic_symbols();

        let universal = UniversalExporter::new(settings)
            .with_dotnet_help(dotnet);

        // Record until the user hits CTRL+C.
        let continue_recording = Arc::new(AtomicBool::new(true));
        let handler_clone = continue_recording.clone();
        ctrlc::set_handler(move || {
            handler_clone.store(false, Ordering::SeqCst);
        }).expect("Unable to setup CTRL+C handler");
        
        
        // Start recording.
        let print_banner = Arc::new(AtomicBool::new(true));

        let exporter = match universal.parse_until("record-trace", move || {
            
            // Print the banner telling the user that recording has started.
            if print_banner.load(Ordering::SeqCst) {
                print_banner.store(false, Ordering::SeqCst);
                println!("Recording started.  Press CTRL+C to stop.");
            }

            // When the user hits CTRL+C this will flip to true.
            !continue_recording.load(Ordering::SeqCst)
        }) {
            Ok(exporter) => exporter,
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        };

        println!("\nRecording stopped.");
        let mut exporter = exporter.borrow_mut();

        // Capture binary metdata and resolve symbols.
        println!("Resolving symbols.");
        exporter.capture_and_resolve_symbols();

        PerfViewExporter::run(&exporter, &self.args);

        println!("Finished recording trace.");
        println!("Trace written to {}", self.args.output_path().display());
    }
}