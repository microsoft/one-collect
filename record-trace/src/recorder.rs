use crate::commandline::RecordArgs;
use one_collect::helpers::dotnet::UniversalDotNetHelp;
use one_collect::helpers::{dotnet::universal::UniversalDotNetHelper, exporting::ExportSettings};
use one_collect::helpers::exporting::formats::perf_view::*;
use one_collect::helpers::exporting::graph::ExportGraph;
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
                println!("Recording trace.  Press CTRL+C to stop.");
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

        /* Split by comm name */
        let comm_map = exporter.split_processes_by_comm();

        println!("Writing files to disk.");
        let cpu = exporter.find_sample_kind("cpu").expect("CPU sample kind should be known.");

        let mut graph = ExportGraph::new();
        let mut buf: String;

        for (comm_id, pids) in comm_map {
            match comm_id {
                None => {
                    for pid in pids {
                        /* Merge by Unknown PID */
                        graph.reset();

                        let process = exporter.find_process(pid).expect("PID should be found.");

                        graph.add_samples(
                            &exporter,
                            process,
                            cpu);

                        let total = graph.nodes()[graph.root_node()].total();

                        if total == 0 {
                            continue;
                        }

                        /* Save as Unknown PID */
                        let path = format!("{}/t.Unknown.{}.PerfView.xml", self.args.output_path().display(), pid);

                        graph.to_perf_view_xml(&path).expect("Export should work.");

                        println!("{}: {} Samples", path, total);
                    }
                },
                Some(comm_id) => {
                    graph.reset();

                    /* Merge by name */
                    let comm = match exporter.strings().from_id(comm_id) {
                        Ok(comm) => {
                            if comm.contains(":") || comm.contains("/") {
                                buf = comm.replace(":", "_").replace("/", "_");
                                &buf
                            } else {
                                comm
                            }
                        },
                        Err(_) => { "Unknown" },
                    };

                    for pid in pids {
                        let process = exporter.find_process(pid).expect("PID should be found.");
                        graph.add_samples(
                            &exporter,
                            process,
                            cpu);
                    }

                    let total = graph.nodes()[graph.root_node()].total();

                    if total == 0 {
                        continue;
                    }

                    /* Save as name */
                    let path = format!("{}/t.{}.PerfView.xml", self.args.output_path().display(), comm);

                    graph.to_perf_view_xml(&path).expect("Export should work.");

                    println!("{}: {} Samples", path, total);
                }
            }
        }

        println!("Finished recording trace.");
    }
}