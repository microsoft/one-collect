// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::commandline::RecordArgs;
use one_collect::helpers::dotnet::UniversalDotNetHelp;
use one_collect::helpers::{dotnet::universal::UniversalDotNetHelper, exporting::ExportSettings};
use one_collect::helpers::exporting::universal::UniversalExporter;

use one_collect::helpers::dotnet::DotNetScripting;
use one_collect::helpers::exporting::{
    ExportMachine,
    ExportFilterAction,
    ExportSampleFilterContext,
    ScriptedUniversalExporter
};
use one_collect::Writable;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::fmt::Write;
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
        let mut format = self.args.format();
        if let Err(e) = format.validate(&self.args) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }

        let mut settings = ExportSettings::default();

        // CPU sampling.
        if self.args.on_cpu() {
            settings = settings.with_cpu_profiling(DEFAULT_CPU_FREQUENCY);
        }

        // Context switches.
        if self.args.off_cpu() {
            settings = settings.with_cswitches();
        }

        // Live.
        if self.args.live() {
            use one_collect::helpers::exporting::process::MetricValue;

            let now = std::time::Instant::now();
            let qpc_freq = ExportMachine::qpc_freq();

            fn append_count(
                count: u64,
                out: &mut String) {
                let _ = write!(out, "{} Count", count);
            }

            fn append_bytes(
                bytes: u64,
                out: &mut String) {
                let kb = bytes as f64 / 1024.0;
                let mb = kb / 1024.0;
                let gb = mb / 1024.0;

                let _ = if gb >= 1.0 {
                    write!(out, "{:.2} GB", gb)
                } else if mb >= 1.0 {
                    write!(out, "{:.2} MB", mb)
                } else if kb >= 1.0 {
                    write!(out, "{:.2} KB", kb)
                } else {
                    write!(out, "{} Bytes", bytes)
                };
            }

            fn append_qpc_duration(
                qpc_freq: u64,
                qpc_duration: u64,
                out: &mut String) {
                let ns = ExportMachine::qpc_to_ns(qpc_freq, qpc_duration);
                let us = ns as f64 / 1000.0;
                let ms = us / 1000.0;
                let secs = ms / 1000.0;

                let _ = if secs >= 1.0 {
                    write!(out, "{:.2} secs", secs)
                } else if ms >= 1.0 {
                    write!(out, "{:.2} ms", ms)
                } else if us >= 1.0 {
                    write!(out, "{:.2} us", us)
                } else {
                    write!(out, "{} ns", ns)
                };
            }

            fn append_span(
                context: &ExportSampleFilterContext,
                qpc_freq: u64,
                out: &mut String) {
                let _ = if let Some(span) = context.sample_span() {
                    append_qpc_duration(qpc_freq, span.qpc_duration(), out);

                    let children = span.children();

                    if !children.is_empty() {
                        let _ = write!(out, ", Spans={{");

                        for child in children {
                            let _ = write!(out, " {}(", context.span_name(child));
                            append_qpc_duration(qpc_freq, child.qpc_duration(), out);
                            let _ = write!(out, ")");
                        }

                        write!(out, " }}")
                    } else {
                        Ok(())
                    }
                } else {
                    write!(out, "ERROR: Orphaned Span")
                };
            }

            let line = Writable::new(String::with_capacity(512));

            settings = settings.with_sample_hook(move |context| {
                let elapsed = now.elapsed();

                let mut line = line.borrow_mut();

                line.clear();

                let _ = write!(
                    line,
                    "+{:.4}: {}({}, PID={}): ",
                    elapsed.as_secs_f64(),
                    context.sample_kind_str(),
                    context.comm_name(),
                    context.pid());

                match context.sample().value() {
                    MetricValue::Count(count) => {
                        append_count(count, &mut line);
                    },
                    MetricValue::Bytes(bytes) => {
                        append_bytes(bytes, &mut line);
                    },
                    MetricValue::Duration(qpc_duration) => {
                        append_qpc_duration(qpc_freq, qpc_duration, &mut line);
                    },
                    MetricValue::Span(_) => {
                        append_span(context, qpc_freq, &mut line);
                    },
                }

                println!("{}", line);

                ExportFilterAction::Keep
            });
        }

        // Filter pids.
        if let Some(target_pids) = self.args.target_pids() {
            for target_pid in target_pids {
                settings = settings.with_target_pid(*target_pid);
            }
        }

        let dotnet = UniversalDotNetHelper::default()
            .with_dynamic_symbols();

        let universal = match self.args.script() {
            Some(script) => {
                let mut scripted = ScriptedUniversalExporter::new(settings);

                scripted.enable_os_scripting();
                scripted.enable_dotnet_scripting();

                match scripted.from_script(script) {
                    Ok(universal) => { universal },
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        process::exit(1);
                    }
                }
            },
            None => {
                UniversalExporter::new(settings)
            }
        }.with_dotnet_help(dotnet);

        // Record until the user hits CTRL+C.
        let continue_recording = Arc::new(AtomicBool::new(true));
        let handler_clone = continue_recording.clone();
        ctrlc::set_handler(move || {
            handler_clone.store(false, Ordering::SeqCst);
        }).expect("Unable to setup CTRL+C handler");
        
        
        // Start recording.
        let print_banner = Arc::new(AtomicBool::new(true));

        let parse_result = universal.parse_until("record-trace", move || {
            
            // Print the banner telling the user that recording has started.
            if print_banner.load(Ordering::SeqCst) {
                print_banner.store(false, Ordering::SeqCst);
                println!("Recording started.  Press CTRL+C to stop.");
            }

            // When the user hits CTRL+C this will flip to true.
            !continue_recording.load(Ordering::SeqCst)
        });

        let exporter = match parse_result {
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

        if let Err(e) = format.run(&mut exporter, &self.args) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }

        println!("Finished recording trace.");
        println!("Trace written to {}", self.args.output_path().display());
    }
}
