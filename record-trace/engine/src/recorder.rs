// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use tracing::{error, info, debug};

use crate::commandline::RecordArgs;
use crate::EngineOutput;

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

const DEFAULT_CPU_FREQUENCY: u64 = 1000;

pub struct Recorder {
    args: RecordArgs,
    output: Arc<EngineOutput>,
}

impl Recorder {
    pub fn new(
        args: RecordArgs,
        output: EngineOutput) -> Self {
        Self {
            args,
            output: Arc::new(output),
        }
    }

    pub fn run(&mut self) -> i32 {
        let mut format = self.args.format();
        if let Err(e) = format.validate(&self.args) {
            error!("Format validation failed: error={}", e);
            self.output.error(&format!("Error: {}", e));
            return 1;
        }

        let mut settings = ExportSettings::default()
            .with_version_attributes()
            .with_trace_context_attributes()
            .with_activity_id_attributes();

        // CPU sampling.
        if self.args.on_cpu() {
            debug!("CPU sampling enabled: frequency={}", DEFAULT_CPU_FREQUENCY);
            settings = settings.with_cpu_profiling(DEFAULT_CPU_FREQUENCY);
        }

        // Context switches.
        if self.args.off_cpu() {
            debug!("Context switch sampling enabled");
            settings = settings.with_cswitches();
        }

        // Page faults.
        if self.args.soft_page_faults() {
            debug!("Soft page fault sampling enabled");
            settings = settings.with_soft_page_faults();
        }

        if self.args.hard_page_faults() {
            debug!("Hard page fault sampling enabled");
            settings = settings.with_hard_page_faults();
        }

        let continue_recording = Arc::new(AtomicBool::new(true));

        // Live.
        if self.args.live() {
            use std::collections::HashMap;
            use one_collect::helpers::exporting::process::MetricValue;

            let now = std::time::Instant::now();
            let qpc_freq = ExportMachine::qpc_freq();

            type FormatWriteFn = Box<dyn FnMut(&mut String, &[u8])>;
            let record_lookup: HashMap<u16, FormatWriteFn> = HashMap::new();
            let record_lookup = Writable::new(record_lookup);

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
            let sample_continue = continue_recording.clone();
            let sample_output = self.output.clone();

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

                if let Some(record) = context.sample_record_data() {
                    let mut record_lookup = record_lookup.borrow_mut();

                    let id = record.record_type_id();

                    let closure = record_lookup.entry(id).or_insert_with(|| {
                        record.record_type().format().get_write_closure()
                    });

                    let _ = write!(line, "\nRecord: ");
                    closure(&mut line, record.record_data());
                }

                // Send live output
                if sample_output.live(&line) != 0 {
                    // Output resulted in a cancellation.
                    sample_continue.store(false, Ordering::SeqCst);
                }

                ExportFilterAction::Keep
            });
        }

        // Filter pids.
        if let Some(target_pids) = self.args.target_pids() {
            debug!("Process filter enabled: pids={:?}", target_pids);
            for target_pid in target_pids {
                settings = settings.with_target_pid(*target_pid);
            }
        }

        let dotnet = UniversalDotNetHelper::default()
            .with_dynamic_symbols();

        let universal = match self.args.script() {
            Some(script) => {
                debug!("Script-based configuration enabled");
                let mut scripted = ScriptedUniversalExporter::new(settings);

                scripted.enable_os_scripting();
                scripted.enable_dotnet_scripting();

                match scripted.from_script(script) {
                    Ok(universal) => { 
                        debug!("Script loaded successfully");
                        universal 
                    },
                    Err(e) => {
                        error!("Script loading failed: error={}", e);
                        self.output.error(&format!("Error: {}", e));
                        return 1;
                    }
                }
            },
            None => {
                debug!("Using default configuration");
                UniversalExporter::new(settings)
            }
        }.with_dotnet_help(dotnet);
        
        // Start recording.
        info!("Starting recording session");
        let print_banner = Arc::new(AtomicBool::new(true));
        let parse_output = self.output.clone();

        let parse_result = universal.parse_until("record-trace", move || {
            // Print the banner telling the user that recording has started.
            if print_banner.load(Ordering::SeqCst) {
                print_banner.store(false, Ordering::SeqCst);
                parse_output.start("Recording started.");
            }

            // Give progress callback.
            if parse_output.progress("") != 0 {
                // Non-zero results in cancellation.
                continue_recording.store(false, Ordering::SeqCst);
            }

            // When a callback returns non-zero, this will flip.
            !continue_recording.load(Ordering::SeqCst)
        });

        let exporter = match parse_result {
            Ok(exporter) => {
                info!("Recording session completed successfully");
                exporter
            },
            Err(e) => {
                error!("Recording session failed: error={}", e);
                self.output.error(&format!("Error: {}", e));
                return 1;
            }
        };

        self.output.end("Recording stopped.");
        let mut exporter = exporter.borrow_mut();

        // Capture binary metdata and resolve symbols.
        info!("Resolving symbols");
        self.output.normal("Resolving symbols.");
        exporter.capture_and_resolve_symbols();

        if let Err(e) = format.run(&mut exporter, &self.args) {
            error!("Export failed: error={}", e);
            self.output.error(&format!("Error: {}", e));
            exporter.cleanup();
            return 1;
        }

        info!("Trace written successfully: path={}", self.args.output_path().display());
        self.output.normal("Finished recording trace.");
        self.output.normal(
            &format!("Trace written to {}", self.args.output_path().display()));

        exporter.cleanup();

        0
    }
}
