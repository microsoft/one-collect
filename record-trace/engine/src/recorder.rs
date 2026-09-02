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

fn per_cpu_buffer_size(
    total_bytes: usize,
    cpu_count: u32) -> usize {
    total_bytes.div_ceil(cpu_count.max(1) as usize)
}

/// Returns the current process's resident memory usage in bytes, or `None`
/// if it cannot be determined on this platform.
#[cfg(target_os = "windows")]
fn current_process_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo,
        PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: We pass a zeroed, correctly-sized PROCESS_MEMORY_COUNTERS and the
    // size of that structure. GetProcessMemoryInfo fills it in and the pseudo
    // handle from GetCurrentProcess is always valid for the current process.
    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) != 0 {
            Some(counters.WorkingSetSize as u64)
        } else {
            None
        }
    }
}

/// Returns the current process's resident memory usage in bytes, or `None`
/// if it cannot be determined on this platform.
#[cfg(target_os = "linux")]
fn current_process_memory_bytes() -> Option<u64> {
    // /proc/self/statm reports the resident set size as a count of pages in
    // its second field.
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;

    Some(rss_pages.saturating_mul(one_collect::os::system_page_size()))
}

/// Returns the current process's resident memory usage in bytes, or `None`
/// if it cannot be determined on this platform.
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn current_process_memory_bytes() -> Option<u64> {
    None
}

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
            .with_activity_id_attributes()
            .with_cgroup_attributes();

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

                let cgroup_id = context.cgroup_id();
                if cgroup_id != 0 {
                    let _ = write!(line, "CGroup={} ", cgroup_id);
                }

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

        // Filter cpus.
        if let Some(target_cpus) = self.args.target_cpus() {
            info!("CPU filter enabled: cpus={:?}", target_cpus);
            for target_cpu in target_cpus {
                settings = settings.with_target_cpu(*target_cpu);
            }
        }

        let dotnet = UniversalDotNetHelper::default()
            .with_dynamic_symbols()
            .with_cleanup_timeout(self.args.dotnet_cleanup_timeout());

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
        };

        let universal = match self.args.buffer_size_bytes() {
            Some(total_bytes) => {
                let cpu_count = ExportMachine::cpu_count();
                let per_cpu_bytes = per_cpu_buffer_size(total_bytes, cpu_count);
                info!(
                    "Configuring event buffers: total_bytes={}, cpu_count={}, per_cpu_bytes={}",
                    total_bytes, cpu_count, per_cpu_bytes);
                universal.with_per_cpu_buffer_bytes(per_cpu_bytes)
            },
            None => universal,
        }.with_dotnet_help(dotnet);
        
        // Start recording.
        info!("Starting recording session");
        let print_banner = Arc::new(AtomicBool::new(true));
        let parse_output = self.output.clone();

        // Stop conditions configured via the command line.
        // The duration clock starts now, immediately before recording begins.
        let deadline = self.args.duration()
            .map(|duration| std::time::Instant::now() + duration);

        // Querying process memory can be slow, so poll it on a dedicated
        // background thread rather than inside the hot parse_until closure.
        // The thread flips continue_recording once the limit is exceeded.
        let memory_monitor = match self.args.max_memory_bytes() {
            Some(max_memory_bytes) if current_process_memory_bytes().is_some() => {
                let monitor_output = self.output.clone();
                let monitor_continue = continue_recording.clone();
                Some(std::thread::spawn(move || {
                    const POLL_INTERVAL: std::time::Duration =
                        std::time::Duration::from_millis(250);

                    while monitor_continue.load(Ordering::SeqCst) {
                        if let Some(used) = current_process_memory_bytes() {
                            if used >= max_memory_bytes {
                                info!(
                                    "Stopping recording: memory limit reached: used_bytes={} limit_bytes={}",
                                    used, max_memory_bytes);
                                monitor_output.normal("Memory limit reached.");
                                monitor_continue.store(false, Ordering::SeqCst);
                                break;
                            }
                        }

                        std::thread::sleep(POLL_INTERVAL);
                    }
                }))
            },
            Some(_) => {
                self.output.error(
                    "Warning: --max-memory is not supported on this platform and will be ignored.");
                None
            },
            None => None,
        };

        let parse_result = universal.parse_until(self.args.session_name(), move || {
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

            // Stop once the configured duration has elapsed.
            if let Some(deadline) = deadline {
                if std::time::Instant::now() >= deadline {
                    info!("Stopping recording: duration limit reached");
                    parse_output.normal("Duration limit reached.");
                    continue_recording.store(false, Ordering::SeqCst);
                }
            }

            // When a callback returns non-zero, this will flip.
            // The memory monitor thread (if any) also flips this when the
            // configured memory limit is exceeded.
            !continue_recording.load(Ordering::SeqCst)
        });

        // Recording has stopped; continue_recording is now false, so the
        // memory monitor thread (if any) will observe it and exit.
        if let Some(memory_monitor) = memory_monitor {
            let _ = memory_monitor.join();
        }

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

        // Capture binary metadata and resolve symbols.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divides_total_buffer_across_cpus() {
        assert_eq!(2 * 1024 * 1024, per_cpu_buffer_size(8 * 1024 * 1024, 4));
    }

    #[test]
    fn rounds_per_cpu_buffer_up() {
        assert_eq!(3, per_cpu_buffer_size(8, 3));
    }
}
