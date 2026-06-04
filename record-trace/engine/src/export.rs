// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use tracing::{error, warn, info, debug};

use one_collect::helpers::exporting::ExportMachine;
use one_collect::helpers::exporting::formats::nettrace::*;
use one_collect::helpers::exporting::formats::perf_view::*;
use one_collect::helpers::exporting::graph::{ExportGraph, ExportGraphMetricValueConverter};
use one_collect::helpers::exporting::process::MetricValue;

use crate::commandline::RecordArgs;
use anyhow::anyhow;
use std::fs::OpenOptions;
use std::path::PathBuf;

pub (crate) trait Exporter {
    fn validate(
        &mut self,
        args: &RecordArgs) -> anyhow::Result<()>;

    fn run(
        &self,
        machine: &mut ExportMachine,
        args: &RecordArgs) -> anyhow::Result<()>;
}

struct PerfViewExportGraphMetricValueConverter {
    qpc_freq: u64,
}

impl ExportGraphMetricValueConverter for PerfViewExportGraphMetricValueConverter {
    fn convert(
        &self,
        machine: &ExportMachine,
        value: MetricValue) -> u64 {
        match value {
            MetricValue::Count(count) => count,
            MetricValue::Duration(qpc_time) => { ((qpc_time as f64 * 1000.0) / self.qpc_freq as f64) as u64 },
            MetricValue::Bytes(bytes) => bytes,
            MetricValue::Span(_) => {
                match machine.span_from_value(value) {
                    Some(span) => {
                        let qpc_time = span.end_time() - span.start_time();
                        ((qpc_time as f64 * 1000.0) / self.qpc_freq as f64) as u64
                    },
                    None => { 0 },
                }
            }
        }
    }
}

impl PerfViewExportGraphMetricValueConverter {
    fn new(qpc_freq: u64) -> Self {
        Self {
            qpc_freq,
        }
    }
}

pub (crate) struct PerfViewExporter {
}

impl PerfViewExporter {
    pub (crate) fn new() -> Self {
        Self {
        }
    }
}

impl Exporter for PerfViewExporter {
    fn validate(
        &mut self,
        args: &RecordArgs) -> anyhow::Result<()> {
        let output_path = args.output_path();
        if output_path.exists() && !output_path.is_dir() {
            warn!("Export path is not a directory: path={}", output_path.display());
            return Err(anyhow!("{} is not a directory.", output_path.display()));
        }
        else if !output_path.exists() {
            warn!("Export path does not exist: path={}", output_path.display());
            return Err(anyhow!("{} does not exist.", output_path.display()));
        }

        debug!("Export path validated: path={}", output_path.display());
        Ok(())
    }

    fn run(
        &self,
        machine: &mut ExportMachine,
        args: &RecordArgs) -> anyhow::Result<()> {
        
        info!("Starting PerfView XML export");
        let converter = PerfViewExportGraphMetricValueConverter::new(ExportMachine::qpc_freq());

        /* Split by comm name */
        let comm_map = machine.split_processes_by_comm();
        debug!("Processes split by comm: count={}", comm_map.len());

        let cpu = match machine.find_sample_kind("cpu") {
            Some(cpu) => { 
                debug!("CPU sample kind found: kind={}", cpu);
                cpu 
            },
            None => {
                if args.on_cpu() {
                    warn!("CPU sample kind not found but CPU sampling was enabled");
                    return Err(anyhow!("CPU sample kind should be known."));
                }

                0
            }
        };

        let cswitch = match machine.find_sample_kind("cswitch") {
            Some(cswitch) => { 
                debug!("CSwitch sample kind found: kind={}", cswitch);
                cswitch 
            },
            None => {
                if args.off_cpu() {
                    warn!("CSwitch sample kind not found but context switch sampling was enabled");
                    return Err(anyhow!("CSwitch sample kind should be known."));
                }

                0
            }
        };

        let mut graph = ExportGraph::new();
        let mut buf: String;

        for (comm_id, pids) in comm_map {
            match comm_id {
                None => {
                    for pid in pids {
                        let single_pid = vec![pid];

                        if args.on_cpu() {
                            let path = format!("{}/t.Unknown.{}.CPU.PerfView.xml", args.output_path().display(), pid);

                            Self::export_pids(
                                machine,
                                &mut graph,
                                &converter,
                                &single_pid,
                                cpu,
                                &path,
                                "CPU Samples");
                        }

                        if args.off_cpu() {
                            let path = format!("{}/t.Unknown.{}.CSwitch.PerfView.xml", args.output_path().display(), pid);

                            Self::export_pids(
                                machine,
                                &mut graph,
                                &converter,
                                &single_pid,
                                cswitch,
                                &path,
                                "Wait Time");
                        }
                    }
                },
                Some(comm_id) => {
                    /* Merge by name */
                    let comm = match machine.strings().from_id(comm_id) {
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

                    if args.on_cpu() {
                        let path = format!("{}/t.{}.CPU.PerfView.xml", args.output_path().display(), comm);

                        Self::export_pids(
                            machine,
                            &mut graph,
                            &converter,
                            &pids,
                            cpu,
                            &path,
                            "CPU Samples");
                    }

                    if args.off_cpu() {
                        let path = format!("{}/t.{}.CSwitch.PerfView.xml", args.output_path().display(), comm);

                        Self::export_pids(
                            machine,
                            &mut graph,
                            &converter,
                            &pids,
                            cswitch,
                            &path,
                            "Wait Time");
                    }
                }
            }
        }
        info!("PerfView XML export completed successfully");
        Ok(())
    }
}

impl PerfViewExporter {
    fn export_pids(
        exporter: &ExportMachine,
        graph: &mut ExportGraph,
        converter: &PerfViewExportGraphMetricValueConverter,
        pids: &[u32],
        kind: u16,
        path: &str,
        sample_desc: &str) {
        graph.reset();

        for pid in pids {
            let process = exporter.find_process(*pid).expect("PID should be found.");

            graph.add_samples(
                exporter,
                process,
                kind,
                Some(converter));
        }

        let total = graph.nodes()[graph.root_node()].total();

        if total != 0 {
            graph.to_perf_view_xml(path).expect("Export should work.");

            println!("{}: {} {}", path, total, sample_desc);
        }
    }
}

pub (crate) struct NetTraceExporter {
    output_path: PathBuf,
}

impl NetTraceExporter {
    pub (crate) fn new() -> Self {
        Self {
            output_path: PathBuf::new(),
        }
    }

    fn resolve_output_path(output_path: &PathBuf) -> PathBuf {
        if output_path.exists() && output_path.is_dir() {
            debug!("Using default output filename: trace.nettrace");
            output_path.join("trace.nettrace")
        }
        else {
            output_path.to_owned()
        }
    }

    fn validate_output_file_path(output_path: &PathBuf) -> anyhow::Result<()> {
        if output_path.exists() && output_path.is_dir() {
            warn!("NetTrace export path is a directory: path={}", output_path.display());
            return Err(anyhow!(
                "The output path {} is a directory. Please provide a file path (for example, trace.nettrace).",
                output_path.display()
            ));
        }

        if let Some(parent) = output_path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            if !parent.exists() {
                warn!("NetTrace export parent path does not exist: path={}", parent.display());
                return Err(anyhow!(
                    "The output directory {} does not exist. Please create it and try again.",
                    parent.display()
                ));
            }
            else if !parent.is_dir() {
                warn!("NetTrace export parent path is not a directory: path={}", parent.display());
                return Err(anyhow!(
                    "The parent path {} exists but is not a directory. Please provide a path with a valid directory as the parent.",
                    parent.display()
                ));
            }
        }

        let output_exists = output_path.exists();
        let open_result = if output_exists {
            OpenOptions::new()
                .write(true)
                .open(output_path)
        }
        else {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output_path)
        };

        match open_result {
            Ok(_) => {
                if !output_exists {
                    std::fs::remove_file(output_path)?;
                }

                Ok(())
            },
            Err(error) => {
                warn!("NetTrace export path is not writable: path={}, error={}", output_path.display(), error);
                Err(anyhow!("{} is not writable: {}", output_path.display(), error))
            },
        }
    }
}

impl Exporter for NetTraceExporter {
    fn validate(
        &mut self,
        args: &RecordArgs) -> anyhow::Result<()> {
        self.output_path = Self::resolve_output_path(args.output_path());
        Self::validate_output_file_path(&self.output_path)?;

        Ok(())
    }

    fn run(
        &self,
        machine: &mut ExportMachine,
        _args: &RecordArgs) -> anyhow::Result<()> {

        info!("Starting NetTrace export: path={}", self.output_path.display());
        if let Err(e) = machine.to_net_trace(|_proc| { true }, &self.output_path.to_str().unwrap()) {
            error!("NetTrace export failed: error={}", e);
        }
        info!("NetTrace export completed successfully");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after unix epoch")
            .as_nanos();

        std::env::temp_dir().join(format!("record-trace-{name}-{nanos}"))
    }

    #[test]
    fn nettrace_directory_path_with_extension_uses_default_filename() {
        let out_dir = unique_temp_path("out-dir");
        let out_dir_with_extension = out_dir.with_extension("data");
        std::fs::create_dir_all(&out_dir_with_extension).expect("Temp output directory should be created");

        let mut exporter = NetTraceExporter::new();
        let args = RecordArgs::parse([
            "record-trace",
            "--on-cpu",
            "--out",
            &out_dir_with_extension.to_string_lossy(),
        ]);

        let result = exporter.validate(&args);

        std::fs::remove_dir_all(out_dir_with_extension).expect("Temp output directory should be removed");

        assert!(result.is_ok());
        assert!(exporter.output_path.ends_with("trace.nettrace"));
    }

    #[test]
    fn nettrace_missing_parent_path_fails_validation() {
        let missing_parent = unique_temp_path("missing-parent");
        let out_file = missing_parent.join("trace.nettrace");

        let mut exporter = NetTraceExporter::new();
        let args = RecordArgs::parse([
            "record-trace",
            "--on-cpu",
            "--out",
            &out_file.to_string_lossy(),
        ]);

        let result = exporter.validate(&args);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Please create it and try again"));
    }
}
