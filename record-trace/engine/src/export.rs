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
    pub fn new() -> Self {
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
    pub fn new() -> Self {
        Self {
            output_path: PathBuf::new(),
        }
    }
}

impl Exporter for NetTraceExporter {
    fn validate(
        &mut self,
        args: &RecordArgs) -> anyhow::Result<()> {
        let output_path = args.output_path();
        self.output_path.push(args.output_path());

        if output_path.exists() && output_path.is_dir() {
            if let Some(extension) = output_path.extension() {
                if extension == "nettrace" {
                    warn!("NetTrace export path is a directory: path={}", output_path.display());
                    return Err(anyhow!("{} is a directory.", output_path.display()));
                }
            }
            else {
                debug!("Using default output filename: trace.nettrace");
                self.output_path.push("trace.nettrace");
            }
        }

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
