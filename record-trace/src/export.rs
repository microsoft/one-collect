use one_collect::helpers::exporting::ExportMachine;
use one_collect::helpers::exporting::formats::perf_view::*;
use one_collect::helpers::exporting::graph::{ExportGraph, ExportGraphMetricValueConverter};
use one_collect::helpers::exporting::process::MetricValue;

use crate::commandline::RecordArgs;

pub (crate) trait Exporter {
    fn run(
        machine: &ExportMachine,
        args: &RecordArgs) -> bool;
}

struct PerfViewExportGraphMetricValueConverter {
    qpc_freq: u64,
}

impl ExportGraphMetricValueConverter for PerfViewExportGraphMetricValueConverter {
    fn convert(&self, value: MetricValue) -> u64 {
        match value {
            MetricValue::Count(count) => count,
            MetricValue::Time(qpc_time) => { ((qpc_time as f64 * 1000.0) / self.qpc_freq as f64) as u64 },
            MetricValue::Bytes(bytes) => bytes,
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

impl Exporter for PerfViewExporter {
    fn run(
        machine: &ExportMachine,
        args: &RecordArgs) -> bool {

        let converter = PerfViewExportGraphMetricValueConverter::new(machine.qpc_freq());

        /* Split by comm name */
        let comm_map = machine.split_processes_by_comm();

        let cpu = machine.find_sample_kind("cpu").expect("CPU sample kind should be known.");
        let cswitch = machine.find_sample_kind("cswitch").expect("CSwitch sample kind should be known.");

        let mut graph = ExportGraph::new();
        let mut buf: String;

        for (comm_id, pids) in comm_map {
            match comm_id {
                None => {
                    for pid in pids {
                        let single_pid = vec![pid];

                        let path = format!("{}/t.Unknown.{}.CPU.PerfView.xml", args.output_path().display(), pid);

                        Self::export_pids(
                            machine,
                            &mut graph,
                            &converter,
                            &single_pid,
                            cpu,
                            &path,
                            "CPU Samples");

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

                    let path = format!("{}/t.{}.CPU.PerfView.xml", args.output_path().display(), comm);

                    Self::export_pids(
                        machine,
                        &mut graph,
                        &converter,
                        &pids,
                        cpu,
                        &path,
                        "CPU Samples");

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
    true
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