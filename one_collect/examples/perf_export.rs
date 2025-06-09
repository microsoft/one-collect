// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use one_collect::helpers::dotnet::*;

use one_collect::helpers::exporting::*;
use one_collect::helpers::exporting::graph::*;
use one_collect::helpers::exporting::formats::perf_view::*;

fn main() {
    let args: Vec<_> = std::env::args().collect();

    if args.len() == 1 {
        println!("Usage: {} <output_directory>", args[0]);
        return;
    }

    let out_dir = &args[1];

    let duration = std::time::Duration::from_secs(5);

    let settings = ExportSettings::default()
        .with_cpu_profiling(1000)
        .with_cswitches();

    let dotnet = UniversalDotNetHelper::default()
        .with_dynamic_symbols();

    let universal = UniversalExporter::new(settings)
        .with_dotnet_help(dotnet);

    println!("Capturing...");
    let exporter = universal.parse_for_duration("perf_export", duration)
        .expect("Check permissions.");

    let mut exporter = exporter.borrow_mut();

    exporter.capture_and_resolve_symbols();

    println!("Exporting...");

    /* Split by comm name */
    let comm_map = exporter.split_processes_by_comm();

    let cpu = exporter.find_sample_kind("cpu").expect("CPU sample kind should be known.");
    let cswitch = exporter.find_sample_kind("cswitch").expect("CSwitch sample kind should be known.");

    let mut graph = ExportGraph::new();
    let mut buf: String;

    for (comm_id, pids) in comm_map {
        match comm_id {
            None => {
                for pid in pids {
                    let single_pid = vec![pid];

                    let path = format!("{}/t.Unknown.{}.CPU.PerfView.xml", out_dir, pid);

                    export_pids(
                        &exporter,
                        &mut graph,
                        &single_pid,
                        cpu,
                        &path,
                        "CPU Samples");

                    let path = format!("{}/t.Unknown.{}.CSwitch.PerfView.xml", out_dir, pid);

                    export_pids(
                        &exporter,
                        &mut graph,
                        &single_pid,
                        cswitch,
                        &path,
                        "Wait Time");
                }
            },
            Some(comm_id) => {
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

                let path = format!("{}/t.{}.CPU.PerfView.xml", out_dir, comm);

                export_pids(
                    &exporter,
                    &mut graph,
                    &pids,
                    cpu,
                    &path,
                    "CPU Samples");

                let path = format!("{}/t.{}.CSwitch.PerfView.xml", out_dir, comm);

                export_pids(
                    &exporter,
                    &mut graph,
                    &pids,
                    cswitch,
                    &path,
                    "Wait Time");
            }
        }
    }
}

fn export_pids(
    exporter: &ExportMachine,
    graph: &mut ExportGraph,
    pids: &[u32],
    kind: u16,
    path: &str,
    sample_desc: &str) {
    graph.reset();

    for pid in pids {
        let process = exporter.find_process(*pid).expect("PID should be found.");

        graph.add_samples(
            &exporter,
            process,
            kind,
            None);
    }

    let total = graph.nodes()[graph.root_node()].total();

    if total != 0 {
        graph.to_perf_view_xml(path).expect("Export should work.");

        println!("{}: {} {}", path, total, sample_desc);
    }
}
