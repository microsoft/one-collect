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
        .with_cpu_profiling(1000);

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
                    let path = format!("{}/t.Unknown.{}.PerfView.xml", out_dir, pid);

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
                let path = format!("{}/t.{}.PerfView.xml", out_dir, comm);

                graph.to_perf_view_xml(&path).expect("Export should work.");

                println!("{}: {} Samples", path, total);
            }
        }
    }
}
