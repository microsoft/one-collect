use one_collect::perf_event::*;

use one_collect::helpers::exporting::*;
use one_collect::helpers::exporting::graph::*;
use one_collect::helpers::exporting::formats::perf_view::*;

use one_collect::helpers::callstack::*;

use one_collect::helpers::dotnet::*;

fn main() {
    let args: Vec<_> = std::env::args().collect();

    if args.len() == 1 {
        println!("Usage: {} <output_directory>", args[0]);
        return;
    }

    let out_dir = &args[1];

    let duration = std::time::Duration::from_secs(5);
    let need_permission = "Need permission (run via sudo?)";

    let helper = CallstackHelper::new()
        .with_dwarf_unwinding();

    let settings = ExportSettings::new(helper)
        .without_cswitches();

    let mut dotnet = DotNetHelper::new()
        .with_perf_maps();

    let mut builder = RingBufSessionBuilder::new()
        .with_page_count(256)
        .with_exporter_events(&settings)
        .with_dotnet_help(&mut dotnet);

    let mut session = builder.build().unwrap();

    let exporter = session.build_exporter(settings).unwrap();

    session.lost_event().add_callback(|_,_,_| {
        println!("WARN: Lost event data");

        Ok(())
    });

    session.lost_samples_event().add_callback(|_,_,_| {
        println!("WARN: Lost samples data");

        Ok(())
    });

    println!("Capturing environment...");
    session.capture_environment();

    println!("Profiling...");
    session.enable().expect(need_permission);
    session.parse_for_duration(duration).unwrap();
    session.disable().expect(need_permission);

    let mut exporter = exporter.borrow_mut();

    println!("Adding kernel mappings...");
    /* Pull in more data, if wanted */
    exporter.add_kernel_mappings();

    println!("Resolving perfmap symbols...");
    exporter.resolve_perf_map_symbols();

    dotnet.disable_perf_maps();
    dotnet.remove_perf_maps();

    println!("Exporting...");

    /* Split by comm name */
    let comm_map = exporter.split_processes_by_comm();

    let cpu = exporter.find_sample_kind("cpu").expect("CPU sample kind should be known.");

    let mut graph = ExportGraph::new();

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

                    /* Save as Uknown PID */
                    let path = format!("{}/t.Unknown.{}.PerfView.xml", out_dir, pid);

                    graph.to_perf_view_xml(&path).expect("Export should work.");

                    println!("{}: {} Samples", path, total);
                }
            },
            Some(comm_id) => {
                graph.reset();

                /* Merge by name */
                let comm = match exporter.strings().from_id(comm_id) {
                    Ok(comm) => { comm },
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
