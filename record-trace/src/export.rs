use one_collect::helpers::exporting::ExportMachine;
use one_collect::helpers::exporting::formats::perf_view::*;
use one_collect::helpers::exporting::graph::ExportGraph;

use crate::commandline::RecordArgs;

pub (crate) trait Exporter {
    fn run(
        machine: &ExportMachine,
        args: &RecordArgs) -> bool;
}

pub (crate) struct PerfViewExporter {
}

impl Exporter for PerfViewExporter {
    fn run(
        machine: &ExportMachine,
        args: &RecordArgs
    ) -> bool {
         /* Split by comm name */
         let comm_map = machine.split_processes_by_comm();

         let cpu = machine.find_sample_kind("cpu").expect("CPU sample kind should be known.");
 
         let mut graph = ExportGraph::new();
         let mut buf: String;
 
         for (comm_id, pids) in comm_map {
             match comm_id {
                 None => {
                     for pid in pids {
                         /* Merge by Unknown PID */
                         graph.reset();
 
                         let process = machine.find_process(pid).expect("PID should be found.");
 
                         graph.add_samples(
                             machine,
                             process,
                             cpu);
 
                         let total = graph.nodes()[graph.root_node()].total();
 
                         if total == 0 {
                             continue;
                         }
 
                         /* Save as Unknown PID */
                         let path = format!("{}/t.Unknown.{}.PerfView.xml", args.output_path().display(), pid);
 
                         graph.to_perf_view_xml(&path).expect("Export should work.");
                     }
                 },
                 Some(comm_id) => {
                     graph.reset();
 
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
 
                     for pid in pids {
                         let process = machine.find_process(pid).expect("PID should be found.");
                         graph.add_samples(
                             machine,
                             process,
                             cpu);
                     }
 
                     let total = graph.nodes()[graph.root_node()].total();
 
                     if total == 0 {
                         continue;
                     }
 
                     /* Save as name */
                     let path = format!("{}/t.{}.PerfView.xml", args.output_path().display(), comm);
 
                     graph.to_perf_view_xml(&path).expect("Export should work.");
                 }
             }
         }
        true
    }
}