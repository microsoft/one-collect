// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::HashMap;
use std::collections::hash_map::Entry::{Vacant, Occupied};

use tracing::{debug, info, enabled, Level};

use crate::intern::InternedStrings;
use crate::helpers::exporting::{*};

use super::process::MetricValue;

#[derive(Default, Hash, Eq, PartialEq)]
pub struct Resolvable {
    name_id: usize,
    symbol_id: usize,
    version_id: usize,
}

impl Resolvable {
    pub fn name(&self) -> usize { self.name_id }

    pub fn symbol_identity(&self) -> usize { self.symbol_id }

    pub fn version_details(&self) -> usize { self.version_id }
}

#[derive(Clone, Default, Hash, Eq, PartialEq)]
pub struct Target {
    address: u64,
    resolvable_id: usize,
    method_id: usize,
}

impl Target {
    pub fn address(&self) -> u64 { self.address }

    pub fn resolvable(&self) -> usize { self.resolvable_id }

    pub fn has_resolvable(&self) -> bool { self.resolvable_id != 0 }

    pub fn method(&self) -> usize { self.method_id }

    pub fn has_method(&self) -> bool { self.method_id != 0 }
}

#[derive(Default)]
pub struct Node {
    id: usize,
    target: Target,
    parent_id: usize,
    child_ids: Vec<usize>,
    exclusive: u64,
    total: u64,
}

impl Node {
    pub fn target(&self) -> Target { self.target.clone() }

    pub fn parent(&self) -> usize { self.parent_id }

    pub fn children(&self) -> &[usize] { &self.child_ids }

    pub fn exclusive(&self) -> u64 { self.exclusive }

    pub fn total(&self) -> u64 { self.total }
}

pub trait ExportGraphMetricValueConverter {
    fn convert(
        &self,
        machine: &ExportMachine,
        value: MetricValue) -> u64;
}

pub struct DefaultExportGraphMetricValueConverter {
}

impl ExportGraphMetricValueConverter for DefaultExportGraphMetricValueConverter {
    fn convert(
        &self,
        machine: &ExportMachine,
        value: MetricValue) -> u64 {
        match value {
            MetricValue::Count(value) => { value },
            MetricValue::Bytes(value) => { value },
            MetricValue::Duration(value) => { value },
            MetricValue::Span(_) => {
                match machine.span_from_value(value) {
                    Some(span) => {
                        span.end_time() - span.start_time()
                    },
                    None => { 0 },
                }
            }
        }
    }
}

impl Default for DefaultExportGraphMetricValueConverter {
    fn default() -> Self {
        Self {}
    }
}

pub struct ExportGraph {
    strings: InternedStrings,
    resolvables: Vec<Resolvable>,
    nodes: Vec<Node>,
    frames: Vec<u64>,
}

const UNKNOWN: &str = "Unknown";

impl ExportGraph {
    pub fn new() -> Self {
        let mut new = Self {
            strings: InternedStrings::new(128),
            resolvables: Vec::new(),
            nodes: Vec::new(),
            frames: Vec::new(),
        };

        new.reset();
        new
    }

    pub fn root_node(&self) -> usize { 0 }

    pub fn strings(&self) -> &InternedStrings { &self.strings }

    pub fn strings_mut(&mut self) -> &mut InternedStrings { &mut self.strings }

    pub fn nodes(&self) -> &[Node] { &self.nodes }

    pub fn resolvables(&self) -> &[Resolvable] { &self.resolvables }

    pub fn reset(
        &mut self) {
        self.strings = InternedStrings::new(128);
        self.nodes.clear();
        self.resolvables.clear();

        /* 0 should always be empty/undefined */
        self.strings.to_id("");
        self.resolvables.push(Resolvable::default());

        /* Always have a root node */
        self.add_node(Node::default());
    }

    fn add_node(
        &mut self,
        mut node: Node) -> usize {
        let id = self.nodes.len();
        node.id = id;
        self.nodes.push(node);
        id
    }

    fn charge(
        &mut self,
        parent_id: usize,
        value: u64) {
        let mut id = self.nodes[parent_id].parent_id;

        loop {
            self.nodes[id].total += value;

            if id == 0 {
                break;
            }

            id = self.nodes[id].parent_id;
        }
    }

    fn merge(
        &mut self,
        parent_id: usize,
        target: Target,
        value: u64) -> usize {
        self.nodes[parent_id].total += value;

        for child_id in &self.nodes[parent_id].child_ids {
            if self.nodes[*child_id].target == target {
                return *child_id;
            }
        }

        let mut node = Node::default();
        node.parent_id = parent_id;
        node.target = target;

        let id = self.add_node(node);
        self.nodes[parent_id].child_ids.push(id);

        id
    }

    fn import_resolvable(
        &mut self,
        resolvable: Resolvable) -> usize {
        for (i, existing) in self.resolvables.iter().enumerate() {
            if *existing == resolvable {
                return i;
            }
        }

        let id = self.resolvables.len();
        self.resolvables.push(resolvable);
        id
    }

    fn import_ip(
        &mut self,
        exporter: &ExportMachine,
        process: &ExportProcess,
        time: u64,
        ip: u64) -> Target {
        /* '/' on Linux and '\\' on Windows */
        const SLASH: char = std::path::MAIN_SEPARATOR;

        let strings = exporter.strings();
        let mut target = Target::default();

        if let Some(mapping) = process.find_mapping(ip, Some(time)) {
            let mut resolvable = Resolvable::default();

            let mut name = match strings.from_id(mapping.filename_id()) {
                Ok(name) => { name },
                Err(_) => { UNKNOWN },
            };

            /* Trim file name to the short name, not full path */
            if let Some(short_name) = name.rsplit(SLASH).next() {
                name = short_name;
            }

            /* Calc file address, unless anonymous */
            if !mapping.anon() {
                if ip > KERNEL_START {
                    target.address = ip;
                } else {
                    target.address = ip - mapping.start();
                    target.address += mapping.file_offset();
                }
            }

            /* Symbol lookup, if any */
            for symbol in mapping.symbols() {
                if ip >= symbol.start() && ip <= symbol.end() {
                    /* Get the actual symbol name */
                    let sym_name = match strings.from_id(symbol.name_id()) {
                        Ok(name) => { name },
                        Err(_) => { UNKNOWN },
                    };

                    // This is not functioning properly for native code, and removes the module name.
                    /*
                    /* Check for method segments */
                    let mut parts = sym_name.rsplitn(2, "::");

                    /*
                        * If we got 2, then treat up to the last "::"
                        * as the namespace and treat the last segment
                        * as the method.
                        */

                    if let Some(method_) = parts.next() {
                        if let Some(namespace_) = parts.next() {
                            /* Use namespace as resolvable name */
                            name = namespace_;

                            /* Use method name as the symbol name */
                            sym_name = method_;
                        }
                    }
                    */

                    target.method_id = self.strings.to_id(sym_name);
                    break;
                }
            }

            /*
             * TODO
             * Version and Symbol Signature strings
             * Need mappings to support these
             */
            resolvable.name_id = self.strings.to_id(name);
            target.resolvable_id = self.import_resolvable(resolvable);
        }
        else {
            /* Completely unknown sample */
            let mut resolvable = Resolvable::default();
            resolvable.name_id = self.strings.to_id(UNKNOWN);
            target.resolvable_id = self.import_resolvable(resolvable);
        }

        target
    }

    pub fn add_samples(
        &mut self,
        exporter: &ExportMachine,
        process: &ExportProcess,
        kind: u16,
        value_converter: Option<&dyn ExportGraphMetricValueConverter>) {
        if enabled!(Level::DEBUG) {
            let sample_count = process.samples().iter().filter(|s| s.kind() == kind).count();
            debug!("Adding samples to graph: process_pid={}, kind={}, sample_count={}", 
                process.pid(), kind, sample_count);
        }
        
        let mut callstack_id_to_node: HashMap<usize, usize> = HashMap::new();

        let default_converter = DefaultExportGraphMetricValueConverter::default();
        let converter = match value_converter {
            Some(converter) => { converter },
            None => { &default_converter },
        };

        for sample in process.samples() {
            if sample.kind() != kind {
                continue;
            }

            let callstack_id = sample.callstack_id();
            let value = converter.convert(exporter, sample.value());
            let time = sample.time();

            /* Import common frames, if not already */
            let id = match callstack_id_to_node.entry(callstack_id) {
                Occupied(entry) => {
                    /* Already imported */
                    let id = *entry.get();

                    /* Add value to node children */
                    self.charge(id, value);

                    id
                },
                Vacant(entry) => {
                    /* Need to import and merge */
                    let _ = exporter.callstacks().from_id(
                        callstack_id,
                        &mut self.frames);

                    let mut id = 0;

                    /* Import and merge each frame */
                    loop {
                        let ip = self.frames.pop();

                        if ip.is_none() {
                            break;
                        }

                        let ip = ip.unwrap();

                        let target = self.import_ip(
                            exporter,
                            process,
                            time,
                            ip);

                        id = self.merge(
                            id,
                            target,
                            value);
                    }

                    /* Save final merged id */
                    *entry.insert(id)
                }
            };

            /* Import top frame */
            let target = self.import_ip(
                exporter,
                process,
                time,
                sample.ip());

            /* Merge top frame */
            let id = self.merge(
                id,
                target,
                value);

            /* Top frame must add exclusive and total */
            let node = &mut self.nodes[id];
            node.exclusive += value;
            node.total += value;
        }
        
        info!("Samples added to graph: pid={}, node_count={}, resolvable_count={}", 
            process.pid(), self.nodes.len(), self.resolvables.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::exporting::formats::perf_view::PerfViewXmlFormat;

    #[test]
    fn it_works() {
        let callstacks = CallstackHelper::new();
        let settings = ExportSettings::new(callstacks);

        /* Ignore process FS to avoid permissions, etc */
        #[cfg(target_os = "linux")]
        let settings = settings.without_process_fs();

        let mut exporter = ExportMachine::new(settings);

        exporter.add_comm_exec(1, "test", 0).unwrap();

        let mut frames = Vec::new();

        for i in 0..16 {
            exporter.add_mmap_exec(
                0,
                1,
                i,
                1,
                0,
                0,
                0,
                0,
                &i.to_string()).unwrap();

            frames.push(i);
        }

        let cpu = exporter.sample_kind("cpu");

        /* Sample each frame, stepping down each time */
        for i in 0..16 {
            exporter.add_sample(
                0,
                MetricValue::Count(1),
                1,
                1,
                0,
                cpu,
                &frames[i..16]).unwrap();
        }

        let process = exporter.find_process(1).unwrap();

        /* Sanity check */
        assert_eq!(16, process.samples().len());

        let mut graph = ExportGraph::new();

        graph.add_samples(
            &exporter,
            &process,
            cpu,
            None);

        /* Should have 16 nodes + root */
        assert_eq!(17, graph.nodes().len());

        let nodes = graph.nodes();
        let mut node = &nodes[graph.root_node()];

        /* Root total should be 16 samples of 1 */
        assert_eq!(16, node.total);

        /* Validate step pattern */
        for i in 0..16 {
            /* Only should have a single child */
            assert_eq!(1, node.child_ids.len());
            node = &nodes[node.child_ids[0]];

            /* Node should include children total */
            assert_eq!(16 - i, node.total);

            /* Only 1 sample per-stack */
            assert_eq!(1, node.exclusive);
        }

        let resolvables = graph.resolvables();
        let strings = graph.strings();

        /* Validate unique resolvables (16 + unknown) */
        assert_eq!(17, resolvables.len());

        for i in 0..16 {
            /* Imported backwards, 15, 14, 13, etc. */
            let resolvable = &resolvables[16-i];
            let name = strings.from_id(resolvable.name_id).unwrap();

            /* Ensure they match */
            assert_eq!(i.to_string(), name);
            assert_eq!(0, resolvable.symbol_id);
            assert_eq!(0, resolvable.version_id);
        }

        graph.to_perf_view_xml("t.UnitTest.PerfView.xml").unwrap();
    }
}
