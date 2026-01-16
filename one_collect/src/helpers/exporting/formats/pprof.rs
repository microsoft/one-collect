// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::io::Write;

use crate::helpers::exporting::graph::{
    ExportGraph,
    Node,
    Resolvable
};

use crate::intern::InternedStrings;

use protobuf::CodedOutputStream;
use protobuf::rt::{self, *};

use flate2::write::GzEncoder;
use flate2::Compression;

use tracing::{debug, info};

fn write_value_type(
    field_number: u32,
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    type_id: usize,
    unit_id: usize) -> anyhow::Result<()> {
    let mut stream = CodedOutputStream::new(buffer);

    stream.write_int64(1, type_id as i64)?;
    stream.write_int64(2, unit_id as i64)?;
    stream.flush()?;
    drop(stream);

    proto_append(field_number, buffer, output)
}

fn write_sample_type(
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    type_id: usize,
    unit_id: usize) -> anyhow::Result<()> {
    write_value_type(
        1,
        buffer,
        output,
        type_id,
        unit_id)
}

fn write_sample(
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    location_ids: &Vec<u64>,
    value: u64) -> anyhow::Result<()> {
    let mut stream = CodedOutputStream::new(buffer);

    stream.write_repeated_packed_uint64(1, &location_ids[..])?;
    stream.write_int64(2, value as i64)?;
    stream.flush()?;
    drop(stream);

    proto_append(2, buffer, output)
}

fn write_samples(
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    nodes: &[Node],
    root: usize) -> anyhow::Result<()> {
    let mut location_ids: Vec<u64> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();

    stack.push(root);

    while let Some(id) = stack.pop() {
        let node = &nodes[id];

        if node.exclusive() > 0 {
            /* Leaf */
            let mut curr_node = node;
            let mut node_id = id;

            location_ids.clear();

            /* Push in nodes from leaf down to root */
            while node_id != root {
                location_ids.push(node_id as u64);
                node_id = curr_node.parent();
                curr_node = &nodes[node_id];
            }

            /* Add the sample with the exclusive value */
            write_sample(
                buffer,
                output,
                &location_ids,
                node.exclusive())?;
        }

        /* Push children */
        for child_id in node.children() {
            stack.push(*child_id);
        }
    }

    Ok(())
}

fn write_mapping(
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    id: usize,
    mem_start: u64,
    mem_end: u64,
    file_offset: u64,
    file_id: usize,
    build_id: usize) -> anyhow::Result<()> {
    let mut stream = CodedOutputStream::new(buffer);

    stream.write_uint64(1, id as u64)?;
    stream.write_uint64(2, mem_start)?;
    stream.write_uint64(3, mem_end)?;
    stream.write_uint64(4, file_offset)?;
    stream.write_uint64(5, file_id as u64)?;

    if build_id != 0 {
        stream.write_uint64(6, build_id as u64)?;
    }

    /* Functions */
    stream.write_bool(7, true)?;

    /* Filenames */
    if file_id != 0 {
        stream.write_bool(8, true)?;
    }

    /* Line Numbers */
    stream.write_bool(9, true)?;

    stream.flush()?;
    drop(stream);

    proto_append(3, buffer, output)
}

fn write_mappings(
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    resolvables: &[Resolvable]) -> anyhow::Result<()> {
    for (id, resolvable) in resolvables.iter().enumerate() {
        write_mapping(
            buffer,
            output,
            id + 1, /* Mappings must be non-zero */
            0,
            0xFFFF800000000000,
            0,
            resolvable.name(),
            resolvable.symbol_identity())?;
    }

    Ok(())
}

fn write_location(
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    id: usize,
    mapping_id: usize,
    address: u64,
    function_id: Option<usize>) -> anyhow::Result<()> {
    let mut stream = CodedOutputStream::new(buffer);

    stream.write_uint64(1, id as u64)?;
    stream.write_uint64(2, mapping_id as u64)?;
    stream.write_uint64(3, address)?;

    if let Some(function_id) = function_id {
        let len = rt::uint64_size(1, function_id as u64);
        stream.write_tag(4, WireType::LengthDelimited)?;
        stream.write_raw_varint32(len as u32)?;
        stream.write_uint64(1, function_id as u64)?;
    }

    stream.flush()?;
    drop(stream);

    proto_append(4, buffer, output)
}

fn write_locations(
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    nodes: &[Node],
    root: usize) -> anyhow::Result<()> {
    let mut stack: Vec<usize> = Vec::new();

    stack.push(root);

    while let Some(id) = stack.pop() {
        let node = &nodes[id];

        if id != root {
            let target = node.target();

            /* Write out a method/function or not */
            let function_id = match target.has_method() {
                true => { Some(id) },
                false => { None },
            };

            /* Location */
            write_location(
                buffer,
                output,
                id,
                target.resolvable() + 1, /* Mappings must be non-zero */
                target.address(),
                function_id)?;
        }

        /* Push children */
        for child_id in node.children() {
            stack.push(*child_id);
        }
    }

    Ok(())
}

fn write_function(
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    id: usize,
    name_id: usize) -> anyhow::Result<()> {
    let mut stream = CodedOutputStream::new(buffer);

    stream.write_uint64(1, id as u64)?;
    stream.write_uint64(2, name_id as u64)?;
    stream.flush()?;
    drop(stream);

    proto_append(5, buffer, output)
}

fn write_functions(
    buffer: &mut Vec<u8>,
    output: &mut CodedOutputStream,
    nodes: &[Node],
    root: usize) -> anyhow::Result<()> {
    let mut stack: Vec<usize> = Vec::new();

    stack.push(root);

    while let Some(id) = stack.pop() {
        let node = &nodes[id];

        if id != root {
            let target = node.target();

            /* Write out a method/function or not */
            if target.has_method() {
                write_function(
                    buffer,
                    output,
                    id,
                    target.method())?;
            }
        }

        /* Push children */
        for child_id in node.children() {
            stack.push(*child_id);
        }
    }

    Ok(())
}

fn write_strings(
    output: &mut CodedOutputStream,
    strings: &InternedStrings) -> anyhow::Result<()> {
    for i in 0..usize::MAX {
        match strings.from_id(i) {
            Ok(value) => { output.write_string(6, value)?; },
            Err(_) => { break; },
        }
    }

    Ok(())
}

fn proto_append(
    field_number: u32,
    input: &mut Vec<u8>,
    output: &mut CodedOutputStream) -> anyhow::Result<()> {
    output.write_bytes(field_number, input)?;
    input.clear();
    Ok(())
}

pub trait PprofFormat {
    fn to_pprof(
        &self,
        type_id: usize,
        unit_id: usize,
        writer: &mut impl Write) -> anyhow::Result<()>;

    fn to_pprof_file(
        &self,
        type_id: usize,
        unit_id: usize,
        path: &str) -> anyhow::Result<()> {
        info!("Starting pprof export: path={}", path);
        
        let file = File::create(path)?;
        let mut gzip = GzEncoder::new(file, Compression::default());

        self.to_pprof(
            type_id,
            unit_id,
            &mut gzip)?;

        gzip.finish()?;
        
        info!("Pprof export completed successfully: path={}", path);

        Ok(())
    }
}

impl PprofFormat for ExportGraph {
    fn to_pprof(
        &self,
        type_id: usize,
        unit_id: usize,
        writer: &mut impl Write) -> anyhow::Result<()> {
        debug!("Writing pprof data: type_id={}, unit_id={}", type_id, unit_id);
        
        let resolvables = self.resolvables();
        let strings = self.strings();
        let nodes = self.nodes();
        let root = self.root_node();

        let mut buffer = Vec::with_capacity(64*1024);
        let mut output = CodedOutputStream::new(writer);

        /* Sample Types */
        write_sample_type(
            &mut buffer,
            &mut output,
            type_id,
            unit_id)?;

        /* Samples */
        write_samples(
            &mut buffer,
            &mut output,
            nodes,
            root)?;

        /* Mappings */
        write_mappings(
            &mut buffer,
            &mut output,
            resolvables)?;

        /* Locations */
        write_locations(
            &mut buffer,
            &mut output,
            nodes,
            root)?;

        /* Functions */
        write_functions(
            &mut buffer,
            &mut output,
            nodes,
            root)?;

        /* Strings */
        write_strings(
            &mut output,
            strings)?;

        /* Done */
        output.flush()?;
        drop(output);
        
        debug!("Pprof data written successfully");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::exporting::*;

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

            /* Add local symbol */
            let mappings = exporter.process_mut(1).mappings_mut();
            let len = mappings.len();
            let last = &mut mappings[len-1];

            last.add_symbol(
                ExportSymbol::new(
                    last.filename_id(),
                    i,
                    i+1));

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
        let type_id = graph.strings_mut().to_id("sample");
        let unit_id = graph.strings_mut().to_id("count");

        graph.add_samples(
            &exporter,
            &process,
            cpu,
            None);

        graph.to_pprof_file(
            type_id,
            unit_id,
            "UnitTest.pprof").unwrap();
    }
}
