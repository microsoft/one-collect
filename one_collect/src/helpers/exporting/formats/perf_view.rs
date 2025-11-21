// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::io::{Write, BufWriter};
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Vacant, Occupied};
use crate::helpers::exporting::graph::{Target, ExportGraph};

use tracing::info;

pub trait PerfViewXmlFormat {
    fn to_perf_view_xml(
        &self,
        path: &str) -> anyhow::Result<()>;
}

impl PerfViewXmlFormat for ExportGraph {
    fn to_perf_view_xml(
        &self,
        path: &str) -> anyhow::Result<()> {
        info!("Starting PerfView XML export: path={}", path);
        
        let resolvables = self.resolvables();
        let strings = self.strings();
        let nodes = self.nodes();
        let root = self.root_node();

        let file = File::create(path)?;
        let mut stack: Vec<usize> = Vec::new();
        let mut frames: HashMap<Target, usize> = HashMap::new();

        stack.push(root);

        while let Some(id) = stack.pop() {
            let node = &nodes[id];
            let count = frames.len();

            /* Push children */
            for child_id in node.children() {
                stack.push(*child_id);
            }

            if id == root {
                continue;
            }

            match frames.entry(node.target()) {
                Occupied(entry) => { entry.get() },
                Vacant(entry) => { entry.insert(count) }
            };
        }

        let mut writer = BufWriter::new(file);

        write!(writer, "<StackWindow>\n")?;
        write!(writer, "<StackSource>\n")?;
        write!(writer, "<Frames Count=\"{}\">\n", frames.len())?;

        let mut name = String::new();

        for (frame, id) in &frames {
            name.clear();

            if frame.has_resolvable() {
                let resolvable = &resolvables[frame.resolvable()];
                let resolvable = strings.from_id(resolvable.name())?;
                name.push_str(resolvable);
            } else {
                name.push_str("Unknown");
            }

            name.push('!');

            if frame.has_method() {
                let method = strings.from_id(frame.method())?;
                name.push_str(method);
            } else {
                name.push_str(&format!("0x{:x}", frame.address()));
            }

            if name.contains("<") || name.contains(">") || name.contains("&") {
                name = name
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;");
            }

            write!(writer, "<Frame ID=\"{}\">{}</Frame>\n", id, name)?;
        }

        write!(writer, "</Frames>\n")?;
        write!(writer, "<Stacks Count=\"{}\">\n", nodes.len() - 1)?;

        stack.push(root);

        let mut sample_count: u64 = 0;

        while let Some(id) = stack.pop() {
            let node = &nodes[id];

            if node.exclusive() > 0 {
                sample_count += 1;
            }

            /* Push children */
            for child_id in node.children() {
                stack.push(*child_id);
            }

            if id == root {
                continue;
            }

            let mut caller_id = node.parent() as isize;

            if node.parent() == root {
                caller_id = -1;
            }

            let frame_id = match frames.get(&node.target()) {
                Some(id) => { *id as isize },
                None => { -1 },
            };

            write!(
                writer,
                "<Stack ID=\"{}\" CallerID=\"{}\" FrameID=\"{}\"/>\n",
                id,
                caller_id,
                frame_id)?;
        }

        write!(writer, "</Stacks>\n")?;
        write!(writer, "<Samples Count=\"{}\">\n", sample_count)?;

        stack.push(root);

        while let Some(id) = stack.pop() {
            let node = &nodes[id];

            /* Push children */
            for child_id in node.children() {
                stack.push(*child_id);
            }

            if id == root {
                continue;
            }

            if node.exclusive() > 0 {
                write!(
                    writer,
                    "<Sample ID=\"{}\" Count=\"1\" StackID=\"{}\" Metric=\"{}\"/>\n",
                    id,
                    id,
                    node.exclusive())?;
            }
        }

        write!(writer, "</Samples>\n")?;
        write!(writer, "</StackSource>\n")?;
        write!(writer, "</StackWindow>\n")?;

        info!("PerfView XML export completed successfully: path={}, frames={}, samples={}", 
            path, frames.len(), sample_count);

        Ok(())
    }
}
