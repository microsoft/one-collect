// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::{HashSet, HashMap};
use std::collections::hash_map::Entry::{Occupied, Vacant};

use crate::intern::InternedStrings;
use crate::helpers::exporting::*;

#[derive(Default)]
pub struct ExportAttributeWalker {
    ids: Vec<usize>,
    seen: HashSet<usize>,
    attributes: Vec<ExportAttributePair>,
    filter: Option<Box<dyn Fn(&ExportAttributePair) -> bool>>,
}

impl ExportAttributeWalker {
    pub(crate) fn start(&mut self) {
        self.ids.clear();
        self.seen.clear();
        self.attributes.clear();
    }

    pub(crate) fn pop_id(&mut self) -> Option<usize> {
        self.ids.pop()
    }

    pub(crate) fn push_attributes(
        &mut self,
        attributes: &[ExportAttributePair]) {
        if let Some(filter) = &self.filter {
            for attribute in attributes {
                if filter(attribute) {
                    self.attributes.push(*attribute);
                }
            }
        } else {
            self.attributes.extend_from_slice(attributes);
        }
    }

    pub(crate) fn push_id(
        &mut self,
        attributes_id: usize) {
        if self.seen.insert(attributes_id) {
            self.ids.push(attributes_id);
        }
    }

    pub fn with_filter(
        self,
        filter: impl Fn(&ExportAttributePair) -> bool + 'static) -> Self {
        let mut clone = self;

        clone.filter = Some(Box::new(filter));

        clone
    }

    pub fn attributes(&self) -> &[ExportAttributePair] {
        &self.attributes
    }
}

#[derive(Default, PartialEq)]
pub struct ExportAttributes {
    attributes: Vec<ExportAttributePair>,
    associated_ids: Vec<usize>,
}

impl ExportAttributes {
    pub fn push_association(
        &mut self,
        attributes_id: usize) {
        self.associated_ids.push(attributes_id);
    }

    pub fn push(
        &mut self,
        pair: ExportAttributePair) {
        self.attributes.push(pair);
    }

    pub fn shrink(&mut self) {
        self.attributes.shrink_to_fit();
        self.associated_ids.shrink_to_fit();
    }

    pub fn associated_ids(&self) -> &[usize] { &self.associated_ids }

    pub fn attributes(&self) -> &[ExportAttributePair] { &self.attributes }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ExportAttributeValue {
    Label(usize),
    Value(u64),
    Record(usize),
}

#[derive(Clone, Copy, PartialEq)]
pub struct ExportAttributePair {
    name: usize,
    value: ExportAttributeValue,
}

impl ExportAttributePair {
    pub fn new(
        name: usize,
        value: ExportAttributeValue) -> Self {
        Self {
            name,
            value,
        }
    }

    pub(crate) fn new_record(
        name: &str,
        record_id: usize,
        strings: &mut InternedStrings) -> Self {
        Self {
            name: strings.to_id(name),
            value: ExportAttributeValue::Record(record_id),
        }
    }

    pub(crate) fn new_label(
        name: &str,
        label: &str,
        strings: &mut InternedStrings) -> Self {
        Self {
            name: strings.to_id(name),
            value: ExportAttributeValue::Label(strings.to_id(label)),
        }
    }

    pub(crate) fn new_value(
        name: &str,
        value: u64,
        strings: &mut InternedStrings) -> Self {
        Self {
            name: strings.to_id(name),
            value: ExportAttributeValue::Value(value),
        }
    }

    pub fn name(&self) -> usize { self.name }

    pub fn name_str<'a>(
        &self,
        strings: &'a InternedStrings) -> Option<&'a str> {
        match strings.from_id(self.name) {
            Ok(name) => { Some(name) },
            Err(_) => { None },
        }
    }

    pub fn label(&self) -> Option<usize> {
        match self.value {
            ExportAttributeValue::Label(id) => { Some(id) },
            _ => { None },
        }
    }

    pub fn label_str<'a>(
        &self,
        strings: &'a InternedStrings) -> Option<&'a str> {
        match self.label() {
            Some(id) => {
                match strings.from_id(id) {
                    Ok(label) => { Some(label) },
                    _ => { None },
                }
            },
            _ => { None },
        }
    }

    pub fn value(&self) -> Option<u64> {
        match self.value {
            ExportAttributeValue::Value(value) => { Some(value) },
            _ => { None },
        }
    }

    pub fn record_id(&self) -> Option<usize> {
        match self.value {
            ExportAttributeValue::Record(id) => { Some(id) },
            _ => { None },
        }
    }

    pub fn attribute_value(&self) -> ExportAttributeValue { self.value }
}

#[derive(Default)]
pub struct VersionOpCodeAttributeSource {
    attributes_cache: HashMap<u32, usize>,
    version_str_id: usize,
    op_code_str_id: usize,
}

impl ExportAttributeSource for VersionOpCodeAttributeSource {
    fn initialize(
        &mut self,
        machine: &mut ExportMachine) {
        self.version_str_id = machine.intern("Version");
        self.op_code_str_id = machine.intern("OpCode");
    }

    fn add_attributes(
        &mut self,
        trace: &mut ExportTraceContext,
        attributes: &mut ExportAttributes) -> anyhow::Result<()> {
        let version = trace.version()?.unwrap_or(0);
        let op_code = trace.op_code()?.unwrap_or(0);
        let lookup_id = (version as u32) << 16 | op_code as u32;

        /* Lookup attributes by version + op_code pair */
        if lookup_id != 0 {
            let attribute_id = match self.attributes_cache.entry(lookup_id) {
                Vacant(entry) => {
                    /* New pair, get new attribute ID for this */
                    let mut attributes = ExportAttributes::default();

                    attributes.push(
                        ExportAttributePair::new(
                            self.version_str_id,
                            ExportAttributeValue::Value(version as u64)));

                    attributes.push(
                        ExportAttributePair::new(
                            self.op_code_str_id,
                            ExportAttributeValue::Value(op_code as u64)));

                    let id = trace.push_unique_attributes(attributes);

                    entry.insert(id);

                    id
                },
                Occupied(entry) => {
                    /* Existing pair, use existing ID */
                    *entry.get()
                },
            };

            attributes.push_association(attribute_id);
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct TraceContextAttributeSource {
    trace_str_id: usize,
    span_str_id: usize,
}

impl ExportAttributeSource for TraceContextAttributeSource {
    fn initialize(
        &mut self,
        machine: &mut ExportMachine) {
        self.trace_str_id = machine.intern("TraceId");
        self.span_str_id = machine.intern("SpanId");
    }

    fn add_attributes(
        &mut self,
        trace: &mut ExportTraceContext,
        attributes: &mut ExportAttributes) -> anyhow::Result<()> {
        if let Some(trace_id) = trace.trace_id()? {
            let record_id = trace.record_data(0, &trace_id);

            attributes.push(
                ExportAttributePair::new(
                    self.trace_str_id,
                    ExportAttributeValue::Record(record_id)));
        }

        if let Some(span_id) = trace.span_id()? {
            let record_id = trace.record_data(0, &span_id);

            attributes.push(
                ExportAttributePair::new(
                    self.span_str_id,
                    ExportAttributeValue::Record(record_id)));
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct ActivityIdAttributeSource {
    activity_str_id: usize,
    related_activity_str_id: usize,
}

impl ExportAttributeSource for ActivityIdAttributeSource {
    fn initialize(
        &mut self,
        machine: &mut ExportMachine) {
        self.activity_str_id = machine.intern("ActivityId");
        self.related_activity_str_id = machine.intern("RelatedActivityId");
    }

    fn add_attributes(
        &mut self,
        trace: &mut ExportTraceContext,
        attributes: &mut ExportAttributes) -> anyhow::Result<()> {
        if let Some(activity_id) = trace.activity_id()? {
            let record_id = trace.record_data(0, &activity_id);

            attributes.push(
                ExportAttributePair::new(
                    self.activity_str_id,
                    ExportAttributeValue::Record(record_id)));
        }

        if let Some(related_activity_id) = trace.related_activity_id()? {
            let record_id = trace.record_data(0, &related_activity_id);

            attributes.push(
                ExportAttributePair::new(
                    self.related_activity_str_id,
                    ExportAttributeValue::Record(record_id)));
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct CgroupAttributeSource {
    attributes_cache: HashMap<u64, usize>,
    cgroup_str_id: usize,
}

impl ExportAttributeSource for CgroupAttributeSource {
    fn initialize(
        &mut self,
        machine: &mut ExportMachine) {
        self.cgroup_str_id = machine.intern("CGroup");
    }

    fn add_attributes(
        &mut self,
        trace: &mut ExportTraceContext,
        attributes: &mut ExportAttributes) -> anyhow::Result<()> {
        let cgroup_id = trace.cgroup()?.unwrap_or(0);

        if cgroup_id != 0 {
            let attribute_id = match self.attributes_cache.entry(cgroup_id) {
                Vacant(entry) => {
                    let mut attributes = ExportAttributes::default();

                    attributes.push(
                        ExportAttributePair::new(
                            self.cgroup_str_id,
                            ExportAttributeValue::Value(cgroup_id)));

                    let id = trace.push_unique_attributes(attributes);

                    entry.insert(id);

                    id
                },
                Occupied(entry) => {
                    *entry.get()
                },
            };

            attributes.push_association(attribute_id);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_walker() {
        let mut walker = ExportAttributeWalker::default();

        /* Push/Pop should work */
        walker.start();
        walker.push_id(1);
        walker.push_id(2);
        walker.push_id(3);

        assert_eq!(3, walker.pop_id().unwrap());
        assert_eq!(2, walker.pop_id().unwrap());
        assert_eq!(1, walker.pop_id().unwrap());
        assert!(walker.pop_id().is_none());

        /* Prevent cycles */
        walker.start();
        walker.push_id(0);
        walker.push_id(0);
        walker.push_id(0);

        assert!(walker.pop_id().is_some());
        assert!(walker.pop_id().is_none());

        /* Ensure attribute retrieval */
        let mut attributes = ExportAttributes::default();
        attributes.push(ExportAttributePair {
            name: 0,
            value: ExportAttributeValue::Value(0),
        });

        walker.push_attributes(attributes.attributes());
        assert_eq!(1, walker.attributes().len());

        /* Start should reset everything */
        walker.push_id(0);
        walker.push_id(1);
        walker.start();

        assert!(walker.pop_id().is_none());
        assert!(walker.attributes().is_empty());

        /* Ensure filtering */
        let mut walker = ExportAttributeWalker::default()
            .with_filter(|a| { a.name() < 3 });

        let mut attributes = ExportAttributes::default();
        attributes.push(ExportAttributePair {
            name: 0,
            value: ExportAttributeValue::Value(0),
        });

        attributes.push(ExportAttributePair {
            name: 1,
            value: ExportAttributeValue::Value(0),
        });

        attributes.push(ExportAttributePair {
            name: 2,
            value: ExportAttributeValue::Value(0),
        });

        /* Should get skipped */
        attributes.push(ExportAttributePair {
            name: 3,
            value: ExportAttributeValue::Value(0),
        });

        walker.push_attributes(attributes.attributes());
        assert_eq!(3, walker.attributes().len());
    }
}
