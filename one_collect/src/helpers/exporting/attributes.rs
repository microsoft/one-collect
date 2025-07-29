// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::HashSet;

use crate::intern::InternedStrings;

#[derive(Default)]
pub struct ExportAttributeWalker {
    ids: Vec<usize>,
    seen: HashSet<usize>,
    attributes: Vec<ExportAttributePair>,
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
        self.attributes.extend_from_slice(attributes);
    }

    pub(crate) fn push_id(
        &mut self,
        attributes_id: usize) {
        if self.seen.insert(attributes_id) {
            self.ids.push(attributes_id);
        }
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
}

#[derive(Clone, Copy, PartialEq)]
pub struct ExportAttributePair {
    name: usize,
    value: ExportAttributeValue,
}

impl ExportAttributePair {
    pub fn new_label(
        name: &str,
        label: &str,
        strings: &mut InternedStrings) -> Self {
        Self {
            name: strings.to_id(name),
            value: ExportAttributeValue::Label(strings.to_id(label)),
        }
    }

    pub fn new_value(
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
    }
}
