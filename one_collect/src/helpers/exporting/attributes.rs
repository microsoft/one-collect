// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::intern::InternedStrings;

#[derive(Default, PartialEq)]
pub struct ExportAttributes {
    attributes: Vec<ExportAttributePair>,
}

impl ExportAttributes {
    pub fn push(
        &mut self,
        pair: ExportAttributePair) {
        self.attributes.push(pair);
    }
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
