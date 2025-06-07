// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::event::{Event, EventFormat};

pub struct ExportRecordData<'a> {
    record_type_id: u16,
    record_type: &'a ExportRecordType,
    record_data: &'a [u8],
}

impl<'a> ExportRecordData<'a> {
    pub fn new(
        record_type_id: u16,
        record_type: &'a ExportRecordType,
        record_data: &'a [u8]) -> Self {
        Self {
            record_type_id,
            record_type,
            record_data,
        }
    }

    pub fn record_type_id(&self) -> u16 { self.record_type_id }

    pub fn record_type(&self) -> &'a ExportRecordType { self.record_type }

    pub fn record_data(&self) -> &'a [u8] { self.record_data }
}

#[derive(PartialEq, Default)]
pub struct ExportRecordType {
    kind: u16,
    id: usize,
    name: String,
    format: EventFormat,
}

impl ExportRecordType {
    pub fn new(
        kind: u16,
        id: usize,
        name: String,
        format: EventFormat) -> Self {
        Self {
            kind,
            id,
            name,
            format,
        }
    }

    pub fn from_event(
        kind: u16,
        event: &Event) -> Self {
        Self {
            kind,
            id: event.id(),
            name: event.name().to_owned(),
            format: event.format().to_owned(),
        }
    }

    pub fn kind(&self) -> u16 { self.kind }

    pub fn id(&self) -> usize { self.id }

    pub fn name(&self) -> &str { &self.name }

    pub fn format(&self) -> &EventFormat { &self.format }
}

#[derive(Default)]
pub(crate) struct ExportRecord {
    record_type: u16,
    offset: usize,
    length: u32,
}

impl ExportRecord {
    pub fn new(
        record_type: u16,
        offset: usize,
        length: u32) -> Self {
        Self {
            record_type,
            offset,
            length,
        }
    }

    pub fn record_type(&self) -> u16 { self.record_type }

    pub fn start(&self) -> usize { self.offset }

    pub fn end(&self) -> usize { self.offset + self.length as usize }
}
