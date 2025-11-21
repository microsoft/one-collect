// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write, BufWriter};

use chrono::{DateTime, Datelike, Timelike, Utc};

use crate::Guid;
use crate::event::{EventField, LocationType};
use crate::helpers::exporting::*;
use crate::helpers::exporting::graph::*;
use crate::helpers::exporting::attributes::*;

use tracing::{debug, error, info};

pub trait NetTraceFormat {
    fn to_net_trace(
        &mut self,
        predicate: impl Fn(&ExportProcess) -> bool,
        path: &str) -> anyhow::Result<()>;
}

#[derive(Eq, Hash, PartialEq)]
struct SavedCallstackKey {
    ip: u64,
    sample_id: u32,
    write_id: u32,
}

#[derive(Eq, Hash, PartialEq)]
struct SavedPidTidKey {
    pid: u32,
    tid: u32,
}

#[derive(Eq, Hash, PartialEq)]
struct SavedLabelKey {
    attributes_id: usize,
    write_id: u32,
}

struct NetTraceField<'a> {
    type_id: u8,
    element_type_id: Option<u8>,
    name: &'a str,
}

const TYPE_ID_BYTE: u8 = 6;
const TYPE_ID_INT16: u8 = 7;
const TYPE_ID_UINT16: u8 = 8;
const TYPE_ID_INT32: u8 = 9;
const TYPE_ID_UINT32: u8 = 10;
const TYPE_ID_INT64: u8 = 11;
const TYPE_ID_UINT64: u8 = 12;
const TYPE_ID_SINGLE: u8 = 13;
const TYPE_ID_DOUBLE: u8 = 14;
const TYPE_ID_NULL_UTF16_STRING: u8 = 18;
const TYPE_ID_ARRAY: u8 = 19;
const TYPE_ID_VARUINT: u8 = 21;
const TYPE_ID_UTF8: u8 = 23;

const VALUE_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_VARUINT,
    element_type_id: None,
    name: "Value",
};

const ID_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_VARUINT,
    element_type_id: None,
    name: "Id",
};

const NAME_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UTF8,
    element_type_id: None,
    name: "Name",
};

const NAMESPACE_NAME_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UTF8,
    element_type_id: None,
    name: "NamespaceName",
};

const FILE_NAME_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UTF8,
    element_type_id: None,
    name: "FileName",
};

const SYMBOL_META_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UTF8,
    element_type_id: None,
    name: "SymbolMetadata",
};

const VERSION_META_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UTF8,
    element_type_id: None,
    name: "VersionMetadata",
};

const NAMESPACE_ID_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_VARUINT,
    element_type_id: None,
    name: "NamespaceId",
};

const MAPPING_ID_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_VARUINT,
    element_type_id: None,
    name: "MappingId",
};

const META_ID_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_VARUINT,
    element_type_id: None,
    name: "MetadataId",
};

const START_ADDRESS_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_VARUINT,
    element_type_id: None,
    name: "StartAddress",
};

const END_ADDRESS_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_VARUINT,
    element_type_id: None,
    name: "EndAddress",
};

const FILE_OFFSET_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_VARUINT,
    element_type_id: None,
    name: "FileOffset",
};

const STACK_EVENT_FIELDS: [NetTraceField; 1] = [
    VALUE_FIELD];

const PROCESS_CREATE_FIELDS: [NetTraceField; 3] = [
    NAMESPACE_ID_FIELD,
    NAME_FIELD,
    NAMESPACE_NAME_FIELD,
];

const PROCESS_EXIT_FIELDS: [NetTraceField; 0] = [];

const PROCESS_MAPPING_FIELDS: [NetTraceField; 6] = [
    ID_FIELD,
    START_ADDRESS_FIELD,
    END_ADDRESS_FIELD,
    FILE_OFFSET_FIELD,
    FILE_NAME_FIELD,
    META_ID_FIELD,
];

const PROCESS_MAPPING_META_FIELDS: [NetTraceField; 3] = [
    ID_FIELD,
    SYMBOL_META_FIELD,
    VERSION_META_FIELD,
];

const PROCESS_SYMBOL_FIELDS: [NetTraceField; 5] = [
    ID_FIELD,
    MAPPING_ID_FIELD,
    START_ADDRESS_FIELD,
    END_ADDRESS_FIELD,
    NAME_FIELD,
];

trait EventPayloadWriter {
    fn write_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()>;

    fn write_u8(
        &mut self,
        value: u8) -> anyhow::Result<()> {
        let bytes: [u8; 1] = [value];

        self.write_bytes(&bytes)
    }

    fn write_u16(
        &mut self,
        value: u16) -> anyhow::Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_u32(
        &mut self,
        value: u32) -> anyhow::Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_u64(
        &mut self,
        value: u64) -> anyhow::Result<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_short_utf8(
        &mut self,
        value: &str) -> anyhow::Result<()> {
        let bytes = value.as_bytes();
        self.write_u16(value.len() as u16)?;
        self.write_bytes(bytes)
    }

    fn write_utf8(
        &mut self,
        value: &str) -> anyhow::Result<()> {
        let bytes = value.as_bytes();
        self.write_varint(value.len() as u64)?;
        self.write_bytes(bytes)
    }

    fn size_utf8(
        &self,
        value: &str) -> usize {
        value.as_bytes().len() + self.size_varint(value.len() as u64)
    }

    fn size_varint(
        &self,
        mut value: u64) -> usize {
        let mut size = 1usize;

        while value >= 128 {
            size += 1;
            value >>= 7;
        }

        size
    }

    fn write_varint(
        &mut self,
        mut value: u64) -> anyhow::Result<()> {
        while value >= 128 {
            self.write_u8((value & 127) as u8 | 128)?;
            value >>= 7;
        }

        self.write_u8((value & 127) as u8)
    }
}

impl EventPayloadWriter for BufWriter<File> {
    fn write_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        Ok(self.write_all(bytes)?)
    }
}

impl EventPayloadWriter for Vec<u8> {
    fn write_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        Ok(self.write_all(bytes)?)
    }
}

struct NetTraceWriter {
    output: BufWriter<File>,
    event_block: Vec<u8>,
    buffer: Vec<u8>,
    record_id_offset: u32,
    existing_event_id: u32,
    create_event_id: u32,
    exit_event_id: u32,
    mapping_event_id: u32,
    symbol_event_id: u32,
    mapping_meta_event_id: u32,
    original_meta_event_ids: HashSet<u32>,
    last_time: u64,
    sync_time: u64,
    flush_time: u64,
    str_buffer: String,
    sym_id: u32,
    saved_labels: HashMap<SavedLabelKey, u32>,
    saved_callstacks: HashMap<SavedCallstackKey, u32>,
    saved_pid_tids: HashMap<SavedPidTidKey, u32>,
    saved_meta_ids: HashMap<ExportDevNode, u32>,
}

impl NetTraceWriter {
    fn new(path: &str) -> anyhow::Result<Self> {
        let mut trace = Self {
            output: BufWriter::new(File::create(path)?),
            event_block: Vec::new(),
            buffer: Vec::new(),
            record_id_offset: 0,
            existing_event_id: 0,
            create_event_id: 0,
            exit_event_id: 0,
            mapping_event_id: 0,
            symbol_event_id: 0,
            mapping_meta_event_id: 0,
            original_meta_event_ids: HashSet::new(),
            last_time: 0,
            sync_time: 0,
            flush_time: 0,
            str_buffer: String::new(),
            sym_id: 0,
            saved_labels: HashMap::new(),
            saved_callstacks: HashMap::new(),
            saved_pid_tids: HashMap::new(),
            saved_meta_ids: HashMap::new(),
        };

        trace.init()?;
        info!("NetTrace writer created successfully: path={}", path);

        Ok(trace)
    }

    fn get_pos(&mut self) -> anyhow::Result<u64> {
        self.output.flush()?;
        Ok(self.output.stream_position()?)
    }

    fn reserve_u32(&mut self) -> anyhow::Result<u64> {
        self.output.write_u32(0)?;
        self.get_pos()
    }

    fn update_u32(
        &mut self,
        value: u32,
        reserved_at: u64) -> anyhow::Result<()> {
        self.output.seek(SeekFrom::Start(reserved_at - 4))?;
        self.output.write_u32(value)?;
        self.output.flush()?;
        self.output.seek(SeekFrom::End(0))?;
        Ok(())
    }

    fn write_start_block(&mut self) -> anyhow::Result<u64> {
        self.reserve_u32()
    }

    fn write_end_block(
        &mut self,
        block_start: u64,
        kind: u8) -> anyhow::Result<()> {
        let total_size = self.get_pos()? - block_start;
        let header = total_size as u32 | (kind as u32) << 24;
        self.update_u32(header, block_start)
    }

    fn write_event_metadata(
        &mut self,
        meta_id: u32,
        provider: &str,
        event_id: u32,
        event_name: &str,
        fields: &[NetTraceField]) -> anyhow::Result<()> {
        let (provider, guid) = match provider.split_once(':') {
            Some((provider, guid)) => {
                let guid = guid
                    .replace("{", "")
                    .replace("}", "")
                    .replace("-", "");

                let guid = match u128::from_str_radix(guid.trim(), 16) {
                    Ok(guid) => { Some(Guid::from_u128(guid)) },
                    Err(_) => { None },
                };

                (provider, guid)
            },
            None => { (provider, None) },
        };

        /* Write payload */
        self.buffer.clear();
        self.buffer.write_varint(meta_id as u64)?;
        self.buffer.write_utf8(provider)?;
        self.buffer.write_varint(event_id as u64)?;
        self.buffer.write_utf8(event_name)?;
        self.buffer.write_u16(fields.len() as u16)?;

        for field in fields {
            let mut size = self.buffer.size_utf8(field.name) + 1;

            if field.type_id == TYPE_ID_ARRAY {
                size += 1;
            }

            self.buffer.write_u16(size as u16)?;
            self.buffer.write_utf8(field.name)?;
            self.buffer.write_u8(field.type_id)?;

            if field.type_id == TYPE_ID_ARRAY {
                self.buffer.write_u8(field.element_type_id.unwrap_or(0))?;
            }
        }

        /* OptionalMetadata */
        if let Some(guid) = guid {
            self.buffer.write_u16(17)?; /* GUID + kind */
            self.buffer.write_u8(7)?; /* Provider Guid */
            self.buffer.write_u32(guid.data1)?;
            self.buffer.write_u16(guid.data2)?;
            self.buffer.write_u16(guid.data3)?;
            self.buffer.write_u8(guid.data4[0])?;
            self.buffer.write_u8(guid.data4[1])?;
            self.buffer.write_u8(guid.data4[2])?;
            self.buffer.write_u8(guid.data4[3])?;
            self.buffer.write_u8(guid.data4[4])?;
            self.buffer.write_u8(guid.data4[5])?;
            self.buffer.write_u8(guid.data4[6])?;
            self.buffer.write_u8(guid.data4[7])?;
        } else {
            self.buffer.write_u16(0)?;
        }

        let payload = self.buffer.as_slice();

        self.output.write_u16(payload.len() as u16)?; /* Size */
        self.output.write_bytes(payload)
    }

    fn write_eventblock_start(
        &mut self,
        min_time: u64,
        max_time: u64) -> anyhow::Result<u64> {
        let block_start = self.write_start_block()?;

        /* Header */
        self.output.write_u16(20)?; /* HeaderSize */
        self.output.write_u16(1)?; /* Flags: Compressed */
        self.output.write_u64(min_time)?; /* Min timestamp */
        self.output.write_u64(max_time)?; /* Max timestamp */

        Ok(block_start)
    }

    fn write_event_timestamp(
        &mut self,
        mut time: u64) -> anyhow::Result<()> {
        /* Never allow before sync time */
        if time < self.sync_time {
            time = self.sync_time;
        }

        /* Don't allow overflow (should never happen, but if it does...) */
        if time < self.last_time {
            time = self.last_time;
        }

        /* We store time for events always as a delta from last */
        let delta = time - self.last_time;

        self.last_time = time;

        self.event_block.write_varint(delta)
    }

    fn write_event_blob_from_buffer(
        &mut self,
        machine: &ExportMachine,
        meta_id: u32,
        cpu: u32,
        stack_id: Option<u32>,
        label_id: Option<u32>,
        replay: &ExportProcessReplay) -> anyhow::Result<()> {
        let thread_id = self.get_pid_tid_id(replay);

        self.event_block.write_u8(223)?; /* Flags: 1 | 2 | 4 | 8 | 16 | 64 | 128 */
        self.event_block.write_varint(meta_id as u64)?; /* MetaID */
        self.event_block.write_varint(0u64)?; /* SeqID inc */
        self.event_block.write_varint(0u64)?; /* Capture Thread ID */
        self.event_block.write_varint(cpu as u64)?; /* Processor Number */
        self.event_block.write_varint(thread_id as u64)?; /* Actual Thread ID */

        let stack_id = match stack_id {
            Some(stack_id) => { stack_id + 1 },
            None => { 0 },
        };

        self.event_block.write_varint(stack_id as u64)?; /* Stack ID */

        self.write_event_timestamp(replay.time())?;

        let label_id = match label_id {
            Some(label_id) => { label_id + 1 },
            None => { 0 },
        };

        self.event_block.write_varint(label_id as u64)?; /* Label ID */

        let payload = self.buffer.as_slice();

        self.event_block.write_varint(payload.len() as u64)?; /* Payload Size */
        self.event_block.write_bytes(payload)?;

        /* We flush every 1 MB */
        if self.event_block.len() >= 1048576 {
            self.flush_event_block(
                machine,
                self.flush_time,
                self.last_time)?;
        }

        Ok(())
    }

    fn flush_event_block(
        &mut self,
        machine: &ExportMachine,
        start_time: u64,
        end_time: u64) -> anyhow::Result<()> {
        debug!("Flushing NetTrace event block: start_time={}, end_time={}, event_count={}", 
            start_time, end_time, self.event_block.len());
        
        /* Write sequence block */
        self.write_seq_block(start_time)?;

        /* Write stacks to output */
        self.write_callstacks(machine)?;

        /* Write threads to output */
        self.write_threads()?;

        /* Write labels to output */
        self.write_labels(machine)?;

        /* Write events to output */
        let block_start = self.write_eventblock_start(
            start_time,
            end_time)?;

        self.output.write_bytes(&self.event_block)?;

        self.write_eventblock_end(block_start)?;

        /* Clear and update */
        self.event_block.clear();
        self.flush_time = end_time;
        self.last_time = 0;

        Ok(())
    }

    fn write_eventblock_end(
        &mut self,
        block_start: u64) -> anyhow::Result<()> {
        self.write_end_block(block_start, 2)
    }

    fn write_created_replay_event(
        &mut self,
        machine: &ExportMachine,
        replay: &ExportProcessReplay) -> anyhow::Result<()> {
        let process = replay.process();

        let ns_pid = match process.ns_pid() {
            Some(pid) => { pid },
            None => { 0 },
        };

        let name = match process.comm_id() {
            Some(id) => {
                match machine.strings().from_id(id) {
                    Ok(name) => { name },
                    Err(_) => { "Unknown" },
                }
            },
            None  => { "Unknown" },
        };

        self.buffer.clear();
        self.buffer.write_varint(ns_pid as u64)?;
        self.buffer.write_short_utf8(name)?;

        /* TODO: Once we have namespace names */
        self.buffer.write_short_utf8("Unknown")?;

        /*
         * We export using different events for created processes:
         * If the process was created within the machine before starting
         * the collection, then it is an existing process. If it after or
         * at the start of collection, then it's a newly created process.
         */
        let id = match replay.time() < self.sync_time {
            true => { self.existing_event_id },
            false => { self.create_event_id },
        };

        self.write_event_blob_from_buffer(
            machine,
            id,
            0,
            None,
            None,
            replay)
    }

    fn get_pid_tid_id(
        &mut self,
        replay: &ExportProcessReplay) -> u32 {
        /* Save pid_tid for later writing */
        let len = self.saved_pid_tids.len() as u32;

        let tid = match replay.sample_event() {
            Some(sample) => { sample.tid() },
            None => { 0 },
        };

        let key = SavedPidTidKey {
            pid: replay.process().pid(),
            tid,
        };

        *self.saved_pid_tids.entry(key).or_insert(len)
    }

    fn write_sample_replay_event(
        &mut self,
        machine: &ExportMachine,
        replay: &ExportProcessReplay,
        sample: &ExportProcessSample,
        converter: &dyn ExportGraphMetricValueConverter) -> anyhow::Result<()> {
        /* Save callstack for later writing */
        let len = self.saved_callstacks.len() as u32;

        let key = SavedCallstackKey {
            ip: sample.ip(),
            sample_id: sample.callstack_id() as u32,
            write_id: 0,
        };

        let callstack_id = *self.saved_callstacks.entry(key).or_insert(len);

        /* Save label for later writing */
        let len = self.saved_labels.len() as u32;

        let key = SavedLabelKey {
            attributes_id: sample.attributes_id(),
            write_id: 0,
        };

        let label_id = *self.saved_labels.entry(key).or_insert(len);

        /* Write out event */
        let value = converter.convert(machine, sample.value());

        self.buffer.clear();
        self.buffer.write_varint(value)?;

        /* Meta ID of 0 is reserved, so we add 1 here */
        let mut event_id = sample.kind() as u32 + 1;

        /* Handle if it's a record based sample */
        if sample.has_record() {
            /* Get the record for the sample */
            let data = machine.sample_record_data(sample);

            /*
             * We use the record_type as the kind with an offset.
             * This is setup when originally writing out the metadata
             * for the NetTrace file. This ensures we can have samples
             * that contain record data as well as those that don't, even
             * if the name conflicts. We do not need a + 1 here because
             * the record_id_offset handles this for us.
             */
            event_id = self.record_id_offset + data.record_type_id() as u32;

            /* Do not write sample value for original data */
            if self.original_meta_event_ids.contains(&event_id) {
                self.buffer.clear();
            }

            /* Write the extra data after the value */
            self.buffer.write_all(data.record_data())?;
        }

        self.write_event_blob_from_buffer(
            machine,
            event_id,
            sample.cpu() as u32,
            Some(callstack_id),
            Some(label_id),
            replay)
    }

    fn write_exited_replay_event(
        &mut self,
        machine: &ExportMachine,
        replay: &ExportProcessReplay) -> anyhow::Result<()> {
        self.buffer.clear();

        self.write_event_blob_from_buffer(
            machine,
            self.exit_event_id,
            0,
            None,
            None,
            replay)
    }

    fn write_mapping_metadata_event(
        &mut self,
        machine: &ExportMachine,
        replay: &ExportProcessReplay,
        mapping: &ExportMapping) -> anyhow::Result<u32> {
        let mut existing = true;

        let id = match mapping.node() {
            Some(node) => {
                /* 0 is reserved for not defined, so add 1 to length */
                let next_id = self.saved_meta_ids.len() as u32 + 1;

                *self.saved_meta_ids.entry(*node).or_insert_with(|| {
                    /* Flag as a new entry */
                    existing = false;

                    next_id
                })
            },
            None => {
                /* Use 0 for not defined */
                0
            },
        };

        /* Skip writing if we already wrote the entry */
        if !existing {
            self.buffer.clear();
            self.buffer.write_varint(id as u64)?;

            /* Symbol details */
            self.str_buffer.clear();

            if let Some(metadata) = machine.get_mapping_metadata(mapping) {
                metadata.to_symbol_metadata(machine.strings(), &mut self.str_buffer);
            }

            self.buffer.write_short_utf8(&self.str_buffer)?;

            /* Version details */
            self.str_buffer.clear();

            if let Some(metadata) = machine.get_mapping_metadata(mapping) {
                metadata.to_version_metadata(machine.strings(), &mut self.str_buffer);
            }

            self.buffer.write_short_utf8(&self.str_buffer)?;

            self.write_event_blob_from_buffer(
                machine,
                self.mapping_meta_event_id,
                0,
                None,
                None,
                replay)?;
        }

        Ok(id)
    }

    fn write_mapping_replay_event(
        &mut self,
        machine: &ExportMachine,
        replay: &ExportProcessReplay,
        mapping: &ExportMapping) -> anyhow::Result<()> {
        /* Write mapping metadata first if not already written */
        let meta_id = self.write_mapping_metadata_event(machine, replay, mapping)?;

        /* Write actual mapping details */
        let name = match machine.strings().from_id(mapping.filename_id()) {
            Ok(name) => { name },
            Err(_) => { "Unknown" },
        };

        self.buffer.clear();
        self.buffer.write_varint(mapping.id() as u64)?;
        self.buffer.write_varint(mapping.start())?;
        self.buffer.write_varint(mapping.end())?;
        self.buffer.write_varint(mapping.file_offset())?;
        self.buffer.write_short_utf8(name)?;
        self.buffer.write_varint(meta_id as u64)?;

        /* Symbol details */
        self.str_buffer.clear();

        if let Some(metadata) = machine.get_mapping_metadata(mapping) {
            metadata.to_symbol_metadata(machine.strings(), &mut self.str_buffer);
        }

        self.buffer.write_short_utf8(&self.str_buffer)?;

        /* Version details */
        self.str_buffer.clear();

        if let Some(metadata) = machine.get_mapping_metadata(mapping) {
            metadata.to_version_metadata(machine.strings(), &mut self.str_buffer);
        }

        self.buffer.write_short_utf8(&self.str_buffer)?;

        self.write_event_blob_from_buffer(
            machine,
            self.mapping_event_id,
            0,
            None,
            None,
            replay)
    }

    fn write_mapping_symbol_replay_event(
        &mut self,
        machine: &ExportMachine,
        replay: &ExportProcessReplay,
        mapping: &ExportMapping,
        symbol: &ExportSymbol) -> anyhow::Result<()> {
        let name = match machine.strings().from_id(symbol.name_id()) {
            Ok(name) => { name },
            Err(_) => { "Unknown" },
        };

        self.buffer.clear();
        self.buffer.write_varint(self.sym_id as u64)?;
        self.buffer.write_varint(mapping.id() as u64)?;
        self.buffer.write_varint(symbol.start())?;
        self.buffer.write_varint(symbol.end())?;
        self.buffer.write_short_utf8(name)?;

        self.sym_id += 1;

        self.write_event_blob_from_buffer(
            machine,
            self.symbol_event_id,
            0,
            None,
            None,
            replay)
    }

    fn write_replay_event(
        &mut self,
        machine: &ExportMachine,
        replay: &ExportProcessReplay,
        converter: &dyn ExportGraphMetricValueConverter) -> anyhow::Result<()> {
        if let Some(sample) = replay.sample_event() {
            self.write_sample_replay_event(machine, replay, sample, converter)?;
        }

        if replay.created_event() {
            self.write_created_replay_event(machine, replay)?;
        }

        if replay.exited_event() {
            self.write_exited_replay_event(machine, replay)?;
        }

        if let Some(mapping) = replay.mapping_event() {
            self.write_mapping_replay_event(machine, replay, mapping)?;

            for symbol in mapping.symbols() {
                self.write_mapping_symbol_replay_event(
                    machine,
                    replay, 
                    mapping,
                    symbol)?;
            }
        }

        Ok(())
    }

    fn event_field_to_element_type(field: &EventField) -> Option<u8> {
        let mut split = field.type_name.split_whitespace();
        let mut first = split.next().unwrap_or("");

        if first == "__dyn_array" {
            first = split.next().unwrap_or("");
        }

        match first {
            /* Byte */
            "u8" => { Some(TYPE_ID_BYTE) },
            "s8" => { Some(TYPE_ID_BYTE) },
            "char" => { Some(TYPE_ID_BYTE) },

            /* INT16 */
            "u16" => { Some(TYPE_ID_UINT16) },
            "s16" => { Some(TYPE_ID_INT16) },
            "short" => { Some(TYPE_ID_INT16) },

            /* INT32 */
            "u32" => { Some(TYPE_ID_UINT32) },
            "s32" => { Some(TYPE_ID_INT32) },
            "int" => { Some(TYPE_ID_INT32) },

            /* INT64 */
            "u64" => { Some(TYPE_ID_UINT64) },
            "s64" => { Some(TYPE_ID_INT64) },
            "long" => { Some(TYPE_ID_INT64) },

            /* SINGLE */
            "float" => { Some(TYPE_ID_SINGLE) },

            /* DOUBLE */
            "double" => { Some(TYPE_ID_DOUBLE) },

            /* UNSIGNED */
            "unsigned" => {
                /* Ambigious, use size */
                match field.size {
                    1 => { Some(TYPE_ID_BYTE) },
                    2 => { Some(TYPE_ID_UINT16) },
                    4 => { Some(TYPE_ID_UINT32) },
                    8 => { Some(TYPE_ID_UINT64) },
                    _ => { None },
                }
            },

            /* Linux Variable Data */
            "__rel_loc" => { Some(TYPE_ID_UINT32) },
            "__data_loc" => { Some(TYPE_ID_UINT32) },

            /* Windows UTF16 string */
            "string" => { Some(TYPE_ID_NULL_UTF16_STRING) },

            /* Unhandled */
            _ => { None },
        }
    }

    fn event_field_to_type(field: &EventField) -> Option<u8> {
        if field.location == LocationType::StaticUTF16String {
            Some(TYPE_ID_NULL_UTF16_STRING)
        } else if field.location == LocationType::StaticLenPrefixArray {
            Some(TYPE_ID_ARRAY)
        } else {
            if field.type_name.ends_with("]") {
                if let Some(index) = field.type_name.rfind('[') {
                    if index != field.type_name.len() - 2 {
                        /*
                         * NetTrace cannot currently represent static
                         * sized arrays of char/bytes/etc. So we must
                         * stop on these until we have a workaround.
                         */
                        return None;
                    }
                }
            }

            Self::event_field_to_element_type(field)
        }
    }

    fn write_metadata_object(
        &mut self,
        stack_kinds: &[String],
        record_types: &[ExportRecordType]) -> anyhow::Result<()> {
        let block_start = self.write_start_block()?;
        let mut meta_id = 1;

        /* HeaderSize: Future expansion */
        self.output.write_u16(0)?;

        /*
         * Stack Event Metadata:
         * These could be unbounded in size vs our metadata events.
         * In order to make it easy to associate them, we simply use
         * the index of the kind as the meta_id.
         */
        for kind in stack_kinds {
            self.write_event_metadata(
                meta_id,
                "Universal.Events",
                meta_id,
                kind,
                &STACK_EVENT_FIELDS)?;

            meta_id += 1;
        }

        /*
         * Record Event Metadata:
         * These can also be unbounded in size. We use the resource_type
         * as the meta_id along with a calculated offset.
         */
        self.record_id_offset = meta_id;

        let mut record_fields = Vec::new();

        for record_type in record_types {
            record_fields.clear();

            /* Original data does not change it's format */
            if record_type.is_original_data() {
                self.original_meta_event_ids.insert(meta_id);
            } else {
                record_fields.push(VALUE_FIELD);
            }

            /* Dynamic fields */
            for field in record_type.format().fields() {
                match Self::event_field_to_type(field) {
                    Some(type_id) => {
                        let element_type_id = match type_id {
                            TYPE_ID_ARRAY => Self::event_field_to_element_type(field),
                            _ => None,
                        };

                        record_fields.push(NetTraceField {
                            type_id,
                            element_type_id,
                            name: &field.name,
                        });
                    },
                    None => {
                        /*
                         * If we cannot support it, then stop. This is until
                         * we have a way to represent fixed sized arrays.
                         */
                        break;
                    },
                }
            }

            if record_type.is_original_data() {
                /* Determine provider/system from event name */
                let (provider_name, event_name) = match record_type.name().split_once('/') {
                    Some((provider_name, event_name)) => { (provider_name, event_name) },
                    None => { ("Universal.Events", record_type.name()) },
                };

                self.write_event_metadata(
                    meta_id,
                    provider_name,
                    record_type.id() as u32,
                    event_name,
                    &record_fields)?;
            } else {
                self.write_event_metadata(
                    meta_id,
                    "Universal.Events",
                    meta_id,
                    record_type.name(),
                    &record_fields)?;
            }

            meta_id += 1;
        }

        /*
         * System Metadata:
         * These are static IDs, which we save on a per-export basis.
         * The previous unbounded events require us to save these IDs
         * so we can use them later during replay. The pattern is to
         * save the ID being written from meta_id, write it out, then
         * advance meta_id. During replay the saved ID will be used.
         */
        self.existing_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            0, /* Stable ID */
            "ExistingProcess",
            &PROCESS_CREATE_FIELDS)?;

        meta_id += 1;

        self.create_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            1, /* Stable ID */
            "ProcessCreate",
            &PROCESS_CREATE_FIELDS)?;

        meta_id += 1;

        self.exit_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            2, /* Stable ID */
            "ProcessExit",
            &PROCESS_EXIT_FIELDS)?;

        meta_id += 1;

        self.mapping_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            3, /* Stable ID */
            "ProcessMapping",
            &PROCESS_MAPPING_FIELDS)?;

        meta_id += 1;

        self.symbol_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            4, /* Stable ID */
            "ProcessSymbol",
            &PROCESS_SYMBOL_FIELDS)?;

        meta_id += 1;

        self.mapping_meta_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            5, /* Stable ID */
            "ProcessMappingMetadata",
            &PROCESS_MAPPING_META_FIELDS)?;

        /* Done writing metadata */
        self.write_end_block(block_start, 3)
    }

    fn write_seq_block(
        &mut self,
        time_qpc: u64) -> anyhow::Result<()> {
        let block_start = self.write_start_block()?;

        self.output.write_u64(time_qpc)?; /* Timestamp */
        self.output.write_u32(1)?; /* Flags: Clear Threads */
        self.output.write_u32(0)?; /* ThreadCount */

        /* Done writing seq block */
        self.write_end_block(block_start, 4)
    }

    fn write_trace_object(
        &mut self,
        sync_time: DateTime<Utc>,
        sync_time_qpc: u64,
        qpc_freq: u64,
        num_of_cpus: u32,
        sample_freq: u32,
        system_page_size: u64) -> anyhow::Result<()> {
        /* Conversions to match trace format */
        let nanos_between_samples = 1000000000 / sample_freq;
        let milli_secs = sync_time.nanosecond() / 1000000;
        let ptr_size = 8;

        self.sync_time = sync_time_qpc;
        self.flush_time = self.sync_time;

        let block_start = self.write_start_block()?;
        self.output.write_u16(sync_time.year() as u16)?;
        self.output.write_u16(sync_time.month() as u16)?;
        self.output.write_u16(sync_time.weekday() as u16)?;
        self.output.write_u16(sync_time.day() as u16)?;
        self.output.write_u16(sync_time.hour() as u16)?;
        self.output.write_u16(sync_time.minute() as u16)?;
        self.output.write_u16(sync_time.second() as u16)?;
        self.output.write_u16(milli_secs as u16)?;
        self.output.write_u64(sync_time_qpc)?;
        self.output.write_u64(qpc_freq)?;
        self.output.write_u32(ptr_size)?;

        /* Key values */
        self.output.write_u32(3)?;
        self.output.write_utf8("HardwareThreadCount")?;
        self.output.write_utf8(&format!("{}", num_of_cpus))?;
        self.output.write_utf8("ExpectedCPUSamplingRate")?;
        self.output.write_utf8(&format!("{}", nanos_between_samples))?;
        self.output.write_utf8("SystemPageSize")?;
        self.output.write_utf8(&format!("{}", system_page_size))?;

        self.write_end_block(block_start, 1)
    }

    fn init(&mut self) -> anyhow::Result<()> {
        self.init_threads();

        self.output.write(b"Nettrace")?;
        self.output.write_u32(0)?; /* Reserved */
        self.output.write_u32(6)?; /* Major Ver */
        self.output.write_u32(0) /* Minor Ver */
    }

    fn take_saved_callstacks(&mut self) -> Vec<SavedCallstackKey> {
        let mut ids = Vec::new();

        /* Drain the callstacks into a vec, saving the value in the process */
        for (mut k,v) in self.saved_callstacks.drain() {
            k.write_id = v;

            ids.push(k);
        }

        /* Sort by write_id */
        ids.sort_by(|a,b| a.write_id.cmp(&b.write_id));

        ids
    }

    fn take_saved_labels(&mut self) -> Vec<SavedLabelKey> {
        let mut ids = Vec::new();

        /* Drain the labels into a vec, saving the value in the process */
        for (mut k,v) in self.saved_labels.drain() {
            k.write_id = v;

            ids.push(k);
        }

        /* Sort by write_id */
        ids.sort_by(|a,b| a.write_id.cmp(&b.write_id));

        ids
    }

    fn write_callstacks(
        &mut self,
        machine: &ExportMachine) -> anyhow::Result<()> {
        let block_start = self.write_start_block()?;

        let callstacks = self.take_saved_callstacks();
        let len = callstacks.len() as u32;

        self.output.write_u32(1)?; /* First Stack ID */
        self.output.write_u32(len)?; /* Count of stacks */

        let mut ips = Vec::new();

        for callstack in callstacks {
            machine.callstacks().from_id(
                callstack.sample_id as usize,
                &mut ips)?;

            let size = (ips.len() + 1) * 8;

            self.output.write_u32(size as u32)?;
            self.output.write_u64(callstack.ip)?;

            for ip in &ips {
                self.output.write_u64(*ip)?;
            }
        }

        /* Done writing stacks */
        self.write_end_block(block_start, 5)
    }

    fn init_threads(&mut self) {
        /* Add in reserved index of 0 */
        self.saved_pid_tids.insert(
            SavedPidTidKey {
                pid: 0,
                tid: 0,
            },
            0);
    }

    fn write_threads(&mut self) -> anyhow::Result<()> {
        let block_start = self.write_start_block()?;

        for (k,id) in self.saved_pid_tids.drain() {
            let len = self.output.size_varint(k.pid as u64) +
                self.output.size_varint(k.tid as u64) +
                self.output.size_varint(id as u64) +
                2;

            self.output.write_u16(len as u16)?;
            self.output.write_varint(id as u64)?;

            self.output.write_u8(2)?;
            self.output.write_varint(k.pid as u64)?;

            self.output.write_u8(3)?;
            self.output.write_varint(k.tid as u64)?;
        }

        self.init_threads();

        /* Done writing threads */
        self.write_end_block(block_start, 6)
    }

    fn write_labels(
        &mut self,
        machine: &ExportMachine) -> anyhow::Result<()> {
        let block_start = self.write_start_block()?;

        let strings = machine.strings();
        let activity_str_id = strings.find_id("ActivityId").unwrap_or(0);
        let related_activity_str_id = strings.find_id("RelatedActivityId").unwrap_or(0);

        let fn_activity_str_id = activity_str_id;
        let fn_related_activity_str_id = related_activity_str_id;

        let mut walker = ExportAttributeWalker::default()
            .with_filter(move |attribute| {
                /* Only keep supported attributes */
                match attribute.attribute_value() {
                    ExportAttributeValue::Label(_) => { true },
                    ExportAttributeValue::Value(_) => { true },
                    ExportAttributeValue::Record(_) => {
                        if attribute.name() == 0 {
                            return false;
                        }

                        if attribute.name() == fn_activity_str_id ||
                            attribute.name() == fn_related_activity_str_id {
                            return true;
                        }

                        false
                    },
                }
            });

        let labels = self.take_saved_labels();

        self.output.write_u32(1)?;
        self.output.write_u32(labels.len() as u32)?;

        for key in &labels {
            machine.attributes(
                key.attributes_id,
                &mut walker);

            let attributes = walker.attributes();

            /* We do not expect empty attributes */
            if attributes.is_empty() {
                self.output.write_u8(128 | 5)?;
                self.output.write_utf8("Error")?;
                self.output.write_utf8("Expected actual values")?;
                continue;
            }

            let last = attributes.len() - 1;

            for (i,attribute) in attributes.into_iter().enumerate() {
                let name = attribute.name_str(strings).unwrap_or("???");

                /* If last need high bit set */
                let add_flag = if i == last {
                    128u8
                } else {
                    0u8
                };

                match attribute.attribute_value() {
                    ExportAttributeValue::Label(id) => {
                        let value = strings.from_id(id).unwrap_or("???");

                        self.output.write_u8(add_flag | 5)?;
                        self.output.write_utf8(name)?;
                        self.output.write_utf8(value)?;
                    },
                    ExportAttributeValue::Value(value) => {
                        self.output.write_u8(add_flag | 6)?;
                        self.output.write_utf8(name)?;
                        self.output.write_varint(value)?;
                    },
                    ExportAttributeValue::Record(id) => {
                        let record = machine.try_get_record_data(id).unwrap_or_default();
                        let mut written = false;

                        if record.len() == 16 {
                            /* GUID based attributes */
                            if attribute.name() == activity_str_id {
                                self.output.write_u8(add_flag | 1)?;
                                self.output.write_all(record)?;
                                written = true;
                            } else if attribute.name() == related_activity_str_id {
                                self.output.write_u8(add_flag | 2)?;
                                self.output.write_all(record)?;
                                written = true;
                            }
                        }

                        if !written {
                            /*
                             * Unexpected, Log Error in Attributes:
                             * This is to prevent the file from being
                             * potentially unreadable. If this is the
                             * last attribute for example and we don't
                             * write the add_flag for ending, the reader
                             * will have errors.
                             */
                            self.output.write_u8(add_flag | 5)?;
                            self.output.write_utf8("Error")?;
                            self.output.write_utf8("Unknown Record Attribute")?;
                        }
                    }
                }
            }
        }

        /* Done writing labels */
        self.write_end_block(block_start, 8)
    }

    fn finish(
        &mut self,
        machine: &ExportMachine) -> anyhow::Result<()> {
        /* Determine end time to use */
        let end_time = match machine.end_qpc() {
            Some(end_qpc) => { end_qpc },
            None => { u64::MAX },
        };

        /* Flush events/stacks if needed */
        if !self.event_block.is_empty() {
            self.flush_event_block(
                machine,
                self.flush_time,
                end_time)?;
        }

        /* Always emit end sequence to convey end time */
        self.write_seq_block(end_time)?;

        /* EndOfStream Block */
        self.output.write_u32(0)?;

        Ok(self.output.flush()?)
    }
}

impl NetTraceFormat for ExportMachine {
    fn to_net_trace(
        &mut self,
        predicate: impl Fn(&ExportProcess) -> bool,
        path: &str) -> anyhow::Result<()> {
        info!("Starting NetTrace export: path={}", path);
        
        let sync_time = match self.start_date() {
            Some(value) => { value },
            None => { 
                error!("NetTrace export failed: no start date");
                anyhow::bail!("No start date saved, invoke mark_start()."); 
            },
        };

        let sync_time_qpc = match self.start_qpc() {
            Some(value) => { value },
            None => { 
                error!("NetTrace export failed: no start qpc");
                anyhow::bail!("No start qpc saved, invoke mark_start()."); 
            },
        };

        let qpc_freq = Self::qpc_freq();
        let cpu_count = Self::cpu_count();
        let sample_freq = self.settings().cpu_freq() as u32;
        let system_page_size = Self::system_page_size();

        debug!("NetTrace parameters: qpc_freq={}, cpu_count={}, sample_freq={}, page_size={}", 
            qpc_freq, cpu_count, sample_freq, system_page_size);

        let mut writer = NetTraceWriter::new(path)?;

        writer.write_trace_object(
            sync_time,
            sync_time_qpc,
            qpc_freq,
            cpu_count,
            sample_freq,
            system_page_size)?;

        writer.write_metadata_object(
            self.sample_kinds(),
            self.record_types())?;

        let converter = DefaultExportGraphMetricValueConverter::default();

        self.replay_by_time(
            predicate,
            |machine, replay| {
                writer.write_replay_event(machine, replay, &converter)
            })?;

        writer.finish(&self)?;
        
        info!("NetTrace export completed successfully: path={}", path);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_field_to_type() {
        /* BYTE */
        assert_eq!(
            Some(TYPE_ID_BYTE),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "char a".into(),
                    LocationType::Static,
                    0,
                    1)));

        assert_eq!(
            Some(TYPE_ID_BYTE),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "u8 a".into(),
                    LocationType::Static,
                    0,
                    1)));

        assert_eq!(
            Some(TYPE_ID_BYTE),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "s8 a".into(),
                    LocationType::Static,
                    0,
                    1)));

        /* INT16 */
        assert_eq!(
            Some(TYPE_ID_INT16),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "short a".into(),
                    LocationType::Static,
                    0,
                    2)));

        assert_eq!(
            Some(TYPE_ID_INT16),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "s16 a".into(),
                    LocationType::Static,
                    0,
                    2)));

        assert_eq!(
            Some(TYPE_ID_UINT16),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "u16 a".into(),
                    LocationType::Static,
                    0,
                    2)));

        assert_eq!(
            Some(TYPE_ID_UINT16),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "unsigned short a".into(),
                    LocationType::Static,
                    0,
                    2)));

        /* INT32 */
        assert_eq!(
            Some(TYPE_ID_INT32),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "int a".into(),
                    LocationType::Static,
                    0,
                    4)));

        assert_eq!(
            Some(TYPE_ID_INT32),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "s32 a".into(),
                    LocationType::Static,
                    0,
                    4)));

        assert_eq!(
            Some(TYPE_ID_UINT32),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "u32 a".into(),
                    LocationType::Static,
                    0,
                    4)));

        assert_eq!(
            Some(TYPE_ID_UINT32),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "unsigned int a".into(),
                    LocationType::Static,
                    0,
                    4)));

        /* INT64 */
        assert_eq!(
            Some(TYPE_ID_INT64),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "long a".into(),
                    LocationType::Static,
                    0,
                    8)));

        assert_eq!(
            Some(TYPE_ID_INT64),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "s64 a".into(),
                    LocationType::Static,
                    0,
                    8)));

        assert_eq!(
            Some(TYPE_ID_UINT64),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "u64 a".into(),
                    LocationType::Static,
                    0,
                    8)));

        assert_eq!(
            Some(TYPE_ID_UINT64),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "unsigned long a".into(),
                    LocationType::Static,
                    0,
                    8)));

        /* SINGLE */
        assert_eq!(
            Some(TYPE_ID_SINGLE),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "float a".into(),
                    LocationType::Static,
                    0,
                    4)));

        /* DOUBLE */
        assert_eq!(
            Some(TYPE_ID_DOUBLE),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "double a".into(),
                    LocationType::Static,
                    0,
                    4)));

        /* UTF16 String */
        assert_eq!(
            Some(TYPE_ID_NULL_UTF16_STRING),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "string a".into(),
                    LocationType::Static,
                    0,
                    4)));

        assert_eq!(
            Some(TYPE_ID_NULL_UTF16_STRING),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "wchar a[]".into(),
                    LocationType::StaticUTF16String,
                    0,
                    4)));

        /* Variable Linux Data */
        assert_eq!(
            Some(TYPE_ID_UINT32),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "__rel_loc char data[]".into(),
                    LocationType::Static,
                    0,
                    4)));

        assert_eq!(
            Some(TYPE_ID_UINT32),
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "__data_loc char data[]".into(),
                    LocationType::Static,
                    0,
                    4)));

        /* Unknown */
        assert_eq!(
            None,
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "char comm[16]".into(),
                    LocationType::Static,
                    0,
                    16)));

        assert_eq!(
            None,
            NetTraceWriter::event_field_to_type(
                &EventField::new(
                    "Test".into(),
                    "wut da".into(),
                    LocationType::Static,
                    0,
                    1)));
    }
}
