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

const MAX_BLOCK_SIZE: usize = 0x00FF_FFFF;

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
    type_id: TYPE_ID_ARRAY,
    element_type_id: Some(TYPE_ID_UTF8),
    name: "Name",
};

const NAMESPACE_NAME_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_ARRAY,
    element_type_id: Some(TYPE_ID_UTF8),
    name: "NamespaceName",
};

const FILE_NAME_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_ARRAY,
    element_type_id: Some(TYPE_ID_UTF8),
    name: "FileName",
};

const SYMBOL_META_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_ARRAY,
    element_type_id: Some(TYPE_ID_UTF8),
    name: "SymbolMetadata",
};

const VERSION_META_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_ARRAY,
    element_type_id: Some(TYPE_ID_UTF8),
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
        let len = u16::try_from(bytes.len())
            .map_err(|_| anyhow::anyhow!("NetTrace UTF8 string exceeds the 16-bit length limit: {} bytes", bytes.len()))?;
        self.write_u16(len)?;
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
    /*
     * All events are serialized through capture thread index 0. Every emitted
     * event advances that thread's sequence number once, so the emitted event
     * count is also its sequence number within a block.
     */
    event_count: u32,
    /*
     * Sequence points clear capture-thread state at event-block boundaries.
     * Consequently, the final loss gap must start from the number of events
     * in the most recently flushed block, not the total events in the trace.
     */
    last_event_count: u32,
    /*
     * Tracks whether the trace contains at least one thread block. The final
     * loss sequence point references capture thread index 0, so if no event
     * block was written, finish() must first emit a thread block that defines
     * that index. Without it, a trace with only lost events could not encode
     * lost_events.
     */
    wrote_thread_block: bool,
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
            event_count: 0,
            last_event_count: 0,
            wrote_thread_block: false,
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
        anyhow::ensure!(
            total_size <= MAX_BLOCK_SIZE as u64,
            "NetTrace block kind {} exceeds the 24-bit size limit: {} bytes",
            kind,
            total_size);

        let header = total_size as u32 | (kind as u32) << 24;
        self.update_u32(header, block_start)
    }

    fn write_event_metadata(
        &mut self,
        block_start: &mut u64,
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
        let field_count = u16::try_from(fields.len())
            .map_err(|_| anyhow::anyhow!("NetTrace metadata exceeds the 16-bit field count limit"))?;
        self.buffer.clear();
        self.buffer.write_varint(meta_id as u64)?;
        self.buffer.write_utf8(provider)?;
        self.buffer.write_varint(event_id as u64)?;
        self.buffer.write_utf8(event_name)?;
        self.buffer.write_u16(field_count)?;

        for field in fields {
            let mut size = self.buffer.size_utf8(field.name) + 1;

            if field.type_id == TYPE_ID_ARRAY {
                size += 1;
            }

            let size = u16::try_from(size)
                .map_err(|_| anyhow::anyhow!("NetTrace field description exceeds the 16-bit size limit: {}", field.name))?;
            self.buffer.write_u16(size)?;
            self.buffer.write_utf8(field.name)?;
            self.buffer.write_u8(field.type_id)?;

            if field.type_id == TYPE_ID_ARRAY {
                let element_type_id = field.element_type_id
                    .ok_or_else(|| anyhow::anyhow!("NetTrace array field has no supported element type: {}", field.name))?;
                self.buffer.write_u8(element_type_id)?;
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

        let size = u16::try_from(self.buffer.len())
            .map_err(|_| anyhow::anyhow!("NetTrace metadata row exceeds the 16-bit size limit: {} bytes", self.buffer.len()))?;

        if self.get_pos()? - *block_start + 2 + size as u64 > MAX_BLOCK_SIZE as u64 {
            self.write_end_block(*block_start, 3)?;
            *block_start = self.write_start_block()?;
            self.output.write_u16(0)?; /* HeaderSize */
        }

        self.output.write_u16(size)?; /* Size */
        self.output.write_bytes(&self.buffer)
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
        self.event_count = self.event_count.wrapping_add(1);

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
        self.write_seq_block(start_time, None)?;

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

        self.event_block.clear();
        self.last_event_count = self.event_count;
        self.event_count = 0;
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
        let mut block_start = self.write_start_block()?;
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
                &mut block_start,
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

            /* Original data does not change its format */
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
                    &mut block_start,
                    meta_id,
                    provider_name,
                    record_type.id() as u32,
                    event_name,
                    &record_fields)?;
            } else {
                self.write_event_metadata(
                    &mut block_start,
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
            &mut block_start,
            meta_id,
            "Universal.System",
            0, /* Stable ID */
            "ExistingProcess",
            &PROCESS_CREATE_FIELDS)?;

        meta_id += 1;

        self.create_event_id = meta_id;

        self.write_event_metadata(
            &mut block_start,
            meta_id,
            "Universal.System",
            1, /* Stable ID */
            "ProcessCreate",
            &PROCESS_CREATE_FIELDS)?;

        meta_id += 1;

        self.exit_event_id = meta_id;

        self.write_event_metadata(
            &mut block_start,
            meta_id,
            "Universal.System",
            2, /* Stable ID */
            "ProcessExit",
            &PROCESS_EXIT_FIELDS)?;

        meta_id += 1;

        self.mapping_event_id = meta_id;

        self.write_event_metadata(
            &mut block_start,
            meta_id,
            "Universal.System",
            3, /* Stable ID */
            "ProcessMapping",
            &PROCESS_MAPPING_FIELDS)?;

        meta_id += 1;

        self.symbol_event_id = meta_id;

        self.write_event_metadata(
            &mut block_start,
            meta_id,
            "Universal.System",
            4, /* Stable ID */
            "ProcessSymbol",
            &PROCESS_SYMBOL_FIELDS)?;

        meta_id += 1;

        self.mapping_meta_event_id = meta_id;

        self.write_event_metadata(
            &mut block_start,
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
        time_qpc: u64,
        sequence_number: Option<u32>) -> anyhow::Result<()> {
        let block_start = self.write_start_block()?;

        self.output.write_u64(time_qpc)?; /* Timestamp */
        self.output.write_u32(1)?; /* Flags: Clear Threads */

        match sequence_number {
            Some(sequence_number) => {
                /*
                 * Readers compare this lower bound with the sequence numbers
                 * of events observed for capture thread 0 since the previous
                 * Clear Threads sequence point. Any gap is reported as lost
                 * events.
                 */
                self.output.write_u32(1)?; /* ThreadCount */
                self.output.write_varint(0)?; /* Capture Thread Index */
                self.output.write_varint(sequence_number as u64)?;
            },
            None => {
                self.output.write_u32(0)?; /* ThreadCount */
            },
        }

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

        self.output.write_all(b"Nettrace")?;
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
        let callstacks = self.take_saved_callstacks();

        let mut block_start = self.write_start_block()?;
        self.output.write_u32(1)?; /* First Stack ID */
        let mut count_pos = self.reserve_u32()?;
        let mut count = 0;
        let mut block_size = 8;

        let mut ips = Vec::new();

        for callstack in callstacks {
            machine.callstacks().from_id(
                callstack.sample_id as usize,
                &mut ips)?;

            let size = (ips.len() + 1) * 8;
            let entry_size = 4 + size;
            anyhow::ensure!(
                entry_size <= MAX_BLOCK_SIZE - 8,
                "NetTrace callstack exceeds the 24-bit block size limit: {} bytes",
                entry_size);

            if block_size + entry_size > MAX_BLOCK_SIZE {
                self.update_u32(count, count_pos)?;
                self.write_end_block(block_start, 5)?;

                // Stack IDs continue across blocks until the next sequence point.
                block_start = self.write_start_block()?;
                self.output.write_u32(callstack.write_id + 1)?;
                count_pos = self.reserve_u32()?;
                count = 0;
                block_size = 8;
            }

            self.output.write_u32(size as u32)?;
            self.output.write_u64(callstack.ip)?;

            for ip in &ips {
                self.output.write_u64(*ip)?;
            }

            count += 1;
            block_size += entry_size;
        }

        /* Done writing stacks */
        self.update_u32(count, count_pos)?;
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
        let mut block_start = self.write_start_block()?;
        let mut block_size = 0;
        let threads = std::mem::take(&mut self.saved_pid_tids);

        for (k,id) in threads {
            let len = self.output.size_varint(k.pid as u64) +
                self.output.size_varint(k.tid as u64) +
                self.output.size_varint(id as u64) +
                2;

            if block_size + 2 + len > MAX_BLOCK_SIZE {
                self.write_end_block(block_start, 6)?;
                block_start = self.write_start_block()?;
                block_size = 0;
            }
            self.output.write_u16(len as u16)?;
            self.output.write_varint(id as u64)?;

            self.output.write_u8(2)?;
            self.output.write_varint(k.pid as u64)?;

            self.output.write_u8(3)?;
            self.output.write_varint(k.tid as u64)?;
            block_size += 2 + len;
        }

        self.init_threads();
        self.wrote_thread_block = true;

        /* Done writing threads */
        self.write_end_block(block_start, 6)
    }

    fn write_labels(
        &mut self,
        machine: &ExportMachine) -> anyhow::Result<()> {
        let mut block_start = self.write_start_block()?;

        let strings = machine.strings();
        let activity_str_id = strings.find_id("ActivityId").unwrap_or(0);
        let related_activity_str_id = strings.find_id("RelatedActivityId").unwrap_or(0);
        let version_str_id = strings.find_id("Version").unwrap_or(0);
        let op_code_str_id = strings.find_id("OpCode").unwrap_or(0);
        let trace_id_str_id = strings.find_id("TraceId").unwrap_or(0);
        let span_id_str_id = strings.find_id("SpanId").unwrap_or(0);

        let fn_activity_str_id = activity_str_id;
        let fn_related_activity_str_id = related_activity_str_id;
        let fn_trace_id_str_id = trace_id_str_id;
        let fn_span_id_str_id = span_id_str_id;

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
                            attribute.name() == fn_related_activity_str_id ||
                            attribute.name() == fn_trace_id_str_id ||
                            attribute.name() == fn_span_id_str_id {
                            return true;
                        }

                        false
                    },
                }
            });

        let labels = self.take_saved_labels();

        self.output.write_u32(1)?;
        let mut count_pos = self.reserve_u32()?;
        let mut count = 0;
        let mut block_size = 8;

        for key in &labels {
            self.buffer.clear();
            machine.attributes(
                key.attributes_id,
                &mut walker);

            let attributes = walker.attributes();

            /* We do not expect empty attributes */
            if attributes.is_empty() {
                self.buffer.write_u8(128 | 5)?;
                self.buffer.write_utf8("Error")?;
                self.buffer.write_utf8("Expected actual values")?;
            }

            let last = attributes.len().saturating_sub(1);

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

                        self.buffer.write_u8(add_flag | 5)?;
                        self.buffer.write_utf8(name)?;
                        self.buffer.write_utf8(value)?;
                    },
                    ExportAttributeValue::Value(value) => {
                        if attribute.name() == op_code_str_id {
                            /* Kind 7: OpCode */
                            self.buffer.write_u8(add_flag | 7)?;
                            self.buffer.write_u8(value as u8)?;
                        } else if attribute.name() == version_str_id {
                            /* Kind 10: Version */
                            self.buffer.write_u8(add_flag | 10)?;
                            self.buffer.write_u8(value as u8)?;
                        } else {
                            self.buffer.write_u8(add_flag | 6)?;
                            self.buffer.write_utf8(name)?;
                            self.buffer.write_varint(value)?;
                        }
                    },
                    ExportAttributeValue::Record(id) => {
                        let record = machine.try_get_record_data(id).unwrap_or_default();
                        let mut written = false;

                        if record.len() == 16 {
                            /* GUID based attributes */
                            if attribute.name() == activity_str_id {
                                self.buffer.write_u8(add_flag | 1)?;
                                self.buffer.write_all(record)?;
                                written = true;
                            } else if attribute.name() == related_activity_str_id {
                                self.buffer.write_u8(add_flag | 2)?;
                                self.buffer.write_all(record)?;
                                written = true;
                            } else if attribute.name() == trace_id_str_id {
                                /* Kind 3: TraceId */
                                self.buffer.write_u8(add_flag | 3)?;
                                self.buffer.write_all(record)?;
                                written = true;
                            }
                        }

                        if record.len() == 8 && attribute.name() == span_id_str_id {
                            /* Kind 4: SpanId */
                            self.buffer.write_u8(add_flag | 4)?;
                            self.buffer.write_all(record)?;
                            written = true;
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
                            self.buffer.write_u8(add_flag | 5)?;
                            self.buffer.write_utf8("Error")?;
                            self.buffer.write_utf8("Unknown Record Attribute")?;
                        }
                    }
                }
            }

            let size = self.buffer.len();
            anyhow::ensure!(
                size <= MAX_BLOCK_SIZE - 8,
                "NetTrace label list exceeds the 24-bit block size limit: {} bytes",
                size);
            if block_size + size > MAX_BLOCK_SIZE {
                self.update_u32(count, count_pos)?;
                self.write_end_block(block_start, 8)?;
                block_start = self.write_start_block()?;
                self.output.write_u32(key.write_id + 1)?;
                count_pos = self.reserve_u32()?;
                count = 0;
                block_size = 8;
            }
            self.output.write_bytes(&self.buffer)?;
            count += 1;
            block_size += size;
        }

        /* Done writing labels */
        self.update_u32(count, count_pos)?;
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

        /*
         * Nettrace has no scalar lost-event field. Loss is represented as a
         * gap between the events present for a capture thread and the
         * sequence number reported at a sequence point.
         *
         * The collection APIs provide only an aggregate count, not where the
         * losses occurred. Attribute the aggregate to capture thread 0 at the
         * final sequence point. Intermediate sequence points continue to
         * report no gap.
         */
        let lost_events = machine.lost_events();

        if lost_events != 0 && !self.wrote_thread_block {
            /*
             * No event block means no thread block has defined index 0 yet.
             * Define it now so a trace with only lost events has a valid final
             * entry.
             */
            self.write_threads()?;
        }

        let sequence_number = self.loss_sequence_number(lost_events);

        self.write_seq_block(
            end_time,
            sequence_number)?;

        /* EndOfStream Block */
        self.output.write_u32(0)?;

        Ok(self.output.flush()?)
    }

    fn loss_sequence_number(
        &self,
        lost_events: u64) -> Option<u32> {
        if lost_events == 0 {
            /*
             * Preserve the previous zero-loss representation: an empty
             * sequence-point thread list.
             */
            None
        } else {
            /*
             * If N events from the final block are present and L were lost,
             * reporting N + L makes readers infer exactly L missing sequence
             * numbers. Nettrace sequence numbers are 32-bit and wrap, but
             * readers report loss as a signed 32-bit count. Clamp larger
             * aggregates so a full 32-bit wrap cannot appear as zero loss.
             */
            let lost_events = lost_events.min(i32::MAX as u64) as u32;

            Some(self.last_event_count.wrapping_add(lost_events))
        }
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
    use protobuf::CodedInputStream;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(
        name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after unix epoch")
            .as_nanos();

        std::env::temp_dir().join(
            format!("one-collect-{name}-{nanos}.nettrace"))
    }

    fn blocks(data: &[u8]) -> Vec<(u8, &[u8])> {
        assert_eq!(&data[..8], b"Nettrace");
        let mut offset = 20;
        let mut result = Vec::new();
        while offset < data.len() {
            let header = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let size = (header & 0x00FF_FFFF) as usize;
            result.push(((header >> 24) as u8, &data[offset..offset + size]));
            offset += size;
        }
        assert_eq!(offset, data.len());
        result
    }

    fn read_u16(input: &mut CodedInputStream<'_>) -> usize {
        let low = input.read_raw_byte().unwrap();
        let high = input.read_raw_byte().unwrap();
        u16::from_le_bytes([low, high]) as usize
    }

    #[test]
    fn short_utf8_lengths_are_checked_in_bytes() {
        for value in [String::new(), "a".repeat(65535), "\u{00e9}".repeat(32767)] {
            let mut buffer = Vec::new();
            buffer.write_short_utf8(&value).unwrap();
            let mut input = CodedInputStream::from_bytes(&buffer);
            assert_eq!(read_u16(&mut input), value.len());
            assert_eq!(input.read_raw_bytes(value.len() as u32).unwrap(), value.as_bytes());
            assert!(input.eof().unwrap());
        }
        for value in ["a".repeat(65536), "\u{00e9}".repeat(32768)] {
            let mut buffer = vec![42];
            let error = buffer.write_short_utf8(&value).unwrap_err();
            assert!(error.to_string().contains("16-bit length limit"));
            assert_eq!(buffer, vec![42]);
        }
    }

    #[test]
    fn metadata_lengths_are_checked_before_writing() {
        let path = unique_temp_path("metadata-lengths");
        let mut writer = NetTraceWriter::new(path.to_str().unwrap()).unwrap();
        let mut start = writer.write_start_block().unwrap();
        writer.output.write_u16(0).unwrap();
        writer.write_event_metadata(&mut start, 1, "", 1, &"a".repeat(65525), &[]).unwrap();
        let pos = writer.get_pos().unwrap();
        assert_eq!(pos, 20 + 4 + 2 + 2 + 65535);
        let error = writer.write_event_metadata(&mut start, 1, "", 1, &"a".repeat(65526), &[]).unwrap_err();
        assert!(error.to_string().contains("metadata row exceeds"));
        assert_eq!(writer.get_pos().unwrap(), pos);

        let name = "a".repeat(65532);
        let field = NetTraceField { type_id: TYPE_ID_BYTE, element_type_id: None, name: &name };
        let error = writer.write_event_metadata(&mut start, 1, "", 1, "", &[field]).unwrap_err();
        assert!(error.to_string().contains("field description exceeds"));
        assert_eq!(writer.get_pos().unwrap(), pos);

        let fields: Vec<_> = (0..65536).map(|_| NetTraceField {
            type_id: TYPE_ID_BYTE, element_type_id: None, name: "",
        }).collect();
        let error = writer.write_event_metadata(&mut start, 1, "", 1, "", &fields).unwrap_err();
        assert!(error.to_string().contains("field count limit"));
        assert_eq!(writer.get_pos().unwrap(), pos);

        let field = NetTraceField { type_id: TYPE_ID_ARRAY, element_type_id: None, name: "unknown" };
        let error = writer.write_event_metadata(&mut start, 1, "", 1, "", &[field]).unwrap_err();
        assert!(error.to_string().contains("no supported element type"));
        assert_eq!(writer.get_pos().unwrap(), pos);
        drop(writer);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn metadata_spans_blocks_without_resetting_ids() {
        let path = unique_temp_path("metadata-blocks");
        let mut writer = NetTraceWriter::new(path.to_str().unwrap()).unwrap();
        let kinds = vec!["a".repeat(60000); 600];
        writer.write_metadata_object(&kinds, &[]).unwrap();
        drop(writer);
        let data = std::fs::read(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut next_id = 1;
        let mut count = 0;
        for (kind, payload) in blocks(&data) {
            assert_eq!(kind, 3);
            assert!(payload.len() <= MAX_BLOCK_SIZE);
            let mut input = CodedInputStream::from_bytes(payload);
            assert_eq!(read_u16(&mut input), 0);
            while !input.eof().unwrap() {
                let size = read_u16(&mut input);
                let row = input.read_raw_bytes(size as u32).unwrap();
                let mut row = CodedInputStream::from_bytes(&row);
                assert_eq!(row.read_raw_varint32().unwrap(), next_id);
                if next_id <= 600 {
                    assert_eq!(row.read_string().unwrap(), "Universal.Events");
                    assert_eq!(row.read_raw_varint32().unwrap(), next_id);
                    assert_eq!(row.read_string().unwrap(), kinds[(next_id - 1) as usize]);
                }
                next_id += 1;
            }
            count += 1;
        }
        assert_eq!(count, 3);
        assert_eq!(next_id, 607);
    }

    #[test]
    fn label_lists_span_blocks_without_resetting_ids() {
        let path = unique_temp_path("label-blocks");
        let mut writer = NetTraceWriter::new(path.to_str().unwrap()).unwrap();
        let mut machine = ExportMachine::new(ExportSettings::default());
        let value = "a".repeat(60000);
        let label = machine.label_attribute("key", &value);
        for i in 0..600 {
            let mut attributes = ExportAttributes::default();
            attributes.push(label);
            let attributes_id = machine.push_unique_attributes(attributes);
            writer.saved_labels.insert(SavedLabelKey { attributes_id, write_id: 0 }, i);
        }
        writer.write_labels(&machine).unwrap();
        assert!(writer.saved_labels.is_empty());
        drop(writer);
        let data = std::fs::read(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut next_id = 1;
        let rows = blocks(&data);
        assert_eq!(rows.len(), 3);
        for (kind, payload) in rows {
            assert_eq!(kind, 8);
            let mut input = CodedInputStream::from_bytes(payload);
            assert_eq!(input.read_raw_little_endian32().unwrap(), next_id);
            let count = input.read_raw_little_endian32().unwrap();
            assert!(count > 0);
            for _ in 0..count {
                assert_eq!(input.read_raw_byte().unwrap(), 128 | 5);
                assert_eq!(input.read_string().unwrap(), "key");
                assert_eq!(input.read_string().unwrap(), value);
                next_id += 1;
            }
            assert!(input.eof().unwrap());
        }
        assert_eq!(next_id, 601);
    }

    #[test]
    fn oversized_label_list_is_rejected() {
        let path = unique_temp_path("oversized-label");
        let mut writer = NetTraceWriter::new(path.to_str().unwrap()).unwrap();
        let mut machine = ExportMachine::new(ExportSettings::default());
        let mut attributes = ExportAttributes::default();
        attributes.push(machine.label_attribute("key", &"a".repeat(MAX_BLOCK_SIZE)));
        let attributes_id = machine.push_unique_attributes(attributes);
        writer.saved_labels.insert(SavedLabelKey { attributes_id, write_id: 0 }, 0);
        let error = writer.write_labels(&machine).unwrap_err();
        assert!(error.to_string().contains("label list exceeds the 24-bit block size limit"));
        drop(writer);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn threads_span_blocks_without_changing_indices() {
        let path = unique_temp_path("thread-blocks");
        let mut writer = NetTraceWriter::new(path.to_str().unwrap()).unwrap();
        let count = 1_100_000u32;
        for id in 1..=count {
            writer.saved_pid_tids.insert(
                SavedPidTidKey { pid: u32::MAX - id, tid: u32::MAX - id }, id);
        }
        writer.write_threads().unwrap();
        assert_eq!(writer.saved_pid_tids.len(), 1);
        assert_eq!(writer.saved_pid_tids[&SavedPidTidKey { pid: 0, tid: 0 }], 0);
        drop(writer);
        let data = std::fs::read(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let rows = blocks(&data);
        assert_eq!(rows.len(), 2);
        let mut seen = vec![false; count as usize + 1];
        for (kind, payload) in rows {
            assert_eq!(kind, 6);
            assert!(payload.len() <= MAX_BLOCK_SIZE);
            let mut input = CodedInputStream::from_bytes(payload);
            while !input.eof().unwrap() {
                let size = read_u16(&mut input);
                let row = input.read_raw_bytes(size as u32).unwrap();
                let mut row = CodedInputStream::from_bytes(&row);
                let id = row.read_raw_varint32().unwrap();
                assert!(!seen[id as usize]);
                seen[id as usize] = true;
                let expected = if id == 0 { 0 } else { u32::MAX - id };
                assert_eq!(row.read_raw_byte().unwrap(), 2);
                assert_eq!(row.read_raw_varint32().unwrap(), expected);
                assert_eq!(row.read_raw_byte().unwrap(), 3);
                assert_eq!(row.read_raw_varint32().unwrap(), expected);
                assert!(row.eof().unwrap());
            }
        }
        assert!(seen.into_iter().all(|value| value));
    }

    #[test]
    fn system_event_string_schemas_match_payloads() {
        let path = unique_temp_path("system-schemas");
        let mut writer = NetTraceWriter::new(path.to_str().unwrap()).unwrap();
        writer.write_metadata_object(&[], &[]).unwrap();
        let mut machine = ExportMachine::new(ExportSettings::default());
        machine.add_sample(1, MetricValue::Count(1), 1, 1, 0, 0, &[]).unwrap();
        let name = "module-\u{00e9}.so";
        let mapping = ExportMapping::new(
            1, machine.intern(name), 0x1000, 0x2000, 0, false, 7,
            crate::ruwind::UnwindType::DWARF);
        let replay = machine.find_process(1).unwrap().to_replay();
        writer.write_mapping_replay_event(&machine, &replay, &mapping).unwrap();
        let mut expected = vec![7, 0x80, 0x20, 0x80, 0x40, 0];
        expected.extend_from_slice(&(name.len() as u16).to_le_bytes());
        expected.extend_from_slice(name.as_bytes());
        expected.push(0); // No mapping metadata.
        assert_eq!(writer.buffer, expected);
        writer.output.flush().unwrap();
        drop(writer);

        let data = std::fs::read(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let rows = blocks(&data);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, 3);
        let mut input = CodedInputStream::from_bytes(rows[0].1);
        assert_eq!(read_u16(&mut input), 0);
        let mut string_fields = 0;
        while !input.eof().unwrap() {
            let size = read_u16(&mut input);
            let row = input.read_raw_bytes(size as u32).unwrap();
            let mut row = CodedInputStream::from_bytes(&row);
            row.read_raw_varint32().unwrap();
            assert_eq!(row.read_string().unwrap(), "Universal.System");
            row.read_raw_varint32().unwrap();
            row.read_string().unwrap();
            let count = read_u16(&mut row);
            for _ in 0..count {
                let size = read_u16(&mut row);
                let field = row.read_raw_bytes(size as u32).unwrap();
                let mut field = CodedInputStream::from_bytes(&field);
                let name = field.read_string().unwrap();
                let type_id = field.read_raw_byte().unwrap();
                if matches!(name.as_str(),
                    "Name" | "NamespaceName" | "FileName" | "SymbolMetadata" | "VersionMetadata") {
                    assert_eq!(type_id, 19);
                    assert_eq!(field.read_raw_byte().unwrap(), 23);
                    string_fields += 1;
                } else {
                    assert_eq!(type_id, 21);
                }
                assert!(field.eof().unwrap());
            }
            assert_eq!(read_u16(&mut row), 0);
            assert!(row.eof().unwrap());
        }
        assert_eq!(string_fields, 8);
    }

    fn final_sequence_point(
        path: &PathBuf) -> (u32, Option<(u64, u32)>) {
        let data = std::fs::read(path).unwrap();
        let mut offset = 20;
        let mut result = None;

        while offset + 4 <= data.len() {
            let header = u32::from_le_bytes(
                data[offset..offset + 4].try_into().unwrap());
            offset += 4;

            let size = (header & 0x00FF_FFFF) as usize;
            let kind = (header >> 24) as u8;

            if kind == 0 {
                break;
            }

            if kind == 4 {
                let payload = &data[offset..offset + size];
                let flags = u32::from_le_bytes(
                    payload[8..12].try_into().unwrap());
                let thread_count = u32::from_le_bytes(
                    payload[12..16].try_into().unwrap());
                let entry = if thread_count == 0 {
                    None
                } else {
                    let mut input = CodedInputStream::from_bytes(
                        &payload[16..]);
                    let thread_index =
                        input.read_raw_varint64().unwrap();
                    let sequence_number =
                        input.read_raw_varint32().unwrap();

                    Some((thread_index, sequence_number))
                };

                result = Some((flags, entry));
            }

            offset += size;
        }

        result.expect("Expected a sequence point")
    }

    fn write_loss_trace(
        name: &str,
        emitted_events: u32,
        lost_events: u64) -> (PathBuf, (u32, Option<(u64, u32)>)) {
        let path = unique_temp_path(name);
        let mut writer = NetTraceWriter::new(
            path.to_str().unwrap()).unwrap();
        let machine = ExportMachine::new(ExportSettings::default());

        writer.last_event_count = emitted_events;
        machine.add_lost_events(lost_events);
        writer.finish(&machine).unwrap();
        drop(writer);

        let sequence_point = final_sequence_point(&path);
        (path, sequence_point)
    }

    fn check_callstack_blocks(
        depths: &[usize]) -> Vec<(usize, u32)> {
        let path = unique_temp_path("stack-blocks");
        let mut writer = NetTraceWriter::new(
            path.to_str().unwrap()).unwrap();
        let mut machine = ExportMachine::new(ExportSettings::default());

        for (i, depth) in depths.iter().enumerate() {
            let mut frames = vec![0x1000; *depth];
            frames[0] = 0x10000 + i as u64;
            let sample = machine.make_sample(
                1, MetricValue::Count(1), 1, 0, 0, &frames);

            writer.saved_callstacks.insert(
                SavedCallstackKey {
                    ip: sample.ip(),
                    sample_id: sample.callstack_id() as u32,
                    write_id: 0,
                },
                i as u32);
        }

        writer.write_callstacks(&machine).unwrap();
        assert!(writer.saved_callstacks.is_empty());
        writer.output.flush().unwrap();
        drop(writer);

        let data = std::fs::read(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut offset = 20;
        let mut next_stack = 0;
        let mut blocks = Vec::new();

        while offset < data.len() {
            let header = u32::from_le_bytes(
                data[offset..offset + 4].try_into().unwrap());
            assert_eq!(header >> 24, 5);
            let size = (header & 0x00FF_FFFF) as usize;
            offset += 4;
            let end = offset + size;
            let first_id = u32::from_le_bytes(
                data[offset..offset + 4].try_into().unwrap());
            let count = u32::from_le_bytes(
                data[offset + 4..offset + 8].try_into().unwrap());
            assert_eq!(first_id, next_stack as u32 + 1);
            offset += 8;

            for _ in 0..count {
                let stack_size = u32::from_le_bytes(
                    data[offset..offset + 4].try_into().unwrap()) as usize;
                assert_eq!(stack_size, depths[next_stack] * 8);
                offset += 4;
                assert!(offset + stack_size <= end);
                let ip = u64::from_le_bytes(
                    data[offset..offset + 8].try_into().unwrap());
                assert_eq!(ip, 0x10000 + next_stack as u64);

                for frame in data[offset + 8..offset + stack_size].chunks_exact(8) {
                    assert_eq!(u64::from_le_bytes(frame.try_into().unwrap()), 0x1000);
                }

                offset += stack_size;
                next_stack += 1;
            }

            assert_eq!(offset, end);
            blocks.push((size, count));
        }

        assert_eq!(next_stack, depths.len());
        blocks
    }

    #[test]
    fn empty_callstack_block() {
        assert_eq!(check_callstack_blocks(&[]), vec![(8, 0)]);
    }

    #[test]
    fn callstacks_fit_in_one_block() {
        assert_eq!(
            check_callstack_blocks(&[1, 2, 126]),
            vec![(8 + 12 + 20 + 1012, 3)]);
    }

    #[test]
    fn callstacks_split_at_block_size_limit() {
        // Fill a block to 0xFFFFFC bytes, the largest possible stack payload.
        let mut depths = vec![126; 16578];
        depths.push(33);
        depths.push(1);

        assert_eq!(
            check_callstack_blocks(&depths),
            vec![(0x00FF_FFFC, 16579), (20, 1)]);
    }

    #[test]
    fn callstacks_span_multiple_blocks() {
        let blocks = check_callstack_blocks(&vec![126; 35427]);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0], (8 + 16578 * 1012, 16578));
        assert_eq!(blocks[1], blocks[0]);
        assert_eq!(blocks[2], (8 + (35427 - 2 * 16578) * 1012, 2271));
    }

    #[test]
    fn oversized_callstack_is_rejected() {
        let path = unique_temp_path("oversized-stack");
        let mut writer = NetTraceWriter::new(
            path.to_str().unwrap()).unwrap();
        let mut machine = ExportMachine::new(ExportSettings::default());
        let frames = vec![0x1000; MAX_BLOCK_SIZE / 8];
        let sample = machine.make_sample(
            1, MetricValue::Count(1), 1, 0, 0, &frames);
        writer.saved_callstacks.insert(
            SavedCallstackKey {
                ip: sample.ip(),
                sample_id: sample.callstack_id() as u32,
                write_id: 0,
            },
            0);

        let error = writer.write_callstacks(&machine).unwrap_err();
        assert!(error.to_string().contains("callstack exceeds the 24-bit block size limit"));
        drop(writer);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn block_size_limit_is_enforced() {
        for size in [MAX_BLOCK_SIZE - 1, MAX_BLOCK_SIZE, MAX_BLOCK_SIZE + 1] {
            let path = unique_temp_path("block-limit");
            let mut writer = NetTraceWriter::new(
                path.to_str().unwrap()).unwrap();
            let start = writer.write_start_block().unwrap();
            writer.output.seek(SeekFrom::Current(size as i64 - 1)).unwrap();
            writer.output.write_u8(0).unwrap();
            let result = writer.write_end_block(start, 5);

            if size <= MAX_BLOCK_SIZE {
                result.unwrap();
                let data = std::fs::read(&path).unwrap();
                let header = u32::from_le_bytes(data[20..24].try_into().unwrap());
                assert_eq!(header, (5 << 24) | size as u32);
            } else {
                assert!(result.unwrap_err().to_string().contains("exceeds the 24-bit size limit"));
            }

            drop(writer);
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn final_sequence_point_omits_zero_loss() {
        let (path, sequence_point) =
            write_loss_trace("zero-loss", 10, 0);

        assert_eq!((1, None), sequence_point);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn final_sequence_point_reports_loss_after_events() {
        let path = unique_temp_path("event-loss");
        let mut writer = NetTraceWriter::new(
            path.to_str().unwrap()).unwrap();
        let mut machine = ExportMachine::new(ExportSettings::default());
        let kind = machine.sample_kind("test");

        machine.add_sample(
            1,
            MetricValue::Count(1),
            1,
            1,
            0,
            kind,
            &[]).unwrap();
        machine.add_lost_events(7);

        writer.write_metadata_object(
            machine.sample_kinds(),
            machine.record_types()).unwrap();

        let process = machine.find_process(1).unwrap();
        let replay = process.to_replay();
        let converter = DefaultExportGraphMetricValueConverter::default();

        writer.write_replay_event(
            &machine,
            &replay,
            &converter).unwrap();
        writer.finish(&machine).unwrap();
        drop(writer);

        assert_eq!(
            (1, Some((0, 8))),
            final_sequence_point(&path));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn final_sequence_point_reports_loss_after_multiple_event_blocks() {
        let path = unique_temp_path("multi-block-loss");
        let mut writer = NetTraceWriter::new(
            path.to_str().unwrap()).unwrap();
        let mut machine = ExportMachine::new(ExportSettings::default());
        let kind = machine.sample_kind("test");

        machine.add_sample(
            1,
            MetricValue::Count(1),
            1,
            1,
            0,
            kind,
            &[]).unwrap();

        writer.write_metadata_object(
            machine.sample_kinds(),
            machine.record_types()).unwrap();

        let process = machine.find_process(1).unwrap();
        let replay = process.to_replay();
        let converter = DefaultExportGraphMetricValueConverter::default();

        writer.write_replay_event(
            &machine,
            &replay,
            &converter).unwrap();
        writer.flush_event_block(
            &machine,
            writer.flush_time,
            writer.last_time).unwrap();

        writer.write_replay_event(
            &machine,
            &replay,
            &converter).unwrap();
        machine.add_lost_events(7);
        writer.finish(&machine).unwrap();
        drop(writer);

        assert_eq!(
            (1, Some((0, 8))),
            final_sequence_point(&path));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn final_sequence_point_reports_loss_without_events() {
        let (path, sequence_point) =
            write_loss_trace("loss-only", 0, 7);

        assert_eq!((1, Some((0, 7))), sequence_point);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn final_sequence_point_wraps_sequence_number() {
        let (path, sequence_point) =
            write_loss_trace("loss-wrap", u32::MAX, 2);

        assert_eq!((1, Some((0, 1))), sequence_point);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn final_sequence_point_clamps_unrepresentable_loss() {
        let (path, sequence_point) =
            write_loss_trace("loss-clamp", 10, u64::MAX);

        assert_eq!(
            (1, Some((0, 10u32.wrapping_add(i32::MAX as u32)))),
            sequence_point);

        std::fs::remove_file(path).unwrap();
    }

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
