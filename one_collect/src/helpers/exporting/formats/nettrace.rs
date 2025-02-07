use std::fs::File;
use std::io::{Seek, SeekFrom, Write, BufWriter};

use chrono::{DateTime, Datelike, Timelike, Utc};

use crate::helpers::exporting::*;

pub trait NetTraceFormat {
    fn to_net_trace(
        &mut self,
        predicate: impl Fn(&ExportProcess) -> bool,
        path: &str) -> anyhow::Result<()>;
}

struct NetTraceField {
    type_id: u32,
    name: &'static str,
}

const TYPE_ID_UINT32: u32 = 10;
const TYPE_ID_UINT64: u32 = 12;
const TYPE_ID_STRING: u32 = 18;

const VALUE_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UINT64,
    name: "Value",
};

const ID_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UINT32,
    name: "Id",
};

const NAME_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_STRING,
    name: "Name",
};

const NAMESPACE_NAME_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_STRING,
    name: "NamespaceName",
};

const FILE_NAME_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_STRING,
    name: "FileName",
};

const SYMBOL_INDEX_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_STRING,
    name: "SymbolIndex",
};

const PROCESS_ID_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UINT32,
    name: "ProcessId",
};

const NAMESPACE_ID_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UINT32,
    name: "NamespaceId",
};

const MAPPING_ID_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UINT32,
    name: "MappingId",
};

const START_ADDRESS_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UINT64,
    name: "StartAddress",
};

const END_ADDRESS_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UINT64,
    name: "EndAddress",
};

const FILE_OFFSET_FIELD: NetTraceField = NetTraceField {
    type_id: TYPE_ID_UINT64,
    name: "FileOffset",
};

const STACK_EVENT_FIELDS: [NetTraceField; 1] = [VALUE_FIELD];

const PROCESS_CREATE_FIELDS: [NetTraceField; 4] = [
    ID_FIELD,
    NAMESPACE_ID_FIELD,
    NAME_FIELD,
    NAMESPACE_NAME_FIELD,
];

const PROCESS_EXIT_FIELDS: [NetTraceField; 1] = [PROCESS_ID_FIELD];

const PROCESS_MAPPING_FIELDS: [NetTraceField; 7] = [
    ID_FIELD,
    PROCESS_ID_FIELD,
    START_ADDRESS_FIELD,
    END_ADDRESS_FIELD,
    FILE_OFFSET_FIELD,
    FILE_NAME_FIELD,
    SYMBOL_INDEX_FIELD,
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

    fn write_utf8(
        &mut self,
        value: &str) -> anyhow::Result<()> {
        let bytes = value.as_bytes();
        self.write_u32(value.len() as u32)?;
        self.write_bytes(bytes)
    }

    fn write_unicode_with_null(
        &mut self,
        value: &str) -> anyhow::Result<()> {
        for c in value.chars() {
            self.write_u16(c as u16)?;
        }

        self.write_u16(0)
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
    buffer: Vec<u8>,
    existing_event_id: u32,
    create_event_id: u32,
    exit_event_id: u32,
    mapping_event_id: u32,
    symbol_event_id: u32,
    last_time: u64,
    sync_time: u64,
    name_buffer: String,
    sym_id: u32,
}

impl NetTraceWriter {
    fn new(path: &str) -> anyhow::Result<Self> {
        let mut trace = Self {
            output: BufWriter::new(File::create(path)?),
            buffer: Vec::new(),
            existing_event_id: 0,
            create_event_id: 0,
            exit_event_id: 0,
            mapping_event_id: 0,
            symbol_event_id: 0,
            last_time: 0,
            sync_time: 0,
            name_buffer: String::new(),
            sym_id: 0,
        };

        trace.init()?;

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

    fn align_to_u32(&mut self) -> anyhow::Result<u64> {
        let pos = self.get_pos()?;
        let align = pos & 3;

        /* Already aligned */
        if align == 0 {
            return Ok(0);
        }

        let padding = 4 - align;

        for _ in 0..padding {
            self.output.write_u8(0)?;
        }

        Ok(padding)
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

    fn reserve_object_size(&mut self) -> anyhow::Result<(u64, u64)> {
        let loc = self.reserve_u32()?;
        let pad = self.align_to_u32()?;

        Ok((loc, pad))
    }

    fn update_object_size(
        &mut self,
        loc: u64,
        pad: u64) -> anyhow::Result<()> {
        let total_size = self.get_pos()? - loc - pad;
        self.update_u32(total_size as u32, loc)
    }

    fn write_start_object(
        &mut self,
        version: u32,
        min_version: u32,
        name: &str) -> anyhow::Result<()> {
        self.write_tag(5)?; /* BeginObj: Root */
        self.write_tag(5)?; /* BeginObj: Type */
        self.write_tag(1)?; /* NullRef */
        self.output.write_u32(version)?; /* Version */
        self.output.write_u32(min_version)?; /* Min Version */
        self.output.write_utf8(name)?; /* Name */
        self.write_tag(6) /* EndObj: Type */
    }

    fn write_end_object(
        &mut self) -> anyhow::Result<()> {
        self.write_tag(6)
    }

    fn write_tag(
        &mut self,
        kind: u8) -> anyhow::Result<()> {
        self.output.write_u8(kind)
    }

    fn write_event_metadata(
        &mut self,
        meta_id: u32,
        provider: &str,
        event_id: u32,
        event_name: &str,
        keywords: u64,
        version: u32,
        level: u32,
        fields: &[NetTraceField]) -> anyhow::Result<()> {
        /* Write payload */
        self.buffer.clear();
        self.buffer.write_u32(meta_id)?;
        self.buffer.write_unicode_with_null(provider)?;
        self.buffer.write_u32(event_id)?;
        self.buffer.write_unicode_with_null(event_name)?;
        self.buffer.write_u64(keywords)?;
        self.buffer.write_u32(version)?;
        self.buffer.write_u32(level)?;
        self.buffer.write_u32(fields.len() as u32)?;

        for field in fields {
            self.buffer.write_u32(field.type_id)?;
            self.buffer.write_unicode_with_null(field.name)?;
        }

        let payload = self.buffer.as_slice();

        self.output.write_u8(128)?; /* Flags: PayloadSize */
        self.output.write_varint(self.sync_time)?; /* Timestamp */
        self.output.write_varint(payload.len() as u64)?; /* PayloadSize */
        self.output.write_bytes(payload)
    }

    fn write_eventblock_start(
        &mut self) -> anyhow::Result<(u64,u64)> {
        self.write_start_object(2, 2, "EventBlock")?;
        let (loc, pad) = self.reserve_object_size()?;

        /* Header */
        self.output.write_u16(20)?; /* HeaderSize */
        self.output.write_u16(1)?; /* Flags: Compressed */
        self.output.write_u64(self.sync_time)?; /* Min timestamp */
        self.output.write_u64(u64::MAX)?; /* Max timestamp */

        Ok((loc, pad))
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

        self.output.write_varint(delta)
    }

    fn write_event_blob_from_buffer(
        &mut self,
        meta_id: u32,
        cpu: u32,
        thread_id: u32,
        stack_id: Option<u32>,
        time: u64) -> anyhow::Result<()> {
        if stack_id.is_some() {
            self.output.write_u8(207)?; /* Flags: 1 | 2 | 4 | 8 | 64 | 128 */
        } else {
            self.output.write_u8(199)?; /* Flags: 1 | 2 | 4 | 64 | 128 */
        }
        self.output.write_varint(meta_id as u64)?; /* MetaID */
        self.output.write_varint(0u64)?; /* SeqID inc */
        self.output.write_varint(thread_id as u64)?; /* Capture Thread ID */
        self.output.write_varint(cpu as u64)?; /* Processor Number */
        self.output.write_varint(thread_id as u64)?; /* Thread ID */

        if let Some(stack_id) = stack_id {
            self.output.write_varint(stack_id as u64)?; /* Stack ID */
        }

        self.write_event_timestamp(time)?;

        let payload = self.buffer.as_slice();

        self.output.write_varint(payload.len() as u64)?; /* Payload Size */
        self.output.write_bytes(payload)
    }

    fn write_eventblock_end(
        &mut self,
        loc: u64,
        pad: u64) -> anyhow::Result<()> {
        self.update_object_size(loc, pad)?;
        self.write_end_object()
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
        self.buffer.write_u32(process.pid())?;
        self.buffer.write_u32(ns_pid)?;
        self.buffer.write_unicode_with_null(name)?;

        /* TODO: Once we have namespace names */
        self.buffer.write_unicode_with_null("Unknown")?;

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
            id,
            0,
            0,
            None,
            replay.time())
    }

    fn write_exited_replay_event(
        &mut self,
        replay: &ExportProcessReplay) -> anyhow::Result<()> {
        let process = replay.process();

        self.buffer.clear();
        self.buffer.write_u32(process.pid())?;

        self.write_event_blob_from_buffer(
            self.exit_event_id,
            0,
            0,
            None,
            replay.time())
    }

    fn write_mapping_replay_event(
        &mut self,
        machine: &ExportMachine,
        replay: &ExportProcessReplay,
        mapping: &ExportMapping) -> anyhow::Result<()> {
        let process = replay.process();

        let name = match machine.strings().from_id(mapping.filename_id()) {
            Ok(name) => { name },
            Err(_) => { "Unknown" },
        };

        let sym_index = match machine.get_mapping_metadata(mapping) {
            Some(metadata) => {
                use std::fmt::Write;

                self.name_buffer.clear();

                match metadata {
                    ModuleMetadata::Elf(elf) => {
                        self.name_buffer.push_str("elf:");

                        if let Some(build_id) = elf.build_id() {
                            for b in build_id {
                                write!(self.name_buffer, "{:02x}", b)?;
                            }
                        }

                        self.name_buffer.push_str(":");

                        if let Some(debug_link) = elf.debug_link(machine.strings()) {
                            self.name_buffer.push_str(debug_link);
                        }
                    },

                    ModuleMetadata::PE(pe) => {
                        self.name_buffer.push_str("pe:");

                        if let Some(name) = pe.symbol_name(machine.strings()) {
                            self.name_buffer.push_str(name);
                        }

                        self.name_buffer.push_str(":");
                        write!(self.name_buffer, "{}", pe.symbol_age())?;

                        self.name_buffer.push_str(":");
                        for b in pe.symbol_sig() {
                            write!(self.name_buffer, "{:02x}", b)?;
                        }

                        self.name_buffer.push_str(":");

                        if let Some(version) = pe.version_name(machine.strings()) {
                            self.name_buffer.push_str(version);
                        }
                    },
                }

                &self.name_buffer
            },

            None => { "" },
        };

        self.buffer.clear();
        self.buffer.write_u32(mapping.id() as u32)?;
        self.buffer.write_u32(process.pid())?;
        self.buffer.write_u64(mapping.start())?;
        self.buffer.write_u64(mapping.end())?;
        self.buffer.write_u64(mapping.file_offset())?;
        self.buffer.write_unicode_with_null(name)?;
        self.buffer.write_unicode_with_null(sym_index)?;

        self.write_event_blob_from_buffer(
            self.mapping_event_id,
            0,
            0,
            None,
            replay.time())
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
        self.buffer.write_u32(self.sym_id)?;
        self.buffer.write_u32(mapping.id() as u32)?;
        self.buffer.write_u64(symbol.start())?;
        self.buffer.write_u64(symbol.end())?;
        self.buffer.write_unicode_with_null(name)?;

        self.sym_id += 1;

        self.write_event_blob_from_buffer(
            self.symbol_event_id,
            0,
            0,
            None,
            replay.time())
    }

    fn write_replay_event(
        &mut self,
        machine: &ExportMachine,
        replay: &ExportProcessReplay) -> anyhow::Result<()> {
        if replay.created_event() {
            self.write_created_replay_event(machine, replay)?;
        }

        if replay.exited_event() {
            self.write_exited_replay_event(replay)?;
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

    fn write_metadata_object(
        &mut self,
        stack_kinds: &[String]) -> anyhow::Result<()> {
        self.write_start_object(2, 2, "MetadataBlock")?;
        let (loc, pad) = self.reserve_object_size()?;

        /* Header */
        self.output.write_u16(20)?; /* HeaderSize */
        self.output.write_u16(1)?; /* Flags: Compressed */
        self.output.write_u64(self.sync_time)?; /* Min timestamp */
        self.output.write_u64(u64::MAX)?; /* Max timestamp */

        let mut meta_id = 0;

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
                0,
                0,
                0,
                &STACK_EVENT_FIELDS)?;

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
            0,
            0,
            0,
            &PROCESS_CREATE_FIELDS)?;

        meta_id += 1;

        self.create_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            1, /* Stable ID */
            "ProcessCreate",
            0,
            0,
            0,
            &PROCESS_CREATE_FIELDS)?;

        meta_id += 1;

        self.exit_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            2, /* Stable ID */
            "ProcessExit",
            0,
            0,
            0,
            &PROCESS_EXIT_FIELDS)?;

        meta_id += 1;

        self.mapping_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            3, /* Stable ID */
            "ProcessMapping",
            0,
            0,
            0,
            &PROCESS_MAPPING_FIELDS)?;

        meta_id += 1;

        self.symbol_event_id = meta_id;

        self.write_event_metadata(
            meta_id,
            "Universal.System",
            4, /* Stable ID */
            "ProcessSymbol",
            0,
            0,
            0,
            &PROCESS_SYMBOL_FIELDS)?;

        /* Done writing metadata */
        self.update_object_size(loc, pad)?;
        self.write_end_object()
    }

    fn write_trace_object(
        &mut self,
        sync_time: DateTime<Utc>,
        sync_time_qpc: u64,
        qpc_freq: u64,
        process_id: u32,
        num_of_cpus: u32,
        sample_freq: u32) -> anyhow::Result<()> {
        /* Conversions to match trace format */
        let nanos_between_samples = 1000000000 / sample_freq;
        let milli_secs = sync_time.nanosecond() / 1000000;
        let ptr_size = 8;

        self.sync_time = sync_time_qpc;

        self.write_start_object(4, 4, "Trace")?;
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
        self.output.write_u32(process_id)?;
        self.output.write_u32(num_of_cpus)?;
        self.output.write_u32(nanos_between_samples)?;
        self.write_end_object()
    }

    fn init(&mut self) -> anyhow::Result<()> {
        self.output.write(b"Nettrace")?;
        self.output.write_utf8("!FastSerialization.1")
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        self.write_tag(1)?; /* NullRef */

        Ok(self.output.flush()?)
    }
}

impl NetTraceFormat for ExportMachine {
    fn to_net_trace(
        &mut self,
        predicate: impl Fn(&ExportProcess) -> bool,
        path: &str) -> anyhow::Result<()> {
        let sync_time = match self.start_date() {
            Some(value) => { value },
            None => { anyhow::bail!("No start date saved, invoke mark_start()."); },
        };

        let sync_time_qpc = match self.start_qpc() {
            Some(value) => { value },
            None => { anyhow::bail!("No start qpc saved, invoke mark_start()."); },
        };

        let qpc_freq = self.qpc_freq();
        let cpu_count = self.cpu_count();
        let sample_freq = self.settings().cpu_freq() as u32;

        let mut writer = NetTraceWriter::new(path)?;

        writer.write_trace_object(
            sync_time,
            sync_time_qpc,
            qpc_freq,
            0,
            cpu_count,
            sample_freq)?;

        writer.write_metadata_object(self.sample_kinds())?;

        let (loc, pad) = writer.write_eventblock_start()?;

        self.replay_by_time(
            predicate,
            |machine, replay| {
                writer.write_replay_event(machine, replay)
            })?;

        writer.write_eventblock_end(loc, pad)?;

        writer.finish()?;

        Ok(())
    }
}
