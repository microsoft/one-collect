// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

#[cfg(not(target_os = "linux"))]
struct UnixStream {}

use std::io::{Read, BufRead, BufReader, Write};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::collections::{HashSet, HashMap};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crate::helpers::dotnet::*;
use crate::helpers::dotnet::universal::UniversalDotNetHelperOSHooks;
use crate::helpers::exporting::{UniversalExporter, ExportSettings, ExportTraceContext};
use crate::helpers::exporting::process::MetricValue;
use crate::helpers::exporting::record::ExportRecordType;

use crate::intern::InternedStrings;
use crate::user_events::*;
use crate::tracefs::*;
use crate::perf_event::*;
use crate::openat::OpenAt;
use crate::Writable;
use crate::procfs;
use crate::event::*;

use crate::helpers::dotnet::scripting::*;
use crate::helpers::dotnet::nettrace;

use tracing::{warn, info, debug};

#[cfg(target_os = "linux")]
use libc::PROT_EXEC;

#[cfg(not(target_os = "linux"))]
const PROT_EXEC: i32 = 0;

struct PerfMapContext {
    tmp: OpenAt,
    pid: u32,
    nspid: u32,
}

impl PerfMapContext {
    fn new(
        pid: u32,
        nspid: u32) -> anyhow::Result<Self> {
        let path = format!("/proc/{}/root/tmp", pid);

        let tmp = File::open(&path)?;

        let new = Self {
            tmp: OpenAt::new(tmp),
            pid,
            nspid,
        };

        Ok(new)
    }

    fn open_diag_socket(&self) -> Option<UnixStream> {
        let wanted = format!("dotnet-diagnostic-{}-", self.nspid);

        match self.tmp.find(Path::new("."), &wanted) {
            Some(paths) => {
                for path in paths {
                    let path = format!("/proc/{}/root/tmp/{}", self.pid, path);
                    if let Ok(sock) = UnixStream::connect(path) {
                        debug!("Opened diagnostic socket: pid={}, nspid={}", self.pid, self.nspid);
                        return Some(sock);
                    }
                }
            },
            None => { },
        }

        warn!("Failed to open diagnostic socket: pid={}, nspid={}", self.pid, self.nspid);
        None
    }

    fn has_perf_map_environ(&self) -> anyhow::Result<bool> {
        let path = format!("/proc/{}/environ", self.pid);
        let mut reader = BufReader::new(File::open(path)?);
        let mut bytes = Vec::new();

        loop {
            bytes.clear();
            let size = reader.read_until(0, &mut bytes)?;

            if size == 0 {
                break;
            }

            /* Remove trailng null */
            bytes.pop();

            if let Ok(line) = std::str::from_utf8(&bytes) {
                if line.starts_with("COMPlus_PerfMapEnabled=") ||
                   line.starts_with("DOTNET_PerfMapEnabled=") {
                    /* Unless it's defined as 0, we treat it as enabled */
                    if !line.ends_with("=0") {
                       debug!("Process already has perfmap enabled: pid={}", self.pid);
                       return Ok(true);
                    }
                }
            }
        }

        /* Undefined or defined as 0 */
        Ok(false)
    }

    fn remove_perf_map(&self) -> anyhow::Result<()> {
        /* First remove perf map */
        let path = format!("perf-{}.map", self.nspid);

        self.tmp.remove(Path::new(&path))?;

        /* Next remove perf info */
        let path = format!("perfinfo-{}.map", self.nspid);

        self.tmp.remove(Path::new(&path))
    }

    fn enable_perf_map(&self) -> anyhow::Result<()> {
        let bytes = b"DOTNET_IPC_V1\x00\x18\x00\x04\x05\x00\x00\x03\x00\x00\x00";

        match self.open_diag_socket() {
            Some(mut sock) => {
                let mut result = [0; 24];

                if let Err(e) = sock.write_all(bytes) {
                    warn!("Failed to write to diagnostic socket: pid={}, nspid={}, error={}", self.pid, self.nspid, e);
                    anyhow::bail!("Failed to write to diagnostic socket: {}", e);
                }
                sock.read_exact(&mut result)?;

                let result = u32::from_le_bytes(result[20..].try_into()?);

                if result != 0 {
                    anyhow::bail!("Failed with error {}.", result);
                }

                Ok(())
            },
            None => { anyhow::bail!("Not found."); },
        }
    }

    fn disable_perf_map(&self) -> anyhow::Result<()> {
        let bytes = b"DOTNET_IPC_V1\x00\x14\x00\x04\x06\x00\x00";

        match self.open_diag_socket() {
            Some(mut sock) => { 
                if let Err(e) = sock.write_all(bytes) {
                    warn!("Failed to write to diagnostic socket: pid={}, nspid={}, error={}", self.pid, self.nspid, e);
                    anyhow::bail!("Failed to write to diagnostic socket: {}", e);
                }
                Ok(())
            },
            None => { anyhow::bail!("Socket not found."); },
        }
    }
}

struct UserEventTracepointEvents {
    tracepoint: String,
    events: Vec<u32>,
}

#[derive(Default)]
struct UserEventProviderEvents {
    events: Vec<UserEventTracepointEvents>,
    keyword: u64,
    level: u8,
    filter_args: String,
    default_tracepoint: Option<String>,
}

impl UserEventProviderEvents {
    fn event_count(&self) -> usize {
        let mut count = 0;

        for event in &self.events {
            count += event.events.len();
        }

        count
    }

    fn add(
        &mut self,
        tracepoint: String,
        dotnet_events: &HashSet<usize>) {
        let mut events = Vec::new();

        for event in dotnet_events {
            events.push(*event as u32);
        }

        self.events.push(
            UserEventTracepointEvents {
                tracepoint,
                events,
            });
    }
}

#[derive(Default)]
struct UserEventTrackerSettings {
    providers: HashMap<String, UserEventProviderEvents>,
}

struct UserEventTracker {
    send: Sender<u32>,
    worker: Option<JoinHandle<()>>,
}

impl UserEventTracker {
    fn new(settings: Arc<Mutex<UserEventTrackerSettings>>) -> Self {
        let (send, recv) = mpsc::channel();

        let worker = thread::spawn(move || {
            Self::worker_thread_proc(recv, settings);
        });

        Self {
            send,
            worker: Some(worker),
        }
    }

    fn write_string(
        buffer: &mut Vec<u8>,
        value: &str) {
        if value.is_empty() {
            buffer.extend_from_slice(&0u32.to_le_bytes());
            return;
        }

        let count = value.chars().count() as u32 + 1u32;

        buffer.extend_from_slice(&count.to_le_bytes());

        for c in value.chars() {
            let c = c as u16;
            buffer.extend_from_slice(&c.to_le_bytes());
        }

        buffer.extend_from_slice(&0u16.to_le_bytes());
    }

    fn enable_events(
        socket: &mut UnixStream,
        settings: &UserEventTrackerSettings,
        buffer: &mut Vec<u8>) -> anyhow::Result<()> {
        buffer.clear();

        /* Magic */
        buffer.extend_from_slice(b"DOTNET_IPC_V1\0");

        /* Reserve size (u16): 14..16 */
        buffer.extend_from_slice(b"\0\0");

        /* EventPipe (2) -> CollectTracing5 (6) */
        buffer.extend_from_slice(b"\x02\x06\x00\x00");

        buffer.extend_from_slice(&1u32.to_le_bytes()); /* output_format */
        buffer.extend_from_slice(&0u64.to_le_bytes()); /* rundownKeyword */

        let count = settings.providers.len() as u32;
        buffer.extend_from_slice(&count.to_le_bytes()); /* provider count */

        /* Providers */
        for (name, provider) in &settings.providers {
            /* Level is u8, but u32 on wire */
            let level = provider.level as u32;

            buffer.extend_from_slice(&provider.keyword.to_le_bytes()); /* keywords */
            buffer.extend_from_slice(&level.to_le_bytes()); /* logLevel */
            Self::write_string(buffer, &name); /* provider_name */
            Self::write_string(buffer, &provider.filter_args); /* filter_data */

            /* event_filter */
            let count = provider.event_count() as u32;
            if provider.default_tracepoint.is_some() {
                /* Allow all events */
                buffer.push(0u8); /* disallow */
                buffer.extend_from_slice(&0u32.to_le_bytes()); /* event count */
            } else {
                /* Allow only specified events */
                buffer.push(1u8); /* allow */
                buffer.extend_from_slice(&count.to_le_bytes()); /* event count */
                for tracepoint in &provider.events {
                    for event in &tracepoint.events {
                        buffer.extend_from_slice(&event.to_le_bytes());
                    }
                }
            }

            /* tracepoint_config */
            if let Some(def_tracepoint) = &provider.default_tracepoint {
                Self::write_string(buffer, def_tracepoint); /* def_tracepoint */
            } else {
                Self::write_string(buffer, ""); /* def_tracepoint */
            }

            let count = provider.events.len() as u32;
            buffer.extend_from_slice(&count.to_le_bytes()); /* tracepoint count */

            for tracepoint in &provider.events {
                let count = tracepoint.events.len() as u32;

                Self::write_string(buffer, &tracepoint.tracepoint); /* tracepoint */
                buffer.extend_from_slice(&count.to_le_bytes()); /* count */

                for event in &tracepoint.events {
                    buffer.extend_from_slice(&event.to_le_bytes());
                }
            }
        }

        /* Update length */
        let len = buffer.len() as u16;
        buffer[14..16].copy_from_slice(&len.to_le_bytes());

        /* Send */
        socket.write_all(buffer)?;

        /* Send over user_events FD */
        socket.write_all_with_user_events_fd(b"\0")?;

        /* Check result */
        let mut result = [0; 20];

        socket.read_exact(&mut result)?;

        if result[16] != 0xFF || result[17] != 0x00 {
            let mut code = [0; 4];
            socket.read_exact(&mut code)?;

            let code = u32::from_le_bytes(code);
            
            warn!("IPC enablement with user_events failed: error_code={:#x}", code);
            anyhow::bail!("IPC enablement with user_events failed with 0x{:X}.", code);
        }

        let mut session = [0; 8];

        socket.read_exact(&mut session)?;
        
        Ok(())
    }

    fn worker_thread_proc(
        recv: Receiver<u32>,
        arc: Arc<Mutex<UserEventTrackerSettings>>) {
        let mut pids: HashMap<u32, UnixStream> = HashMap::new();
        let mut path_buf = PathBuf::new();
        let mut buffer = Vec::new();

        loop {
            let pid = match recv.recv() {
                Ok(pid) => { pid },
                Err(_) => { break; },
            };

            if pid == 0 {
                break;
            }

            /* Skip if already enabled */
            if pids.contains_key(&pid) {
                continue;
            }

            let nspid = procfs::ns_pid(&mut path_buf, pid).unwrap_or(pid);

            if let Ok(diag) = PerfMapContext::new(pid, nspid) {
                if let Some(mut socket) = diag.open_diag_socket() {
                    if let Ok(settings) = arc.lock() {
                        match Self::enable_events(&mut socket, &settings, &mut buffer) {
                            Ok(()) => {
                                info!("Enabled .NET events for process: pid={}", pid);
                                pids.insert(pid, socket);
                            },
                            Err(err) => {
                                warn!("Failed to enable .NET events: pid={}, error={}", pid, err);
                            },
                        }
                    }
                }
            }
        }

        /* Sessions will stop/close upon pids dropping */
    }

    fn track(
        &mut self,
        pid: u32) -> anyhow::Result<()> {
        /* Prevent early stop, should never happen */
        if pid == 0 {
            return Ok(());
        }

        /* Enqueue PID to the worker thread */
        Ok(self.send.send(pid)?)
    }

    fn disable(
        &mut self) -> anyhow::Result<()> {
        /* Enqueue stop message */
        self.send.send(0)?;

        /* Wait for worker to finish */
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }

        Ok(())
    }
}

struct PerfMapTracker {
    send: Sender<u32>,
    worker: Option<JoinHandle<()>>,
}

impl PerfMapTracker {
    fn new(arc: ArcPerfMapContexts) -> Self {
        let (send, recv) = mpsc::channel();

        let worker = thread::spawn(move || {
            Self::worker_thread_proc(recv, arc)
        });

        Self {
            send,
            worker: Some(worker),
        }
    }

    fn worker_thread_proc(
        recv: Receiver<u32>,
        arc: ArcPerfMapContexts) {
        let mut pids = HashSet::new();
        let mut path_buf = PathBuf::new();

        loop {
            let pid = match recv.recv() {
                Ok(pid) => { pid },
                Err(_) => { break; },
            };

            if pid == 0 {
                break;
            }

            /* Skip if already enabled */
            if pids.contains(&pid) {
                continue;
            }

            let nspid = procfs::ns_pid(&mut path_buf, pid).unwrap_or(pid);

            if let Ok(proc) = PerfMapContext::new(pid, nspid) {
                if let Ok(has_environ) = proc.has_perf_map_environ() {
                    if has_environ {
                        continue;
                    }

                    /* Always try to disable in case it was left on */
                    let _ = proc.disable_perf_map();

                    /* Enable until the thread is done */
                    if proc.enable_perf_map().is_ok() {
                        /* Save context for later */
                        arc.lock().unwrap().push(proc);

                        /* Ensure we don't enable it again */
                        pids.insert(pid);
                    }
                }
            }
        }

        /* Thread is done, disable in-case caller forgets */
        for proc in arc.lock().unwrap().iter() {
            let _ = proc.disable_perf_map();
        }
    }

    fn track(
        &mut self,
        pid: u32) -> anyhow::Result<()> {
        /* Prevent early stop, should never happen */
        if pid == 0 {
            return Ok(());
        }

        /* Enqueue PID to the worker thread */
        Ok(self.send.send(pid)?)
    }

    fn disable(
        &mut self) -> anyhow::Result<()> {
        /* Enqueue stop message */
        self.send.send(0)?;

        /* Wait for worker to finish */
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }

        Ok(())
    }
}

type ArcPerfMapContexts = Arc<Mutex<Vec<PerfMapContext>>>;

pub(crate) struct OSDotNetHelper {
    perf_maps: bool,
    perf_map_procs: Option<ArcPerfMapContexts>,
}

impl OSDotNetHelper {
    pub fn new() -> Self {
        Self {
            perf_maps: false,
            perf_map_procs: None,
        }
    }
}

pub trait DotNetHelperLinuxExt {
    fn with_perf_maps(self) -> Self;

    fn remove_perf_maps(&mut self);

    fn disable_perf_maps(&mut self);
}

impl DotNetHelperLinuxExt for DotNetHelper {
    fn with_perf_maps(mut self) -> Self {
        self.os.perf_maps = true;
        self.os.perf_map_procs = Some(
            Arc::new(
                Mutex::new(
                    Vec::new())));
        self
    }

    fn remove_perf_maps(&mut self) {
        if let Some(procs) = &self.os.perf_map_procs {
            for proc in procs.lock().unwrap().iter() {
                let _ = proc.remove_perf_map();
            }
        }
    }

    fn disable_perf_maps(&mut self) {
        if let Some(procs) = &self.os.perf_map_procs {
            for proc in procs.lock().unwrap().iter() {
                let _ = proc.disable_perf_map();
            }
        }
    }
}


#[derive(Default)]
struct LinuxDotNetEventInfo {
    version: Option<u16>,
    keywords: Option<u64>,
    name_id: Option<usize>,
    logical_id: Option<usize>,
    format_index: Option<usize>,
}

struct LinuxDotNetProviderContext<'a> {
    payload_range: std::ops::Range<usize>,
    key: u64,
    id: usize,
    info: &'a LinuxDotNetEventInfo,
    event_names: &'a InternedStrings,
    formats: &'a Vec<EventFormat>,
}

impl<'a> LinuxDotNetProviderContext<'a> {
    fn format_key(&self) -> u64 {
        /*
         * If we have a name use that, otherwise use the
         * actual event ID with the top bit set so we
         * don't collide with name IDs.
         */
        let id = self.info.name_id.unwrap_or(1 << 31 | self.id) as u64;
        let format_id = self.info.format_index.unwrap_or(0) as u64;

        id << 32 | format_id
    }

    fn self_describing_format(&self) -> Option<&EventFormat> {
        if let Some(index) = self.info.format_index {
            if index < self.formats.len() {
                return Some(&self.formats[index]);
            }
        }

        None
    }

    fn short_event_name(
        &self,
        output: &mut String) {
        use std::fmt::Write;

        output.clear();

        match self.info.name_id {
            Some(id) => {
                match self.event_names.from_id(id) {
                    Ok(name) => {
                        let _ = write!(output, "{}", name);
                    },
                    _ => {
                        let _ = write!(output, "Missing({})", self.id);
                    }
                }
            },
            None => {
                let _ = write!(output, "Unknown({})", self.id);
            },
        }
    }
}

type ProviderCallback = dyn FnMut(&mut ExportTraceContext, &LinuxDotNetProviderContext) -> anyhow::Result<()>;

struct LinuxDotNetProvider {
    events: HashMap<usize, Vec<LinuxDotNetEvent>>,
    named_events: HashMap<String, usize>,
    logical_events: HashMap<usize, Vec<LinuxDotNetEvent>>,
    callbacks: Vec<Box<ProviderCallback>>,
    keyword: u64,
    level: u8,
    callback_callstacks: bool,
    filter_args: Option<String>,
}

impl Default for LinuxDotNetProvider {
    fn default() -> Self {
        Self {
            events: HashMap::new(),
            filter_args: None,
            named_events: HashMap::new(),
            logical_events: HashMap::new(),
            callbacks: Vec::new(),
            callback_callstacks: false,
            keyword: 0,
            level: 0,
        }
    }
}

impl LinuxDotNetProvider {
    pub fn has_named_events(&self) -> bool {
        !self.named_events.is_empty()
    }

    pub fn has_callbacks(&self) -> bool {
        !self.callbacks.is_empty()
    }

    pub fn set_filter_args(
        &mut self,
        filter_args: String) -> anyhow::Result<()> {
        if self.filter_args.is_some() {
            anyhow::bail!("Filter arguments are already specified for this provider.");
        }

        self.filter_args = Some(filter_args);

        Ok(())
    }

    pub fn record_provider(
        &mut self,
        provider_name: &str,
        keyword: u64,
        level: u8,
        flags: DotNetProviderFlags) -> anyhow::Result<()> {
        self.ensure_keyword_level(keyword, level);

        self.callback_callstacks = flags.callstacks();

        let provider = guid_from_provider(provider_name)?;
        let provider_name = provider_name.to_owned();

        #[derive(Copy, Clone)]
        struct DotNetRecordType {
            kind: u16,
            record_type: u16,
        }

        let mut record_types = HashMap::new();
        let mut record_formats = HashMap::new();
        let mut name_buf = String::new();

        /* Register provider level callback for recording */
        self.callbacks.push(
            Box::new(move |trace, context| {
                let attributes = trace.default_attributes()?;
                let range = context.payload_range.clone();

                /*
                 * There is a two level lookup here. We first lookup by
                 * the normal key (EVENT ID + PID). If we cannot find the
                 * record type, then we check if we have a record for that
                 * event (EVENT NAME ID + FORMAT INDEX). This ensures that
                 * we only save the minimal amount of record types even
                 * when there are many processes that share the same types.
                 */

                /* Try to get record_type details for ID + PID */
                let record_type = match record_types.entry(context.key) {
                    Occupied(entry) => { *entry.get() },
                    Vacant(entry) => {
                        /* Get a format key (Name ID + Format Index, etc.) */
                        let format_key = context.format_key();

                        /* Check if we already have a record type for this format type */
                        let record_type = match record_formats.get(&format_key) {
                            Some(record_type) => { *record_type },
                            None => {
                                /* Create new record type */
                                context.short_event_name(&mut name_buf);

                                let full_name = event_full_name(
                                    &provider_name,
                                    provider,
                                    &name_buf);

                                let kind = trace.kind(&full_name);

                                let format = match context.self_describing_format() {
                                    Some(format) => { format.clone() },
                                    None => { EventFormat::default() },
                                };

                                let mut record_type = ExportRecordType::new(
                                    kind,
                                    context.id,
                                    full_name,
                                    format);

                                record_type.set_original_data_flag();

                                let record_type = trace.record_type(record_type);

                                let record_type = DotNetRecordType {
                                    kind,
                                    record_type,
                                };

                                record_formats.insert(format_key, record_type);

                                record_type
                            }
                        };

                        *entry.insert(record_type)
                    }
                };

                /* Override callstacks if keywords don't match any bits */
                if let Some(keywords) = context.info.keywords {
                    if flags.callstack_keywords() & keywords == 0 {
                        trace.override_callstacks(true);
                    }
                }

                /* Record */
                let result = trace
                    .sample_builder()
                    .with_kind(record_type.kind)
                    .with_record_type(record_type.record_type)
                    .with_attributes(attributes)
                    .with_record_event_data(range)
                    .save_value(MetricValue::Count(1));

                /* Always reset callstack override */
                trace.override_callstacks(false);

                result
            }));

        Ok(())
    }

    fn ensure_keyword_level(
        &mut self,
        keyword: u64,
        level: u8) {
        self.keyword |= keyword;

        if level > self.level {
            self.level = level;
        }
    }

    pub fn add_named_event(
        &mut self,
        name: String,
        event: LinuxDotNetEvent,
        callstacks: bool) {
        self.ensure_keyword_level(event.keyword, event.level);

        if callstacks {
            self.callback_callstacks = true;
        }

        let next_id = self.named_events.len();

        let id = self
            .named_events
            .entry(name)
            .or_insert(next_id);

        self.logical_events
            .entry(*id)
            .or_default()
            .push(event);
    }

    pub fn add_event(
        &mut self,
        dotnet_id: usize,
        event: LinuxDotNetEvent) {
        self.ensure_keyword_level(event.keyword, event.level);

        self.events
            .entry(dotnet_id)
            .or_default()
            .push(event);
    }

    pub fn proxy_id_to_events(
        &self,
        proxy_id_set: &HashSet<usize>,
        dotnet_id_set: &mut HashSet<usize>) {
        for (dotnet_id, events) in self.events.iter() {
            for event in events {
                if proxy_id_set.contains(&event.proxy_id) {
                    dotnet_id_set.insert(*dotnet_id);
                }
            }
        }
    }
}

struct LinuxDotNetEvent {
    proxy_id: usize,
    keyword: u64,
    level: u8,
}

const DOTNET_HEADER_FIELDS: &str = "u8 version; u16 event_id; __rel_loc u8[] extension; __rel_loc u8[] payload";

struct DotNetEventDesc {
    name: String,
}

impl DotNetEventDesc {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl UserEventDesc for DotNetEventDesc {
    fn format(&self) -> String {
        format!(
            "{} {}",
            self.name,
            DOTNET_HEADER_FIELDS
        )
    }
}

fn register_dotnet_tracepoint(
    provider: Writable<LinuxDotNetProvider>,
    settings: ExportSettings,
    tracefs: &TraceFS,
    name: &str,
    user_events: &UserEventsFactory,
    callstacks: bool,
    use_names: bool) -> anyhow::Result<ExportSettings> {
    let _ = user_events.create(&DotNetEventDesc::new(name))?;

    let mut event = tracefs.find_event("user_events", name)?;
    
    debug!("Registered .NET tracepoint: name={}, callstacks={}, use_names={}", name, callstacks, use_names);

    if !callstacks {
        event.set_no_callstack_flag();
    }

    let fmt = event.format();
    let id = fmt.get_field_ref_unchecked("event_id");
    let version = fmt.get_field_ref_unchecked("version");
    let payload = fmt.get_field_ref_unchecked("payload");
    let extension = fmt.get_field_ref_unchecked("extension");

    let empty_info = LinuxDotNetEventInfo::default();

    let mut format_lookup: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut formats = Vec::new();
    let mut info_lookup = HashMap::new();
    let mut event_names = InternedStrings::new(16);
    let mut name_buf = String::new();

    /* Index 0 should always be default */
    formats.push(EventFormat::default());

    let settings = settings.with_event(
        event,
        |_built| {
            Ok(())
        },
        move |trace| {
            let mut provider = provider.borrow_mut();

            let fmt = trace.data().format();
            let data = trace.data().event_data();

            /* Read DotNet ABI Version */
            let version = fmt.get_u8(version, data)?;

            /* Read DotNet ID */
            let id = fmt.get_u16(id, data)? as usize;

            /* Read payload range */
            let payload_range = fmt.get_rel_loc(payload, data)?;

            /* Lookups within a provider is PID and Event ID */
            let pid = trace.pid()?;
            let key = (pid as u64) << 32 | id as u64;

            let mut activity_id = None;
            let mut related_activity_id = None;

            match version {
                1 => {
                    /* Decode extension */
                    let extension_range = fmt.get_rel_loc(extension, data)?;
                    let extension = &data[extension_range];

                    nettrace::parse_event_extension_v1(
                        extension,
                        |label, data| { match label {
                            nettrace::LABEL_META => {
                                let meta = nettrace::MetaParserV5::parse(data);

                                let mut info = LinuxDotNetEventInfo::default();

                                /* Save version, if any by PID + Event */
                                if let Some(version) = meta.version() {
                                    info.version = Some(version as u16);
                                }

                                info.keywords = meta.keywords();

                                /* Save logical ID by PID + Event if we have any*/
                                if use_names {
                                    /* Read event name */
                                    meta.event_name(&mut name_buf);

                                    /*
                                     * Only set name_id and logical_id if we have a name:
                                     * We need to know later if this event was a dynamic
                                     * event or a manifest event. The name_id being Some
                                     * vs None indicates this.
                                     */
                                    if !name_buf.is_empty() {
                                        info.name_id = Some(event_names.to_id(&name_buf));

                                        /* Lookup event name and return logical event ID */
                                        if let Some(id) = provider.named_events.get(&name_buf) {
                                            info.logical_id = Some(*id);
                                        }
                                    }

                                    info.format_index = match format_lookup.get(meta.fields()) {
                                        Some(format_index) => { Some(*format_index) },
                                        None => {
                                            let format = nettrace::FieldsParserV5::parse(meta.fields());
                                            let format_index = formats.len();
                                            formats.push(format);

                                            format_lookup.insert(meta.fields().into(), format_index);

                                            Some(format_index)
                                        }
                                    };
                                }

                                info_lookup.insert(key, info);
                            },
                            nettrace::LABEL_ACTIVITY => {
                                if data.len() == 16 {
                                    activity_id = data[0..16].try_into().ok();
                                }
                            },
                            nettrace::LABEL_RELATED_ACTIVITY => {
                                if data.len() == 16 {
                                    related_activity_id = data[0..16].try_into().ok();
                                }
                            },
                            _ => {},
                        }});
                },
                _ => {},
            }

            let info = info_lookup.get(&key).unwrap_or(&empty_info);

            let events = if !use_names {
                /* Lookup DotNet Event from Manifest ID */
                provider.events.get(&id)
            } else {
                /* Lookup DotNet Event from Logical ID (Name) */
                if let Some(logical_id) = info.logical_id {
                    provider.logical_events.get(&logical_id)
                } else {
                    None
                }
            };

            /* Setup overrides */
            trace.override_version(info.version);
            trace.override_activity_id(activity_id);
            trace.override_related_activity_id(related_activity_id);

            if let Some(events) = events {
                /* Proxy DotNet data to all proxy events */
                for event in events {
                    trace.proxy_event_data(
                        event.proxy_id,
                        payload_range.clone());
                }
            }

            /* All tracepoints run provider level callbacks */
            if !provider.callbacks.is_empty() {
                let context = LinuxDotNetProviderContext {
                    payload_range: payload_range.clone(),
                    key,
                    id,
                    info,
                    event_names: &event_names,
                    formats: &formats,
                };

                for callback in &mut provider.callbacks {
                    callback(trace, &context)?;
                }
            }

            /* Always clear overrides */
            trace.override_version(None);
            trace.override_activity_id(None);
            trace.override_related_activity_id(None);

            Ok(())
        });

    Ok(settings)
}

pub(crate) struct OSDotNetEventFactory {
    proxy: Box<dyn FnMut(String, usize) -> Option<Event>>,
    providers: Writable<HashMap<String, Writable<LinuxDotNetProvider>>>,
}

impl OSDotNetEventFactory {
    pub fn new(proxy: impl FnMut(String, usize) -> Option<Event> + 'static) -> Self {
        Self {
            proxy: Box::new(proxy),
            providers: Writable::new(HashMap::new()),
        }
    }

    pub fn hook_to_exporter(
        &mut self,
        exporter: UniversalExporter) -> UniversalExporter {
        let fn_providers = self.providers.clone();
        let tracefs = TraceFS::open();

        let user_events = match &tracefs {
            Ok(tracefs) => {
                match tracefs.user_events_factory() {
                    Ok(user_events) => { Some(user_events) },
                    Err(_) => { None },
                }
            },
            Err(_) => { None },
        };

        let tracker_events = Arc::new(Mutex::new(UserEventTrackerSettings::default()));

        let user_events = Writable::new(user_events);
        let fn_user_events = user_events.clone();
        let settings_tracker_events = tracker_events.clone();

        exporter.with_settings_hook(move |mut settings| {
            let tracefs = match tracefs.as_ref() {
                Ok(tracefs) => { tracefs },
                Err(err)  => { anyhow::bail!("Tracefs is not accessible: {}", err); },
            };
            let user_events = fn_user_events.borrow();
            let user_events = match user_events.as_ref() {
                Some(user_events) => { user_events },
                None => { anyhow::bail!("User events are not accessible."); },
            };

            let pid = std::process::id();
            let mut wanted_ids = HashSet::new();

            for (name, provider) in fn_providers.borrow().iter() {
                /* Split proxy events by callstack flag */
                let mut callstacks = HashSet::new();
                let mut no_callstacks = HashSet::new();

                /* Determine wanted PROXY IDs */
                wanted_ids.clear();
                for dotnet_events in provider.borrow().events.values() {
                    for event in dotnet_events {
                        wanted_ids.insert(event.proxy_id);
                    }
                }

                /* Check proxy events */
                settings.for_each_event(|event| {
                    if let Some(proxy_id) = event.get_proxy_id() {
                        if wanted_ids.contains(&proxy_id) {
                            if event.has_no_callstack_flag() {
                                no_callstacks.insert(proxy_id);
                            } else {
                                callstacks.insert(proxy_id);
                            }
                        }
                    }
                });

                /* Remove TraceFS bad characters */
                let safe_name = name
                    .replace("-", "_")
                    .replace("/", "")
                    .replace("?", "")
                    .replace("*", "");

                let mut provider_events = UserEventProviderEvents::default();
                let mut dotnet_ids = HashSet::new();

                if let Some(filter_args) = &provider.borrow().filter_args {
                    provider_events.filter_args = filter_args.clone();
                }

                provider_events.keyword = provider.borrow().keyword;
                provider_events.level = provider.borrow().level;

                /* Create event for each group, if any */
                if !no_callstacks.is_empty() {
                    let tracepoint = format!(
                        "OC_DotNet_{}_{}",
                        safe_name,
                        pid);

                    settings = register_dotnet_tracepoint(
                        provider.clone(),
                        settings,
                        tracefs,
                        &tracepoint,
                        user_events,
                        false,
                        false)?;

                    dotnet_ids.clear();

                    provider.borrow().proxy_id_to_events(
                        &no_callstacks,
                        &mut dotnet_ids);

                    provider_events.add(
                        tracepoint,
                        &dotnet_ids);
                }

                if !callstacks.is_empty() {
                    let tracepoint = format!(
                        "OC_DotNet_{}_{}_C",
                        safe_name,
                        pid);

                    settings = register_dotnet_tracepoint(
                        provider.clone(),
                        settings,
                        tracefs,
                        &tracepoint,
                        user_events,
                        true,
                        false)?;

                    dotnet_ids.clear();

                    provider.borrow().proxy_id_to_events(
                        &callstacks,
                        &mut dotnet_ids);

                    provider_events.add(
                        tracepoint,
                        &dotnet_ids);
                }

                if provider.borrow().has_named_events() ||
                   provider.borrow().has_callbacks() {
                    let tracepoint = format!(
                        "OC_DotNet_{}_{}_All",
                        safe_name,
                        pid);

                    settings = register_dotnet_tracepoint(
                        provider.clone(),
                        settings,
                        tracefs,
                        &tracepoint,
                        user_events,
                        provider.borrow().callback_callstacks,
                        true)?;

                    provider_events.default_tracepoint = Some(tracepoint);
                }

                match settings_tracker_events.lock() {
                    Ok(mut tracker_events) => {
                        tracker_events.providers.insert(
                            name.to_owned(), provider_events);
                    },
                    Err(_) => { anyhow::bail!("Settings already locked."); },
                }
            }

            Ok(settings)
        }).with_build_hook(move |mut session, _context| {
            let session_tracker_events = tracker_events.clone();

            /* Hook session IPC integration */
            Ok(session.with_hooks(
                |_builder| {
                    /* Nothing to build */
                },

                move |session| {
                    /* Perf map support */
                    let event = session.mmap_event();
                    let fmt = event.format();
                    let pid = fmt.get_field_ref_unchecked("pid");
                    let prot = fmt.get_field_ref_unchecked("prot");
                    let filename = fmt.get_field_ref_unchecked("filename[]");

                    let tracker = Writable::new(
                        UserEventTracker::new(session_tracker_events));

                    let tracker_close = tracker.clone();

                    event.add_callback(move |data| {
                        let fmt = data.format();
                        let data = data.event_data();

                        let prot = fmt.get_u32(prot, data)? as i32;

                        /* Skip non-executable mmaps */
                        if prot & PROT_EXEC != PROT_EXEC {
                            return Ok(());
                        }

                        let pid = fmt.get_u32(pid, data)?;
                        let filename = fmt.get_str(filename, data)?;

                        /* Check if dotnet process */
                        if filename.starts_with("/memfd:doublemapper") {
                            /* Attempt to track, will check diag sock, etc */
                            tracker.borrow_mut().track(pid)?;
                        }

                        Ok(())
                    });

                    /* When session drops, stop worker thread */
                    let event = session.drop_event();

                    event.add_callback(move |_| {
                        tracker_close.borrow_mut().disable()
                    });
                }
            ))
        }).with_export_drop_hook(move || {
            /* Drop factory: This ensures we keep user_events FD until drop */
            let _ = user_events.borrow_mut().take();
        })
    }

    pub fn record_provider(
        &mut self,
        provider_name: &str,
        keyword: u64,
        level: u8,
        flags: DotNetProviderFlags) -> anyhow::Result<()> {
        self.providers
            .borrow_mut()
            .entry(provider_name.into())
            .or_insert_with(|| Writable::new(LinuxDotNetProvider::default()))
            .borrow_mut()
            .record_provider(provider_name, keyword, level, flags)
    }

    pub fn set_filter_args(
        &mut self,
        provider_name: &str,
        filter_args: String) -> anyhow::Result<()> {
        self.providers
            .borrow_mut()
            .entry(provider_name.into())
            .or_insert_with(|| Writable::new(LinuxDotNetProvider::default()))
            .borrow_mut()
            .set_filter_args(filter_args)
    }

    pub fn new_event(
        &mut self,
        provider_name: &str,
        keyword: u64,
        level: u8,
        id: Option<usize>,
        name: String) -> anyhow::Result<Event> {
        let provider = guid_from_provider(provider_name)?;
        let full_name = event_full_name(provider_name, provider, &name);

        let event = match (self.proxy)(full_name, id.unwrap_or(0)) {
            Some(event) => { event },
            None => { anyhow::bail!("Event couldn't be created with proxy"); },
        };

        let proxy_id = match event.get_proxy_id() {
            Some(proxy_id) => { proxy_id },
            None => { anyhow::bail!("Proxy events must have a proxy ID set."); },
        };

        let dotnet_event = LinuxDotNetEvent {
            proxy_id,
            keyword,
            level,
        };

        let mut providers = self
            .providers
            .borrow_mut();

        let mut provider = providers
            .entry(provider_name.into())
            .or_insert_with(|| Writable::new(LinuxDotNetProvider::default()))
            .borrow_mut();

        match id {
            None => {
                provider.add_named_event(
                    name,
                    dotnet_event,
                    !event.has_no_callstack_flag());
            },
            Some(id) => {
                provider.add_event(
                    id,
                    dotnet_event);
            }
        }

        Ok(event)
    }
}

#[cfg(target_os = "linux")]
impl UniversalDotNetHelperOSHooks for DotNetHelper {
    fn os_with_dynamic_symbols(self) -> Self {
        self.with_perf_maps()
    }

    fn os_cleanup_dynamic_symbols(&mut self) {
        self.remove_perf_maps();
    }
}

impl DotNetHelp for RingBufSessionBuilder {
    fn with_dotnet_help(
        mut self,
        helper: &mut DotNetHelper) -> Self {
        let perf_maps = helper.os.perf_maps;
        let perf_maps_procs = match helper.os.perf_map_procs.as_ref() {
            Some(arc) => { Some(arc.clone()) },
            None => { None },
        };

        self.with_hooks(
            move |_builder| {
                /* Nothing to build */
            },

            move |session| {
                if perf_maps {
                    /* Perf map support */
                    let event = session.mmap_event();
                    let fmt = event.format();
                    let pid = fmt.get_field_ref_unchecked("pid");
                    let prot = fmt.get_field_ref_unchecked("prot");
                    let filename = fmt.get_field_ref_unchecked("filename[]");

                    /* SAFETY: We always have this for perf_maps_procs */
                    let tracker = PerfMapTracker::new(perf_maps_procs.unwrap());
                    let perfmap = Writable::new(tracker);
                    let perfmap_close = perfmap.clone();

                    event.add_callback(move |data| {
                        let fmt = data.format();
                        let data = data.event_data();

                        let prot = fmt.get_u32(prot, data)? as i32;

                        /* Skip non-executable mmaps */
                        if prot & PROT_EXEC != PROT_EXEC {
                            return Ok(());
                        }

                        let pid = fmt.get_u32(pid, data)?;
                        let filename = fmt.get_str(filename, data)?;

                        /* Check if dotnet process */
                        if filename.starts_with("/memfd:doublemapper") {
                            /* Attempt to track, will check diag sock, etc */
                            perfmap.borrow_mut().track(pid)?;
                        }

                        Ok(())
                    });

                    /* When session drops, stop worker thread */
                    let event = session.drop_event();

                    event.add_callback(move |_| {
                        perfmap_close.borrow_mut().disable()
                    });
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn it_works() {
        let mut helper = DotNetHelper::new()
            .with_perf_maps();

        let mut builder = RingBufSessionBuilder::new()
            .with_page_count(256)
            .with_dotnet_help(&mut helper);

        let mut session = builder.build().unwrap();
        let duration = std::time::Duration::from_secs(1);

        session.capture_environment();
        session.enable().unwrap();
        session.parse_for_duration(duration).unwrap();
        session.disable().unwrap();

        helper.disable_perf_maps();
        helper.remove_perf_maps();
    }
}
