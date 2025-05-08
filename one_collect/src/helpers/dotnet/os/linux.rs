#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

#[cfg(not(target_os = "linux"))]
struct UnixStream {}

use std::io::{Read, BufRead, BufReader, Write};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::collections::{HashSet, HashMap};
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crate::helpers::dotnet::*;
use crate::helpers::dotnet::universal::UniversalDotNetHelperOSHooks;
use crate::helpers::exporting::{UniversalExporter, ExportSettings};

use crate::user_events::*;
use crate::tracefs::*;
use crate::perf_event::*;
use crate::openat::OpenAt;
use crate::Writable;
use crate::procfs;
use crate::event::*;

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
                        return Some(sock);
                    }
                }
            },
            None => { },
        }

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

                sock.write_all(bytes)?;
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
            Some(mut sock) => { Ok(sock.write_all(bytes)?) },
            None => { anyhow::bail!("Socket not found."); },
        }
    }
}

struct UserEventTracepointEvents {
    tracepoint: String,
    events: Vec<u16>,
}

#[derive(Default)]
struct UserEventProviderEvents {
    events: Vec<UserEventTracepointEvents>,
    keyword: u64,
    level: u8,
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
        dotnet_events: &HashSet<usize>,
        keyword: u64,
        level: u8) {
        let mut events = Vec::new();

        for event in dotnet_events {
            events.push(*event as u16);
        }

        self.keyword |= keyword;

        if level > self.level {
            self.level = level;
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
            Self::write_string(buffer, ""); /* filter_data */

            /* event_filter */
            let count = provider.event_count() as u32;
            buffer.push(1u8); /* allow */
            buffer.extend_from_slice(&count.to_le_bytes()); /* event count */
            for tracepoint in &provider.events {
                for event in &tracepoint.events {
                    buffer.extend_from_slice(&event.to_le_bytes());
                }
            }

            /* tracepoint_config */
            Self::write_string(buffer, ""); /* def_tracepoint */
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
                            Ok(()) => { pids.insert(pid, socket); },
                            Err(_) => { /* Nothing */ },
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

struct LinuxDotNetProvider {
    events: Writable<HashMap<usize, Vec<LinuxDotNetEvent>>>,
}

impl Default for LinuxDotNetProvider {
    fn default() -> Self {
        Self {
            events: Writable::new(HashMap::new()),
        }
    }
}

impl LinuxDotNetProvider {
    pub fn add_event(
        &mut self,
        dotnet_id: usize,
        event: LinuxDotNetEvent) {
        self.events
            .borrow_mut()
            .entry(dotnet_id)
            .or_default()
            .push(event)
    }

    pub fn proxy_id_to_events(
        &self,
        proxy_id_set: &HashSet<usize>,
        dotnet_id_set: &mut HashSet<usize>,
        keyword: &mut u64,
        level: &mut u8) {
        for (dotnet_id, events) in self.events.borrow().iter() {
            for event in events {
                if proxy_id_set.contains(&event.proxy_id) {
                    *keyword |= event.keyword;
                    *level |= event.level;
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

const DOTNET_HEADER_FIELDS: &str = "u16 event_id; __rel_loc u8[] payload; __rel_loc u8[] meta";

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
    provider: &LinuxDotNetProvider,
    settings: ExportSettings,
    tracefs: &TraceFS,
    name: &str,
    user_events: &UserEventsFactory,
    callstacks: bool) -> anyhow::Result<ExportSettings> {
    let events = provider.events.clone();

    let _ = user_events.create(&DotNetEventDesc::new(name))?;

    let mut event = tracefs.find_event("user_events", name)?;

    if !callstacks {
        event.set_no_callstack_flag();
    }

    let fmt = event.format();
    let id = fmt.get_field_ref_unchecked("event_id");
    let payload = fmt.get_field_ref_unchecked("payload");

    let settings = settings.with_event(
        event,
        |_built| {
            Ok(())
        },
        move |trace| {
            let fmt = trace.data().format();
            let data = trace.data().event_data();

            /* Read DotNet ID */
            let id = fmt.get_u16(id, data)? as usize;

            /* Read payload range */
            let payload_range = fmt.get_rel_loc(payload, data)?;

            /* Lookup DotNet Event from ID */
            if let Some(events) = events.borrow().get(&id) {
                /* Proxy DotNet data to all proxy events */
                for event in events {
                    trace.proxy_event_data(
                        event.proxy_id,
                        payload_range.clone());
                }
            }

            Ok(())
        });

    Ok(settings)
}

pub(crate) struct OSDotNetEventFactory {
    proxy: Box<dyn FnMut(String) -> Option<Event>>,
    providers: Writable<HashMap<String, LinuxDotNetProvider>>,
}

impl OSDotNetEventFactory {
    pub fn new(proxy: impl FnMut(String) -> Option<Event> + 'static) -> Self {
        Self {
            proxy: Box::new(proxy),
            providers: Writable::new(HashMap::new()),
        }
    }

    pub fn hook_to_exporter(
        &mut self,
        exporter: UniversalExporter) -> UniversalExporter {
        let fn_providers = self.providers.clone();
        let tracefs = match TraceFS::open() {
            Ok(tracefs) => { Some(tracefs) },
            Err(_) => { None },
        };

        let user_events = match &tracefs {
            Some(tracefs) => {
                match tracefs.user_events_factory() {
                    Ok(user_events) => { Some(user_events) },
                    Err(_) => { None },
                }
            },
            None => { None },
        };

        let tracker_events = Arc::new(Mutex::new(UserEventTrackerSettings::default()));

        let user_events = Writable::new(user_events);
        let fn_user_events = user_events.clone();
        let settings_tracker_events = tracker_events.clone();

        exporter.with_settings_hook(move |mut settings| {
            let tracefs = match tracefs.as_ref() {
                Some(tracefs) => { tracefs },
                None => { anyhow::bail!("TraceFS is not accessible."); },
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
                for dotnet_events in provider.events.borrow().values() {
                    for event in dotnet_events {
                        wanted_ids.insert(event.proxy_id);
                    }
                }

                /* Check proxy events */
                settings.for_each_event(|event| {
                    if !event.has_proxy_flag() {
                        return;
                    }

                    if wanted_ids.contains(&event.id()) {
                        if event.has_no_callstack_flag() {
                            no_callstacks.insert(event.id());
                        } else {
                            callstacks.insert(event.id());
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

                /* Create event for each group, if any */
                if !no_callstacks.is_empty() {
                    let tracepoint = format!(
                        "OC_DotNet_{}_{}",
                        safe_name,
                        pid);

                    settings = register_dotnet_tracepoint(
                        provider,
                        settings,
                        tracefs,
                        &tracepoint,
                        user_events,
                        false)?;

                    let mut keyword = 0u64;
                    let mut level = 0u8;

                    dotnet_ids.clear();

                    provider.proxy_id_to_events(
                        &no_callstacks,
                        &mut dotnet_ids,
                        &mut keyword,
                        &mut level);

                    provider_events.add(
                        tracepoint,
                        &dotnet_ids,
                        keyword,
                        level);
                }

                if !callstacks.is_empty() {
                    let tracepoint = format!(
                        "OC_DotNet_{}_{}_C",
                        safe_name,
                        pid);

                    settings = register_dotnet_tracepoint(
                        provider,
                        settings,
                        tracefs,
                        &tracepoint,
                        user_events,
                        true)?;

                    let mut keyword = 0u64;
                    let mut level = 0u8;

                    dotnet_ids.clear();

                    provider.proxy_id_to_events(
                        &callstacks,
                        &mut dotnet_ids,
                        &mut keyword,
                        &mut level);

                    provider_events.add(
                        tracepoint,
                        &dotnet_ids,
                        keyword,
                        level);
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
                        if filename == "/memfd:doublemapper" {
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

    pub fn new_event(
        &mut self,
        provider_name: &str,
        keyword: u64,
        level: u8,
        id: usize,
        name: String) -> anyhow::Result<Event> {
        let event = match (self.proxy)(name) {
            Some(event) => { event },
            None => { anyhow::bail!("Event couldn't be created with proxy"); },
        };

        let dotnet_event = LinuxDotNetEvent {
            proxy_id: event.id(),
            keyword,
            level,
        };

        self.providers
            .borrow_mut()
            .entry(provider_name.into())
            .or_default()
            .add_event(id, dotnet_event);

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
                        if filename == "/memfd:doublemapper" {
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
