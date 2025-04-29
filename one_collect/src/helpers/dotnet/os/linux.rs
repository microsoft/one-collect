#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

#[cfg(not(target_os = "linux"))]
struct UnixStream {}

use std::io::{Read, BufRead, BufReader, Write};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::collections::{HashSet};
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crate::helpers::dotnet::*;
use crate::helpers::dotnet::universal::UniversalDotNetHelperOSHooks;

#[cfg(feature = "scripting")]
use crate::helpers::exporting::UniversalExporter;

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

pub(crate) struct OSDotNetEventFactory {
    proxy: Box<dyn FnMut(String) -> Option<Event>>,
}

impl OSDotNetEventFactory {
    pub fn new(proxy: impl FnMut(String) -> Option<Event> + 'static) -> Self {
        Self {
            proxy: Box::new(proxy),
        }
    }

    pub fn hook_to_exporter(
        &mut self,
        _exporter: UniversalExporter) -> UniversalExporter {
        todo!("Need to build hook");
    }

    pub fn new_event(
        &mut self,
        _provider_name: &str,
        _keyword: u64,
        _level: u8,
        _id: usize,
        name: String) -> anyhow::Result<Event> {
        let _event = match (self.proxy)(name) {
            Some(event) => { event },
            None => { anyhow::bail!("Event couldn't be created with proxy"); },
        };

        todo!("Need to proxy via user_events");
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
