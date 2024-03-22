use std::fs::File;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::os::unix::ffi::OsStrExt;
use std::os::fd::{RawFd, FromRawFd, IntoRawFd};
use crate::intern::InternedCallstacks;
use super::*;

pub struct ExportProcessSample {
    time: u64,
    value: u64,
    cpu: u16,
    kind: u16,
    tid: u32,
    ip: u64,
    callstack_id: usize,
}

impl ExportProcessSample {
    pub fn new(
        time: u64,
        value: u64,
        cpu: u16,
        kind: u16,
        tid: u32,
        ip: u64,
        callstack_id: usize) -> Self {
        Self {
            time,
            value,
            cpu,
            kind,
            tid,
            ip,
            callstack_id,
        }
    }

    pub fn time_mut(&mut self) -> &mut u64 { &mut self.time }

    pub fn value_mut(&mut self) -> &mut u64 { &mut self.value }

    pub fn time(&self) -> u64 { self.time }

    pub fn value(&self) -> u64 { self.value }

    pub fn cpu(&self) -> u16 { self.cpu }

    pub fn kind(&self) -> u16 { self.kind }

    pub fn tid(&self) -> u32 { self.tid }

    pub fn ip(&self) -> u64 { self.ip }

    pub fn callstack_id(&self) -> usize { self.callstack_id }
}

pub struct ExportProcess {
    pid: u32,
    comm_id: Option<usize>,
    root_fs: Option<RawFd>,
    samples: Vec<ExportProcessSample>,
    mappings: Vec<ExportMapping>,
    anon_maps: bool,
}

impl ExportProcess {
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            comm_id: None,
            root_fs: None,
            samples: Vec::new(),
            mappings: Vec::new(),
            anon_maps: false,
        }
    }

    pub fn add_root_fs(
        &mut self,
        path_buf: &mut PathBuf) -> anyhow::Result<()> {
        path_buf.clear();
        path_buf.push("/proc");
        path_buf.push(self.pid.to_string());
        path_buf.push("root");
        path_buf.push(".");

        let root = File::open(path_buf)?;

        self.root_fs = Some(root.into_raw_fd());

        Ok(())
    }

    pub fn open_file(
        &self,
        path: &Path) -> anyhow::Result<File> {
        match self.root_fs {
            None => {
                anyhow::bail!("Root fs is not set or had an error.");
            },
            Some(root_fd) => {
                let path = CString::new(path.as_os_str().as_bytes())?;
                let mut path = path.as_bytes_with_nul();

                if path[0] == b'/' {
                    path = &path[1..]
                }

                unsafe {
                    let fd = libc::openat(
                        root_fd,
                        path.as_ptr() as *const libc::c_char,
                        libc::O_RDONLY | libc::O_CLOEXEC);

                    if fd == -1 {
                        return Err(std::io::Error::last_os_error().into());
                    }

                    Ok(File::from_raw_fd(fd))
                }
            }
        }
    }

    pub fn add_mapping(
        &mut self,
        mapping: ExportMapping) {
        if mapping.anon() {
            self.anon_maps = true;
        }

        self.mappings.push(mapping);
    }

    pub fn add_sample(
        &mut self,
        sample: ExportProcessSample) {
        self.samples.push(sample);
    }

    pub fn set_comm_id(
        &mut self,
        comm_id: usize) {
        self.comm_id = Some(comm_id);
    }

    pub fn pid(&self) -> u32 { self.pid }

    pub fn comm_id(&self) -> Option<usize> { self.comm_id }

    pub fn samples(&self) -> &Vec<ExportProcessSample> { &self.samples }

    pub fn mappings(&self) -> &Vec<ExportMapping> { &self.mappings }

    pub fn mappings_mut(&mut self) -> &mut Vec<ExportMapping> { &mut self.mappings }

    pub fn has_anon_mappings(&self) -> bool { self.anon_maps }

    pub fn get_unique_kernel_ips(
        &self,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks) {
        addrs.clear();
        frames.clear();

        for sample in &self.samples {
            /* Skip user mode samples */
            if sample.ip() < KERNEL_START {
                continue;
            }

            addrs.insert(sample.ip());

            if callstacks.from_id(
                sample.callstack_id(),
                frames).is_ok() {
                for frame in frames.iter() {
                    /* Stop on first user-mode frame */
                    if *frame < KERNEL_START {
                        break;
                    }

                    addrs.insert(*frame);
                }
            }
        }
    }

    pub fn get_unique_user_ips(
        &self,
        addrs: &mut HashSet<u64>,
        frames: &mut Vec<u64>,
        callstacks: &InternedCallstacks,
        mapping: Option<&ExportMapping>) {
        addrs.clear();
        frames.clear();

        for sample in &self.samples {
            /* Only add user frames */
            if sample.ip() < KERNEL_START {
                match mapping {
                    Some(mapping) => {
                        if mapping.contains_ip(sample.ip()) {
                            addrs.insert(sample.ip());
                        }
                    },
                    None => { addrs.insert(sample.ip()); }
                }
            }

            if callstacks.from_id(
                sample.callstack_id(),
                frames).is_ok() {
                for frame in frames.iter() {
                    /* Only add user frames */
                    if *frame < KERNEL_START {
                        match mapping {
                            Some(mapping) => {
                                if mapping.contains_ip(*frame) {
                                    addrs.insert(*frame);
                                }
                            },
                            None => { addrs.insert(*frame); }
                        }
                    }
                }
            }
        }
    }

    pub fn fork(
        &self,
        pid: u32) -> Self { 
        let mut fork = Self::new(pid);

        fork.comm_id = self.comm_id;
        fork.mappings = self.mappings.clone();
        fork.root_fs = self.root_fs.clone();

        fork
    }
}

impl Drop for ExportProcess {
    fn drop(&mut self) {
        /* Close root_fs, if any */
        if let Some(fd) = self.root_fs.take() {
            unsafe {
                libc::close(fd);
            }
        }
    }
}
