// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::path::PathBuf;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::ops::DerefMut;
use std::collections::HashMap;
use std::collections::hash_map::Entry::{self, Vacant};
use tracing::{debug, warn};

use super::*;
use crate::PathBufInteger;
use crate::perf_event::*;
use crate::event::DataFieldRef;
use crate::Writable;

use libc::*;
use ruwind::*;

pub struct CallstackReader {
    state: Writable<MachineState>,
}

impl Clone for CallstackReader {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone()
        }
    }
}

struct ModuleLookup {
    fds: HashMap<ModuleKey, RawFd>,
}

impl ModuleLookup {
    fn new() -> Self {
        Self {
            fds: HashMap::new(),
        }
    }

    fn entry(
        &mut self,
        key: ModuleKey) -> Entry<'_, ModuleKey, RawFd> {
        self.fds.entry(key)
    }
}

impl ModuleAccessor for ModuleLookup {
    fn open(
        &self,
        key: &ModuleKey) -> Option<File> {
        match self.fds.get(&key) {
            Some(fd) => {
                /* Clone it and return for caller */
                unsafe {
                    let cloned_fd = dup(*fd);
                    Some(File::from_raw_fd(cloned_fd))
                }
            },
            None => { None },
        }
    }
}

struct MachineState {
    machine: Machine,
    modules: ModuleLookup,
    ip_field: DataFieldRef,
    pid_field: DataFieldRef,
    callchain_field: DataFieldRef,
    regs_user_field: DataFieldRef,
    stack_user_field: DataFieldRef,
    path: PathBuf,
    unwinder: Option<Box<dyn MachineUnwinder>>,
    unwind: Box<dyn FnMut(&mut UnwindRequest)>,
}

impl MachineState {
    fn new() -> Self {
        let empty = DataFieldRef::default();

        Self {
            machine: Machine::new(),
            modules: ModuleLookup::new(),
            ip_field: empty.clone(),
            pid_field: empty.clone(),
            callchain_field: empty.clone(),
            regs_user_field: empty.clone(),
            stack_user_field: empty.clone(),
            path: PathBuf::new(),
            unwinder: None,
            unwind: Box::new(|request| {
                request.unwind_machine();
            }),
        }
    }

    fn set_unwind(
        &mut self,
        unwind: impl FnMut(&mut UnwindRequest) + 'static) {
        self.unwind = Box::new(unwind);
    }

    fn add_comm_exec(
        &mut self,
        pid: u32) {
        self.machine.add_process(
            pid,
            Process::new());
        debug!("Process added for callstack tracking: pid={}", pid);
    }

    fn fork(
        &mut self,
        pid: u32,
        ppid: u32) {
        self.machine.fork_process(pid, ppid);
        debug!("Process forked: pid={}, ppid={}", pid, ppid);
    }

    fn exit(
        &mut self,
        pid: u32) {
        self.machine.remove_process(pid);
        debug!("Process removed from callstack tracking: pid={}", pid);
    }

    fn add_mmap_exec(
        &mut self,
        pid: u32,
        addr: u64,
        len: u64,
        offset: u64,
        maj: u32,
        min: u32,
        ino: u64,
        filename: &str) {
        let dev = (maj << 8) as u64 | min as u64;

        let mem_backed = filename.starts_with('[') ||
           filename.starts_with("/memfd:") ||
           filename.starts_with("//anon");

        if !mem_backed {
            /* File backed */
            let key = ModuleKey::new(dev, ino);

            if let Vacant(entry) = self.modules.entry(key) {
                /* Try to open and keep a single FD for that file */
                self.path.clear();
                self.path.push("/proc");
                self.path.push_u32(pid);
                self.path.push("root");
                self.path.push(filename);

                /* Only insert if we can actually open it */
                if let Ok(file) = std::fs::File::open(&self.path) {
                    entry.insert(file.into_raw_fd());
                } else {
                    warn!("Failed to open module file: pid={}, filename={}", pid, filename);
                }
            }
        }

        // PE files
        let unwind_type =
            if filename.ends_with(".dll") || filename.ends_with(".exe") {
                UnwindType::Prolog
            } else {
                UnwindType::DWARF
            };

        /* Always add to the process for unwinding info */
        if let Some(process) = self.machine.find_process(pid) {
            let module: Module;
            let start = addr;
            let end = start + len;

            if !mem_backed {
                module = Module::new(
                    start,
                    end,
                    offset,
                    dev,
                    ino,
                    unwind_type);
            } else {
                module = Module::new_anon(
                    start,
                    end);
            }

            process.add_module(module);
        }
    }
}

pub struct UnwindRequest<'a> {
    pid: u32,
    rip: u64,
    rbp: u64,
    rsp: u64,
    machine: &'a mut Machine,
    unwinder: &'a mut dyn MachineUnwinder,
    modules: &'a dyn ModuleAccessor,
    stack_data: &'a [u8],
    frames: &'a mut Vec<u64>,
}

impl<'a> UnwindRequest<'a> {
    pub fn new(
        pid: u32,
        rip: u64,
        rbp: u64,
        rsp: u64,
        machine: &'a mut Machine,
        unwinder: &'a mut dyn MachineUnwinder,
        modules: &'a dyn ModuleAccessor,
        stack_data: &'a [u8],
        frames: &'a mut Vec<u64>) -> Self {
        Self {
            pid,
            rip,
            rbp,
            rsp,
            machine,
            unwinder,
            modules,
            stack_data,
            frames,
        }
    }

    pub fn pid(&self) -> u32 { self.pid }

    pub fn machine(&mut self) -> &Machine { self.machine }

    pub fn unwind_machine(
        &mut self) -> UnwindResult {
        self.machine.unwind_process(
            self.pid,
            self.unwinder,
            self.modules,
            self.rip,
            self.rbp,
            self.rsp,
            self.stack_data,
            self.frames)
    }

    pub fn unwind_process(
        &mut self,
        process: &dyn Unwindable,
        accessor: &dyn ModuleAccessor) -> UnwindResult {
        let mut result = UnwindResult::new();

        self.unwinder.reset(
            self.rip,
            self.rbp,
            self.rsp);

        self.frames.push(self.rip);
        result.frames_pushed += 1;

        self.unwinder.unwind(
            process,
            accessor,
            self.stack_data,
            self.frames,
            &mut result);

        result
    }
}

impl CallstackReader {
    pub fn with_unwind(
        self,
        unwind: impl FnMut(&mut UnwindRequest) + 'static) -> Self {
        self.state.borrow_mut().set_unwind(unwind);
        self
    }

    pub fn read_frames(
        &self,
        full_data: &[u8],
        frames: &mut Vec<u64>) {
        self.state.write(|state| {
            /* Get frames from callchain */
            let mut data = state.callchain_field.get_data(full_data);
            let mut count = data.len() / 8;

            if count == 0 {
                /* No callchain, try to get from IP */
                if let Some(ip) = state.ip_field.try_get_u64(full_data) {
                    frames.push(ip);
                }
            }

            while count > 0 {
                let frame = u64::from_ne_bytes(
                    data[0..8]
                    .try_into()
                    .unwrap());

                /* Don't push in context frames */
                if frame < abi::PERF_CONTEXT_MAX {
                    frames.push(frame);
                }

                data = &data[8..];
                count -= 1;
            }

            /* Get remaining frames from unwinder/user_stack */
            if let Some(unwinder) = &mut state.unwinder {
                let pid: u32;

                /* Registers */
                let data = state.regs_user_field.get_data(full_data);

                /* Expected 3 registers on x64 */
                if data.len() != 24 {
                    debug!("Invalid register data length: expected=24, got={}", data.len());
                    return;
                }

                /* PID */
                match state.pid_field.try_get_u32(full_data) {
                    Some(_pid) => { pid = _pid; },
                    None => { 
                        debug!("Failed to read PID from data");
                        return; 
                    },
                }

                let rbp = u64::from_ne_bytes(data[0..8].try_into().unwrap());
                let rsp = u64::from_ne_bytes(data[8..16].try_into().unwrap());
                let rip = u64::from_ne_bytes(data[16..24].try_into().unwrap());

                /* Stack data */
                let data = state.stack_user_field.get_data(full_data);

                let mut request = UnwindRequest::new(
                    pid,
                    rip,
                    rbp,
                    rsp,
                    &mut state.machine,
                    unwinder.deref_mut(),
                    &state.modules,
                    data,
                    frames);

                (state.unwind)(&mut request);
            }
        });
    }
}

pub struct CallstackHelper {
    state: Writable<MachineState>,
    unwinder: Option<Box<dyn MachineUnwinder>>,
    external_lookup: bool,
    ip_only: bool,
    stack_size: u32,
}

impl CallstackHelper {
    fn clone_mut(&mut self) -> Self {
        Self {
            state: self.state.clone(),
            unwinder: self.unwinder.take(),
            external_lookup: self.external_lookup,
            ip_only: self.ip_only,
            stack_size: self.stack_size,
        }
    }

    pub fn new() -> Self {
        Self {
            state: Writable::new(MachineState::new()),
            unwinder: None,
            external_lookup: false,
            ip_only: false,
            stack_size: 4096,
        }
    }

    pub fn with_external_lookup(&mut self) -> Self {
        let mut clone = self.clone_mut();

        clone.external_lookup = true;

        clone
    }

    pub fn with_ip_only(&mut self) -> Self {
        let mut clone = self.clone_mut();

        clone.ip_only = true;

        clone
    }

    pub fn has_unwinder(&self) -> bool { self.unwinder.is_some() }

    #[cfg(target_arch = "x86_64")]
    pub fn with_dwarf_unwinding(&mut self) -> Self {
        let mut clone = self.clone_mut();

        clone.unwinder = Some(Box::new(default_unwinder()));

        clone
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_dwarf_unwinding(&mut self) -> Self {
        self.clone_mut()
    }

    pub fn with_stack_size(
        &mut self,
        bytes: u32) -> Self {
        let mut clone = self.clone_mut();

        clone.stack_size = bytes;

        clone
    }

    pub fn to_reader(self) -> CallstackReader {
        let unwind_op = |request: &mut UnwindRequest| {
            request.unwind_machine();
        };

        self.state.write(move |state| {
            state.unwinder = self.unwinder;
            state.set_unwind(unwind_op);
        });

        CallstackReader {
            state: self.state,
        }
    }
}

impl CallstackHelp for RingBufSessionBuilder {
    fn with_callstack_help(
        mut self,
        helper: &CallstackHelper) -> Self {
        let dwarf = helper.unwinder.is_some();
        let external_lookup = helper.external_lookup;
        let ip_only = helper.ip_only;
        let stack_size = helper.stack_size;
        let session_state = helper.state.clone();

        self.with_hooks(
            move |builder| {
                /*
                 * In all cases, when the callstack helper is used, it's
                 * assumed that they want callstacks. In both the DWARF
                 * and non-DWARF cases, we should be consistent.
                 *
                 * On per-event basis, the callstack can be configured to
                 * use just the IP via set_no_callstack_flag() to save
                 * both space and cpu consumption, if required.
                 *
                 * If only IPs are wanted for all events, the ip_only flag
                 * can be used to achieve this.
                 */
                if ip_only {
                    /* If only IP is needed, we can do a simpler setup */
                    if let Some(profiling) = builder.take_profiling_events() {
                        builder.replace_profiling_events(
                            profiling
                            .with_ip());
                    }

                    if let Some(tp) = builder.take_tracepoint_events() {
                        builder.replace_tracepoint_events(
                            tp
                            .with_ip());
                    }

                    if let Some(cswitch) = builder.take_cswitch_events() {
                        builder.replace_cswitch_events(
                            cswitch
                            .with_ip());
                    }

                    if let Some(bpf) = builder.take_bpf_events() {
                        builder.replace_bpf_events(
                            bpf
                            .with_ip());
                    }

                    return;
                }

                if !dwarf {
                    /* Non-DWARF, turn on simple callchain data */
                    if let Some(profiling) = builder.take_profiling_events() {
                        builder.replace_profiling_events(
                            profiling
                            .with_callchain_data());
                    }

                    if let Some(tp) = builder.take_tracepoint_events() {
                        builder.replace_tracepoint_events(
                            tp
                            .with_callchain_data());
                    }

                    if let Some(cswitch) = builder.take_cswitch_events() {
                        builder.replace_cswitch_events(
                            cswitch
                            .with_callchain_data());
                    }

                    if let Some(bpf) = builder.take_bpf_events() {
                        builder.replace_bpf_events(
                            bpf
                            .with_callchain_data());
                    }

                    return;
                }

                let events = builder
                    .take_kernel_events()
                    .unwrap_or_else(RingBufBuilder::for_kernel)
                    .with_mmap_records()
                    .with_comm_records()
                    .with_task_records();

                builder.replace_kernel_events(events);

                /*
                 * Sampling based events that are being used need to
                 * be configured to grab callchains for kernel only.
                 * We also need user registers and the raw user stack.
                 */
                if let Some(profiling) = builder.take_profiling_events() {
                    builder.replace_profiling_events(
                        profiling
                        .with_callchain_data()
                        .without_user_callchain_data()
                        .with_user_regs_data(
                            abi::PERF_REG_BP |
                            abi::PERF_REG_SP |
                            abi::PERF_REG_IP)
                        .with_user_stack_data(stack_size));
                }

                if let Some(tp) = builder.take_tracepoint_events() {
                    builder.replace_tracepoint_events(
                        tp
                        .with_callchain_data()
                        .without_user_callchain_data()
                        .with_user_regs_data(
                            abi::PERF_REG_BP |
                            abi::PERF_REG_SP |
                            abi::PERF_REG_IP)
                        .with_user_stack_data(stack_size));
                }

                if let Some(cswitch) = builder.take_cswitch_events() {
                    builder.replace_cswitch_events(
                        cswitch
                        .with_callchain_data()
                        .without_user_callchain_data()
                        .with_user_regs_data(
                            abi::PERF_REG_BP |
                            abi::PERF_REG_SP |
                            abi::PERF_REG_IP)
                        .with_user_stack_data(stack_size));
                }

                if let Some(bpf) = builder.take_bpf_events() {
                    builder.replace_bpf_events(
                        bpf
                        .with_callchain_data()
                        .without_user_callchain_data()
                        .with_user_regs_data(
                            abi::PERF_REG_BP |
                            abi::PERF_REG_SP |
                            abi::PERF_REG_IP)
                        .with_user_stack_data(stack_size));
                }
            },

            move |session| {
                /* Always grab callchain and IP field */
                session_state.write(|state| {
                    state.callchain_field = session.callchain_data_ref();
                    state.ip_field = session.ip_data_ref();
                });

                /* No need to hook unless DWARF with callchains */
                if !dwarf || ip_only {
                    return;
                }

                /* DWARF needs a few more fields and hooks */
                session_state.write(|state| {
                    state.pid_field = session.pid_field_ref();
                    state.regs_user_field = session.regs_user_data_ref();
                    state.stack_user_field = session.stack_user_data_ref();
                });

                /* If using an external/common lookup don't track */
                if external_lookup {
                    return;
                }

                /* Hook mmap records */
                let event = session.mmap_event();
                let fmt = event.format();
                let pid = fmt.get_field_ref_unchecked("pid");
                let addr = fmt.get_field_ref_unchecked("addr");
                let len = fmt.get_field_ref_unchecked("len");
                let pgoffset = fmt.get_field_ref_unchecked("pgoffset");
                let maj = fmt.get_field_ref_unchecked("maj");
                let min = fmt.get_field_ref_unchecked("min");
                let ino = fmt.get_field_ref_unchecked("ino");
                let prot = fmt.get_field_ref_unchecked("prot");
                let filename = fmt.get_field_ref_unchecked("filename[]");
                let state = session_state.clone();

                event.add_callback(move |data| {
                    let fmt = data.format();
                    let data = data.event_data();

                    let prot = fmt.get_u32(prot, data)? as i32;

                    /* Skip non-executable mmaps */
                    if prot & PROT_EXEC != PROT_EXEC {
                        return Ok(());
                    }

                    let mut state = state.borrow_mut();

                    state.add_mmap_exec(
                        fmt.get_u32(pid, data)?,
                        fmt.get_u64(addr, data)?,
                        fmt.get_u64(len, data)?,
                        fmt.get_u64(pgoffset, data)?,
                        fmt.get_u32(maj, data)?,
                        fmt.get_u32(min, data)?,
                        fmt.get_u64(ino, data)?,
                        fmt.get_str(filename, data)?);

                    Ok(())
                });

                /* Hook comm records */
                let event = session.comm_event();
                let fmt = event.format();
                let pid = fmt.get_field_ref_unchecked("pid");
                let tid = fmt.get_field_ref_unchecked("tid");
                let state = session_state.clone();

                event.add_callback(move |data| {
                    let fmt = data.format();
                    let data = data.event_data();

                    let pid = fmt.get_u32(pid, data)?;
                    let tid = fmt.get_u32(tid, data)?;

                    if pid != tid {
                        return Ok(())
                    }

                    state.write(|state| {
                        state.add_comm_exec(pid);
                    });

                    Ok(())
                });

                /* Hook fork records */
                let event = session.fork_event();
                let fmt = event.format();
                let pid = fmt.get_field_ref_unchecked("pid");
                let ppid = fmt.get_field_ref_unchecked("ppid");
                let tid = fmt.get_field_ref_unchecked("tid");
                let state = session_state.clone();

                event.add_callback(move |data| {
                    let fmt = data.format();
                    let data = data.event_data();

                    let pid = fmt.get_u32(pid, data)?;
                    let tid = fmt.get_u32(tid, data)?;

                    if pid != tid {
                        return Ok(());
                    }

                    let ppid = fmt.get_u32(ppid, data)?;

                    state.write(|state| {
                        state.fork(pid, ppid);
                    });

                    Ok(())
                });

                /* Hook exit records */
                let event = session.exit_event();
                let fmt = event.format();
                let pid = fmt.get_field_ref_unchecked("pid");
                let state = session_state.clone();

                event.add_callback(move |data| {
                    let fmt = data.format();
                    let data = data.event_data();

                    let pid = fmt.get_u32(pid, data)?;

                    state.write(|state| {
                        state.exit(pid);
                    });

                    Ok(())
                });
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracefs::TraceFS;

    #[test]
    #[ignore]
    fn no_callchain_flag() {
        let helper = CallstackHelper::new()
            .with_dwarf_unwinding();

        let tracepoints = RingBufBuilder::for_tracepoint()
            .with_callchain_data();

        let mut builder = RingBufSessionBuilder::new()
            .with_page_count(256)
            .with_tracepoint_events(tracepoints)
            .with_callstack_help(&helper);

        let tracefs = TraceFS::open().unwrap();
        let mut waking = tracefs.find_event("sched", "sched_waking").unwrap();

        /* This removes callchain/regs and uses only IP */
        waking.set_no_callstack_flag();

        let stack_reader = helper.to_reader();
        let mut frames = Vec::new();
        let bad_count = Writable::new(0u64);
        let callback_count = bad_count.clone();

        waking.add_callback(move |data| {
            let full_data = data.full_data();

            frames.clear();

            stack_reader.read_frames(
                full_data,
                &mut frames);

            /* We expect to only get the IP when no callstack is on */
            if frames.len() != 1 {
                *callback_count.borrow_mut() += 1;
                anyhow::bail!("Expected only IP, Len={}", frames.len());
            }

            Ok(())
        });

        let mut session = builder.build().unwrap();
        let duration = std::time::Duration::from_secs(1);

        session.add_event(waking).unwrap();

        session.enable().unwrap();
        session.parse_for_duration(duration).unwrap();
        session.disable().unwrap();

        assert_eq!(0, *bad_count.borrow());
    }

    #[test]
    #[ignore]
    fn it_works() {
        let helper = CallstackHelper::new()
            .with_dwarf_unwinding();

        let freq = 1000;

        let profiling = RingBufBuilder::for_profiling(
            freq)
            .with_callchain_data();

        let mut builder = RingBufSessionBuilder::new()
            .with_page_count(256)
            .with_profiling_events(profiling)
            .with_callstack_help(&helper);

        let mut session = builder.build().unwrap();
        let duration = std::time::Duration::from_secs(1);

        let stack_reader = helper.to_reader();
        let pid_field = session.pid_field_ref();

        let event = session.cpu_profile_event();
        let mut frames = Vec::new();

        event.add_callback(move |data| {
            let full_data = data.full_data();

            let pid = pid_field.try_get_u32(full_data).unwrap();
            frames.clear();

            stack_reader.read_frames(
                full_data,
                &mut frames);

            println!("PID {}:", pid);

            for frame in &frames {
                println!("0x{:X}", frame);
            }

            println!("");

            Ok(())
        });

        session.lost_event().add_callback(|_| {
            println!("WARN: Lost event data");

            Ok(())
        });

        session.lost_samples_event().add_callback(|_| {
            println!("WARN: Lost samples data");

            Ok(())
        });

        session.capture_environment();
        session.enable().unwrap();
        session.parse_for_duration(duration).unwrap();
        session.disable().unwrap();
    }
}
