use std::fs::File;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::ops::DerefMut;
use std::collections::HashMap;
use std::collections::hash_map::Entry::{self, Vacant};
use crate::perf_event::*;
use crate::event::DataFieldRef;
use crate::Writable;

use ruwind::*;

/* Libc calls */
const PROT_EXEC: u32 = 4;

extern "C" {
    fn dup(fd: RawFd) -> RawFd;
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
    pid_field: DataFieldRef,
    callchain_field: DataFieldRef,
    regs_user_field: DataFieldRef,
    stack_user_field: DataFieldRef,
    path: String,
    unwinder: Option<Box<dyn MachineUnwinder>>,
}

impl MachineState {
    fn new() -> Self {
        let empty = DataFieldRef::default();

        Self {
            machine: Machine::new(),
            modules: ModuleLookup::new(),
            pid_field: empty.clone(),
            callchain_field: empty.clone(),
            regs_user_field: empty.clone(),
            stack_user_field: empty.clone(),
            path: String::new(),
            unwinder: None,
        }
    }

    fn add_comm_exec(
        &mut self,
        pid: u32) {
        self.machine.add_process(
            pid,
            Process::new());
    }

    fn fork(
        &mut self,
        pid: u32,
        ppid: u32) {
        self.machine.fork_process(pid, ppid);
    }

    fn exit(
        &mut self,
        pid: u32) {
        self.machine.remove_process(pid);
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
                self.path.push_str("/proc/");
                self.path.push_str(&pid.to_string());
                self.path.push_str("/root");
                self.path.push_str(filename);

                /* Only insert if we can actually open it */
                if let Ok(file) = std::fs::File::open(&self.path) {
                    entry.insert(file.into_raw_fd());
                }
            }
        }

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
                    ino);
            } else {
                module = Module::new_anon(
                    start,
                    end);
            }

            process.add_module(module);
        }
    }
}

pub struct CallstackReader {
    state: Writable<MachineState>,
}

impl CallstackReader {
    pub fn read_frames(
        &self,
        full_data: &[u8],
        frames: &mut Vec<u64>) {
        self.state.write(|state| {
            /* Get frames from callchain */
            let mut data = state.callchain_field.get_data(full_data);
            let mut count = data.len() / 8;

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

                /* PID */
                match state.pid_field.try_get_u32(full_data) {
                    Some(_pid) => { pid = _pid; },
                    None => { return; },
                }

                /* Registers */
                let data = state.regs_user_field.get_data(full_data);

                /* Expected 3 registers on x64 */
                if data.len() != 24 {
                    return;
                }

                let rbp = u64::from_ne_bytes(data[0..8].try_into().unwrap());
                let rsp = u64::from_ne_bytes(data[8..16].try_into().unwrap());
                let rip = u64::from_ne_bytes(data[16..24].try_into().unwrap());

                /* Stack data */
                let data = state.stack_user_field.get_data(full_data);

                state.machine.unwind_process(
                    pid,
                    unwinder.deref_mut(),
                    &state.modules,
                    rip,
                    rbp,
                    rsp,
                    data,
                    frames);
            }
        });
    }
}

impl Clone for CallstackReader {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone()
        }
    }
}

pub struct CallstackHelper {
    state: Writable<MachineState>,
    unwinder: Option<Box<dyn MachineUnwinder>>,
    stack_size: u32,
}

impl CallstackHelper {
    fn clone_mut(&mut self) -> Self {
        Self {
            state: self.state.clone(),
            unwinder: self.unwinder.take(),
            stack_size: self.stack_size,
        }
    }

    pub fn new() -> Self {
        Self {
            state: Writable::new(MachineState::new()),
            unwinder: None,
            stack_size: 4096,
        }
    }

    pub fn with_dwarf_unwinding(&mut self) -> Self {
        let mut clone = self.clone_mut();

        clone.unwinder = Some(Box::new(default_unwinder()));

        clone
    }

    pub fn with_stack_size(
        &mut self,
        bytes: u32) -> Self {
        let mut clone = self.clone_mut();

        clone.stack_size = bytes;

        clone
    }

    pub fn to_reader(self) -> CallstackReader {
        self.state.write(|state| {
            state.unwinder = self.unwinder;
        });

        CallstackReader {
            state: self.state,
        }
    }
}

pub trait CallstackHelp {
    fn with_callstack_help(
        &mut self,
        helper: &CallstackHelper) -> Self;
}

impl CallstackHelp for RingBufSessionBuilder {
    fn with_callstack_help(
        &mut self,
        helper: &CallstackHelper) -> Self {
        let dwarf = helper.unwinder.is_some();
        let stack_size = helper.stack_size;
        let session_state = helper.state.clone();

        self.with_hooks(
            move |builder| {
                /* No need to change builder unless DWARF */
                if !dwarf {
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
            },

            move |session| {
                /* Always grab callchain field */
                session_state.write(|state| {
                    state.callchain_field = session.callchain_data_ref();
                });

                /* No need to hook unless DWARF */
                if !dwarf {
                    return;
                }

                /* DWARF needs a few more fields and hooks */
                session_state.write(|state| {
                    state.pid_field = session.pid_field_ref();
                    state.regs_user_field = session.regs_user_data_ref();
                    state.stack_user_field = session.stack_user_data_ref();
                });

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

                event.add_callback(move |_full_data,fmt,data| {
                    let prot = fmt.try_get_u32(prot, data).unwrap();

                    /* Skip non-executable mmaps */
                    if prot & PROT_EXEC != PROT_EXEC {
                        return;
                    }

                    state.write(|state| {
                        state.add_mmap_exec(
                            fmt.try_get_u32(pid, data).unwrap(),
                            fmt.try_get_u64(addr, data).unwrap(),
                            fmt.try_get_u64(len, data).unwrap(),
                            fmt.try_get_u64(pgoffset, data).unwrap(),
                            fmt.try_get_u32(maj, data).unwrap(),
                            fmt.try_get_u32(min, data).unwrap(),
                            fmt.try_get_u64(ino, data).unwrap(),
                            fmt.try_get_str(filename, data).unwrap());
                    });
                });

                /* Hook comm records */
                let event = session.comm_event();
                let fmt = event.format();
                let pid = fmt.get_field_ref_unchecked("pid");
                let tid = fmt.get_field_ref_unchecked("tid");
                let state = session_state.clone();

                event.add_callback(move |_full_data,fmt,data| {
                    let pid = fmt.try_get_u32(pid, data).unwrap();
                    let tid = fmt.try_get_u32(tid, data).unwrap();

                    if pid != tid {
                        return;
                    }

                    state.write(|state| {
                        state.add_comm_exec(pid);
                    });
                });

                /* Hook fork records */
                let event = session.fork_event();
                let fmt = event.format();
                let pid = fmt.get_field_ref_unchecked("pid");
                let ppid = fmt.get_field_ref_unchecked("ppid");
                let tid = fmt.get_field_ref_unchecked("tid");
                let state = session_state.clone();

                event.add_callback(move |_full_data,fmt,data| {
                    let pid = fmt.try_get_u32(pid, data).unwrap();
                    let tid = fmt.try_get_u32(tid, data).unwrap();

                    if pid != tid {
                        return;
                    }

                    let ppid = fmt.try_get_u32(ppid, data).unwrap();

                    state.write(|state| {
                        state.fork(pid, ppid);
                    });
                });

                /* Hook exit records */
                let event = session.exit_event();
                let fmt = event.format();
                let pid = fmt.get_field_ref_unchecked("pid");
                let state = session_state.clone();

                event.add_callback(move |_full_data,fmt,data| {
                    let pid = fmt.try_get_u32(pid, data).unwrap();

                    state.write(|state| {
                        state.exit(pid);
                    });
                });
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        event.add_callback(move |full_data,_fmt,_data| {
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
        });

        session.lost_event().add_callback(|_,_,_| {
            println!("WARN: Lost event data");
        });

        session.lost_samples_event().add_callback(|_,_,_| {
            println!("WARN: Lost samples data");
        });

        session.enable().unwrap();
        session.parse_for_duration(duration).unwrap();
        session.disable().unwrap();
    }
}
