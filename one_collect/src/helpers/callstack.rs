use std::os::fd::{IntoRawFd, RawFd};
use std::collections::HashMap;
use std::collections::hash_map::Entry::Vacant;
use crate::perf_event::*;
use crate::Writable;

use ruwind::*;

const PROT_EXEC: u32 = 4;

struct MachineState {
    machine: Machine,
    module_fds: HashMap<ModuleKey, RawFd>,
    path: String,
}

impl MachineState {
    fn new() -> Self {
        Self {
            machine: Machine::new(),
            module_fds: HashMap::new(),
            path: String::new(),
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

            if let Vacant(entry) = self.module_fds.entry(key) {
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

pub struct CallstackHelper {
    state: Writable<MachineState>,
}

impl CallstackHelper {
    pub fn new() -> Self {
        Self {
            state: Writable::new(MachineState::new()),
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
        let session_state = helper.state.clone();

        self.with_hooks(
            move |builder| {
                let events = builder
                    .take_kernel_events()
                    .unwrap_or_else(RingBufBuilder::for_kernel)
                    .with_mmap_records()
                    .with_comm_records()
                    .with_task_records();

                builder.replace_kernel_events(events);
            },

            move |session| {
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
        let helper = CallstackHelper::new();

        let options = RingBufOptions::new()
            .with_callchain_data();

        let freq = 1000;

        let profiling = RingBufBuilder::for_profiling(
            &options,
            freq);

        let mut builder = RingBufSessionBuilder::new()
            .with_profiling_events(profiling)
            .with_callstack_help(&helper);

        let mut session = builder.build().unwrap();
        let duration = std::time::Duration::from_secs(10);

        session.enable().unwrap();
        session.parse_for_duration(duration).unwrap();
        session.disable().unwrap();
    }
}
