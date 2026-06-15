// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use tracing::{debug, warn, error, trace};

impl Machine {
    pub fn new() -> Self { Self::default() }

    pub fn add_process(
        &mut self,
        pid: u32,
        process: Process) -> bool {
        match self.processes.entry(pid) {
            Vacant(entry) => {
                debug!("Process added: pid={}", pid);
                entry.insert(process);
                true
            },
            Occupied(_) => {
                debug!("Process already exists: pid={}", pid);
                false
            }
        }
    }

    pub fn fork_process(
        &mut self,
        pid: u32,
        ppid: u32) -> bool {
        let child: Process;

        match self.find_process(ppid) {
            Some(parent) => {
                debug!("Process forked: pid={}, ppid={}", pid, ppid);
                child = parent.fork();
            },
            None => {
                warn!("Process fork failed: ppid={} not found", ppid);
                return false
            },
        }

        self.add_process(pid, child)
    }

    pub fn find_process(
        &mut self,
        pid: u32) -> Option<&mut Process> {
        self.processes.get_mut(&pid)
    }

    pub fn remove_process(
        &mut self,
        pid: u32) -> bool {
        match self.processes.remove(&pid) {
            Some(_) => {
                debug!("Process removed: pid={}", pid);
                true
            },
            None => {
                warn!("Process removal failed: pid={} not found", pid);
                false
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn unwind_process(
        &mut self,
        pid: u32,
        unwinder: &mut dyn MachineUnwinder,
        accessor: &dyn ModuleAccessor,
        rip: u64,
        rbp: u64,
        rsp: u64,
        stack_data: &[u8],
        stack_frames: &mut Vec<u64>) -> UnwindResult {
        let mut result = UnwindResult::new();

        trace!("Starting unwind: pid={}, rip={:#x}, rbp={:#x}, rsp={:#x}", pid, rip, rbp, rsp);

        /* Reset unwinder */
        unwinder.reset(
            rip,
            rbp,
            rsp);

        /* Always push IP */
        stack_frames.push(rip);
        result.frames_pushed += 1;

        match self.processes.get_mut(&pid) {
            Some(process) => {
                /* Ensure sorted */
                process.sort();

                /* Unwind process via unwinder */
                unwinder.unwind(
                    process,
                    accessor,
                    stack_data,
                    stack_frames,
                    &mut result);

                trace!("Unwind completed: pid={}, frames_pushed={}", pid, result.frames_pushed);
                if let Some(error) = result.error {
                    debug!("Unwind stopped with error: {}", error);
                }
            },
            None => {
                /* Process not mapped */
                error!("Process not found for unwinding: pid={}", pid);
                result.error = Some(UnwindError::ProcessNotMapped);
            },
        }

        result
    }
}
