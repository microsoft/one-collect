use super::*;

impl Machine {
    pub fn new() -> Self { Self::default() }

    pub fn add_process(
        &mut self,
        pid: u32,
        process: Process) -> bool {
        match self.processes.entry(pid) {
            Vacant(entry) => {
                entry.insert(process);
                true
            },
            Occupied(_) => {
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
            Some(parent) => { child = parent.fork(); },
            None => { return false },
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
            Some(_) => { true },
            None => { false },
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
            },
            None => {
                /* Process not mapped */
                result.error = Some("Process not mapped");
            },
        }

        result
    }
}
