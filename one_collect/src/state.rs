use std::collections::HashMap;

#[derive(Copy,Default,Debug)]
pub struct ProcessTrackingOptions {
    process_names: bool,
}

impl ProcessTrackingOptions {
    pub fn new() -> Self {
        ProcessTrackingOptions {
             process_names: false,
        }
    }

    pub fn with_process_names(&mut self) -> Self {
        Self {
            process_names: true,
        }
    }

    pub(crate) fn process_names(&self) -> bool {
        self.process_names
    }

    pub(crate) fn any(&self) -> bool {
        self.process_names()
    }
}

impl Clone for ProcessTrackingOptions {
    fn clone(&self) -> Self {
        ProcessTrackingOptions {
            process_names: self.process_names,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.process_names = source.process_names;
    }
}

pub struct ProcessState {
    pid: u32,
    name: Option<String>,
}

impl ProcessState {
    pub(crate) fn new(pid: u32) -> ProcessState {
        ProcessState {
            pid,
            name: None,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn name(&self) -> &str {
        match self.name.as_deref() {
            Some(name) => name,
            None => "",
        }
    }

    pub(crate) fn set_name(&mut self, name: &str) {
        self.name = Some(String::from(name));
    }

    fn fork(&self, pid: u32) -> Self {
        ProcessState {
            pid,
            name: match &self.name {
                Some(name)=> Some(String::from(name)),
                None => None,
            }
        }
    }

    fn reset(&mut self) {
        self.name = None;
    }
}

pub struct SessionState {
    live_processes: HashMap<u32, ProcessState>,
}

impl SessionState {
    pub(crate) fn new() -> SessionState {
        SessionState {
            live_processes: HashMap::new(),
        }
    }

    pub(crate) fn new_process(&mut self, pid: u32) -> &mut ProcessState {
        self.live_processes.entry(pid)
            .and_modify(|proc| { proc.reset() })
            .or_insert_with(|| ProcessState::new(pid))
    }

    pub(crate) fn fork_process(&mut self, pid: u32, ppid: u32) {
        if let Some(proc) = self.live_processes.get(&ppid) {
            self.live_processes.insert(pid, proc.fork(pid));
        }
        else {
            self.new_process(pid);
        }
    }

    pub(crate) fn drop_process(&mut self, pid: u32) {
        self.live_processes.remove(&pid);
    }

    pub fn process(&self, pid: u32) -> Option<&ProcessState> {
        self.live_processes.get(&pid)
    }

    pub fn process_mut(&mut self, pid: u32) -> Option<&mut ProcessState> {
        self.live_processes.get_mut(&pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_process() {
        let mut session_state = SessionState::new();

        let pid = 1000;
        assert!(session_state.process(pid).is_none());
        session_state.new_process(pid);

        let process_state = session_state.process(pid).unwrap();
        assert_eq!(process_state.pid(), pid);
        assert_eq!(process_state.name(), "");

        let process_state = session_state.process_mut(pid).unwrap();
        assert_eq!(process_state.pid(), pid);
        assert_eq!(process_state.name(), "");

        let name = "process-name";
        process_state.set_name(name);
        assert_eq!(process_state.name(), name);

        let process_state = session_state.process(pid).unwrap();
        assert_eq!(process_state.pid(), pid);
        assert_eq!(process_state.name(), name);

        session_state.drop_process(pid);
        let process_state = session_state.process(pid);
        assert!(process_state.is_none());
    }

    #[test]
    fn reuse_pid_without_drop() {
        let mut session_state = SessionState::new();

        let pid = 1000;
        session_state.new_process(pid);

        let process_state = session_state.process_mut(pid).unwrap();
        assert_eq!(process_state.pid(), pid);
        assert_eq!(process_state.name(), "");

        let name = "process-name";
        process_state.set_name(name);
        assert_eq!(process_state.name(), name);

        session_state.new_process(pid);
        let process_state = session_state.process(pid).unwrap();
        assert_eq!(process_state.pid(), pid);
        assert_eq!(process_state.name(), "");
    }

    #[test]
    fn reuse_pid_with_drop() {
        let mut session_state = SessionState::new();

        let pid = 1000;
        session_state.new_process(pid);

        let process_state = session_state.process_mut(pid).unwrap();
        assert_eq!(process_state.pid(), pid);
        assert_eq!(process_state.name(), "");

        let name = "process-name";
        process_state.set_name(name);
        assert_eq!(process_state.name(), name);

        session_state.drop_process(pid);
        assert!(session_state.process(pid).is_none());

        session_state.new_process(pid);
        let process_state = session_state.process(pid).unwrap();
        assert_eq!(process_state.pid(), pid);
        assert_eq!(process_state.name(), "");
    }

    #[test]
    fn fork() {
        let mut session_state = SessionState::new();

        let pid = 1000;
        session_state.new_process(pid);

        let process_state = session_state.process_mut(pid).unwrap();
        assert_eq!(process_state.pid(), pid);
        assert_eq!(process_state.name(), "");

        let name = "process-name";
        process_state.set_name(name);
        assert_eq!(process_state.name(), name);

        let new_pid = 1001;
        session_state.fork_process(new_pid, pid);

        let process_state = session_state.process(new_pid).unwrap();
        assert_eq!(process_state.pid(), new_pid);
        assert_eq!(process_state.name(), name);
    }

    #[test]
    fn fork_nonexistent_process() {
        let mut session_state = SessionState::new();

        let pid = 1000;
        let ppid = 1001;
        session_state.fork_process(pid, ppid);
        assert!(session_state.process(ppid).is_none());

        let process_state = session_state.process(pid).unwrap();
        assert_eq!(process_state.pid(), pid);
        assert_eq!(process_state.name(), "");
    }
}