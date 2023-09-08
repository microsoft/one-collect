use std::collections::HashMap;

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
}

pub struct SessionState {
    live_processes: HashMap<u32, Box<ProcessState>>,
}

impl SessionState {
    pub(crate) fn new() -> SessionState {
        SessionState {
            live_processes: HashMap::new(),
        }
    }

    pub(crate) fn new_process(&mut self, pid: u32) -> &mut ProcessState {
        let state = Box::new(ProcessState::new(pid));
        self.live_processes.insert(pid, state);
        self.live_processes.get_mut(&pid).unwrap()
    }

    pub(crate) fn drop_process(&mut self, pid: u32) {
        self.live_processes.remove(&pid);
    }

    pub fn process(&self, pid: u32) -> Option<&ProcessState> {
        match self.live_processes.get(&pid) {
            Some(state) => Some(state),
            None => None,
        }
    }

    pub fn process_mut(&mut self, pid: u32) -> Option<&mut ProcessState> {
        match self.live_processes.get_mut(&pid) {
            Some(state) => Some(state),
            None => None,
        }
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
}