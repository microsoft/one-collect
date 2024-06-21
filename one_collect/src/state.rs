use std::collections::HashMap;

/// Struct representing the options to track a process.
#[derive(Copy,Default,Debug)]
pub struct ProcessTrackingOptions {
    process_names: bool,
}

impl ProcessTrackingOptions {
    /// Creates a new `ProcessTrackingOptions` instance with `process_names` set to false.
    ///
    /// # Returns
    ///
    /// A new `ProcessTrackingOptions` instance.
    pub fn new() -> Self {
        ProcessTrackingOptions {
             process_names: false,
        }
    }

    /// Returns a new `ProcessTrackingOptions` instance with `process_names` set to true.
    ///
    /// # Returns
    ///
    /// A new `ProcessTrackingOptions` instance.
    pub fn with_process_names(&mut self) -> Self {
        Self {
            process_names: true,
        }
    }

    /// Returns the value of `process_names`.
    ///
    /// # Returns
    ///
    /// A boolean value representing if process names are to be tracked.
    pub(crate) fn process_names(&self) -> bool {
        self.process_names
    }

    /// Returns true if any tracking option is set, false otherwise.
    ///
    /// # Returns
    ///
    /// A boolean value indicating if any tracking option is set.
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

/// Struct representing the state of a process.
pub struct ProcessState {
    pid: u32,
    name: Option<String>,
}

impl ProcessState {
    /// Creates a new `ProcessState` instance with the given `pid` and `name` set to `None`.
    ///
    /// # Parameters
    ///
    /// * `pid`: The process id.
    ///
    /// # Returns
    ///
    /// A new `ProcessState` instance.
    pub(crate) fn new(pid: u32) -> ProcessState {
        ProcessState {
            pid,
            name: None,
        }
    }

    /// Returns the process id of the `ProcessState`.
    ///
    /// # Returns
    ///
    /// A `u32` representing the process id.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the name of the `ProcessState` if present, and an empty string if not.
    ///
    /// # Returns
    ///
    /// A `&str` representing the process name or an empty string.
    pub fn name(&self) -> &str {
        match self.name.as_deref() {
            Some(name) => name,
            None => "",
        }
    }

    /// Sets the name of the `ProcessState`.
    ///
    /// # Parameters
    ///
    /// * `name`: A `&str` representing the new process name.
    pub(crate) fn set_name(&mut self, name: &str) {
        self.name = Some(String::from(name));
    }

    /// Creates a new `ProcessState` instance by forking the current one and changing the `pid`.
    ///
    /// # Parameters
    ///
    /// * `pid`: The process id.
    ///
    /// # Returns
    ///
    /// A new `ProcessState` instance.
    fn fork(&self, pid: u32) -> Self {
        ProcessState {
            pid,
            name: match &self.name {
                Some(name)=> Some(String::from(name)),
                None => None,
            }
        }
    }

    /// Resets the `ProcessState`.
    fn reset(&mut self) {
        self.name = None;
    }
}

/// Struct representing the state of a session.
pub struct SessionState {
    live_processes: HashMap<u32, ProcessState>,
}

impl SessionState {
    /// Creates a new `SessionState` instance with an empty `live_processes` map.
    ///
    /// # Returns
    ///
    /// A new `SessionState` instance.
    pub(crate) fn new() -> SessionState {
        SessionState {
            live_processes: HashMap::new(),
        }
    }

    /// Creates a new process with the given `pid` or resets the process if it already exists.
    ///
    /// # Parameters
    ///
    /// * `pid`: The process id.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `ProcessState` of the new or reset process.
    pub(crate) fn new_process(&mut self, pid: u32) -> &mut ProcessState {
        self.live_processes.entry(pid)
            .and_modify(|proc| { proc.reset() })
            .or_insert_with(|| ProcessState::new(pid))
    }

    /// Creates a new process by forking an existing one with `ppid` or creates a new process if it doesn't exist.
    ///
    /// # Parameters
    ///
    /// * `pid`: The process id.
    /// * `ppid`: The parent process id.
    pub(crate) fn fork_process(&mut self, pid: u32, ppid: u32) {
        if let Some(proc) = self.live_processes.get(&ppid) {
            self.live_processes.insert(pid, proc.fork(pid));
        }
        else {
            self.new_process(pid);
        }
    }

    /// Removes the process with the given `pid` from `live_processes`.
    ///
    /// # Parameters
    ///
    /// * `pid`: The process id.
    pub(crate) fn drop_process(&mut self, pid: u32) {
        self.live_processes.remove(&pid);
    }

    /// Returns a reference to the `ProcessState` of the process with the given `pid` if it exists.
    ///
    /// # Parameters
    ///
    /// * `pid`: The process id.
    ///
    /// # Returns
    ///
    /// An `Option` containing a reference to the `ProcessState` if it exists, `None` otherwise.
    pub fn process(&self, pid: u32) -> Option<&ProcessState> {
        self.live_processes.get(&pid)
    }

    /// Returns a mutable reference to the `ProcessState` of the process with the given `pid` if it exists.
    ///
    /// # Parameters
    ///
    /// * `pid`: The process id.
    ///
    /// # Returns
    ///
    /// An `Option` containing a mutable reference to the `ProcessState` if it exists, `None` otherwise.
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
