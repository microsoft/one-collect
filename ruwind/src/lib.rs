use std::collections::HashMap;
use std::collections::hash_map::Entry::{Vacant, Occupied};
use std::fs::File;
use std::hash::{Hash, Hasher};

pub mod elf;
pub mod dwarf;

mod module;
mod process;
mod machine;

#[derive(Eq, Copy)]
pub struct ModuleKey {
    pub dev: u64,
    pub ino: u64,
}

impl Hash for ModuleKey {
    fn hash<H: Hasher>(
        &self,
        state: &mut H) {
        self.dev.hash(state);
        self.ino.hash(state);
    }
}

pub struct UnwindResult {
    pub frames_pushed: usize,
    pub error: Option<&'static str>,
}

impl UnwindResult {
    pub fn new() -> Self {
        Self {
            frames_pushed: 0,
            error: None,
        }
    }
}

impl Default for UnwindResult {
    fn default() -> Self {
        Self::new()
    }
}

pub trait MachineUnwinder {
    fn reset(
        &mut self,
        rip: u64,
        rbp: u64,
        rsp: u64);

    fn unwind(
        &mut self,
        process: &Process,
        accessor: &dyn ModuleAccessor,
        stack_data: &[u8],
        stack_frames: &mut Vec<u64>,
        result: &mut UnwindResult);
}

pub trait ModuleAccessor {
    fn open(
        &self,
        key: &ModuleKey) -> Option<File>;
}

#[derive(Eq)]
pub struct Module {
    start: u64,
    end: u64,
    offset: u64,
    key: ModuleKey,
    anon: bool,
}

#[derive(Default)]
pub struct Process {
    mods: Vec<Module>,
    sorted: bool,
}

#[derive(Default)]
pub struct Machine {
    processes: HashMap<u32, Process>,
}

#[cfg(target_arch = "x86_64")]
pub fn default_unwinder() -> impl MachineUnwinder {
    #[path = "x64unwinder.rs"]
    mod unwinder;
    unwinder::Unwinder::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};

    struct SingleAccessor {
    }

    impl ModuleAccessor for SingleAccessor {
        fn open(
            &self,
            _key: &ModuleKey) -> Option<File> {
            match File::open("test_assets/test") {
                Ok(file) => { Some(file) },
                Err(_) => { None },
            }
        }
    }

    #[test]
    fn it_works() {
        let mut unwinder = default_unwinder();
        let mut machine = Machine::new();

        /* Pull these from stack_gen program */
        let rip: u64 = 0x5601ed65766d;
        let rsp: u64 = 0x7ffeee363070;
        let rbp: u64 = 0x7ffeee363090;
        let start: u64 = 0x5601ed657000;
        let end: u64 = 0x5601ed658000;
        let off: u64 = 0x1000;

        let accessor = SingleAccessor {};
        let mut proc = Process::new();
        let module = Module::new(start, end, off, 0, 0);
        let stack_data = fs::read("test_assets/test.data").unwrap();
        let mut stack_frames: Vec<u64> = Vec::new();

        proc.add_module(module);
        assert!(machine.add_process(0, proc));

        let result = machine.unwind_process(
            0,
            &mut unwinder,
            &accessor,
            rip,
            rbp,
            rsp,
            &stack_data[..],
            &mut stack_frames);

        println!("Got {} frames:", result.frames_pushed);

        for ip in stack_frames {
            println!("0x{:X}", ip);
        }

        if let Some(error) = result.error {
            println!("Error: {}", error);
        }

        assert!(machine.remove_process(0));
    }
}
