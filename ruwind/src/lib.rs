// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::HashMap;
use std::collections::hash_map::Entry::{Vacant, Occupied};
use std::fs::File;
use std::hash::{Hash, Hasher};

pub mod elf;
pub mod dwarf;

mod module;
mod process;
mod machine;

pub trait Unwindable {
    fn find<'a>(
        &'a self,
        ip: u64) -> Option<&'a dyn CodeSection>;
}

pub trait CodeSection {
    fn anon(&self) -> bool;

    fn unwind_type(&self) -> UnwindType;

    fn rva(
        &self,
        ip: u64) -> u64;

    fn key(&self) -> ModuleKey;
}

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UnwindError {
    AnonPrologNotFound,
    RegisterOutOfRange,
    NoReturnAddressRegister,
    CfaWouldGoBackwards,
    BadStackRbpRead,
    BadStackIpRead,
    NoModuleFound,
    ProcessNotMapped,
}

impl UnwindError {
    pub fn as_str(self) -> &'static str {
        match self {
            UnwindError::AnonPrologNotFound => "Anon prolog not found",
            UnwindError::RegisterOutOfRange => "Register out of range",
            UnwindError::NoReturnAddressRegister => "No return address register",
            UnwindError::CfaWouldGoBackwards => "CFA would go backwards",
            UnwindError::BadStackRbpRead => "Bad stack RBP read",
            UnwindError::BadStackIpRead => "Bad stack IP read",
            UnwindError::NoModuleFound => "No module found",
            UnwindError::ProcessNotMapped => "Process not mapped",
        }
    }
}

impl std::fmt::Display for UnwindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub struct UnwindResult {
    pub frames_pushed: usize,
    pub error: Option<UnwindError>,
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
        process: &dyn Unwindable,
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

#[derive(Debug, Eq, Clone, Copy, PartialEq)]
pub enum UnwindType {
    DWARF,
    Prolog,
}

#[derive(Eq, Clone, Copy)]
pub struct Module {
    start: u64,
    end: u64,
    offset: u64,
    va_offset: u64,
    key: ModuleKey,
    anon: bool,
    unwind_type: UnwindType,
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
#[cfg(target_arch = "x86_64")]
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
        let module = Module::new(start, end, off, 0, 0, 0, UnwindType::DWARF);
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

    /*
     * The following tests cover the prolog/scan/fallback paths added
     * to the x86_64 unwinder for issue #255 without requiring real
     * .eh_frame data:
     *
     *   - prolog_rbp_chain_finds_return_address: the RBP-chain walk
     *     in `unwind_prolog` recognises a well-formed `[rbp]/[rbp+8]`
     *     pair and returns the saved return address.
     *
     *   - prolog_skips_one_chain_link_to_find_caller: the chain walk
     *     can skip a frame whose `[rbp+8]` is not a valid code address
     *     and follow `[rbp]` to the next link.
     *
     *   - prolog_scan_finds_return_address_when_chain_invalid: when
     *     the RBP chain is corrupt (bad alignment) the linear scan
     *     finds the (saved_rsp, return_addr) pair.
     *
     *   - prolog_scan_exhausted_returns_no_frame: when no plausible
     *     pair exists in the captured stack the unwinder gives up
     *     cleanly.
     *
     *   - dwarf_lookup_miss_falls_back_to_prolog_walk: a DWARF module
     *     whose accessor cannot supply an ELF file (so FDE lookup
     *     fails with "No module found") triggers the prolog walk
     *     fallback so unwinding still progresses.
     *
     *   - scan_recovery_when_unwound_ip_is_outside_any_module: when
     *     the prolog walk produces a return address that lies outside
     *     any registered module the loop terminates without trying to
     *     dereference further frames (no infinite walk, no panic).
     */

    struct NoFileAccessor;

    impl ModuleAccessor for NoFileAccessor {
        fn open(
            &self,
            _key: &ModuleKey) -> Option<File> {
            None
        }
    }

    /// Builds a stack buffer that begins at `rsp` and is `len` bytes long.
    /// `writes` is a list of `(stack_addr, value)` pairs to place at
    /// the chosen stack addresses (each value is written as an 8-byte
    /// little-endian u64).
    fn build_stack(
        rsp: u64,
        len: usize,
        writes: &[(u64, u64)]) -> Vec<u8> {
        let mut data = vec![0u8; len];

        for (addr, value) in writes {
            assert!(*addr >= rsp,
                "stack write addr {:#x} below rsp {:#x}", addr, rsp);
            let offset = (*addr - rsp) as usize;
            assert!(offset + 8 <= len,
                "stack write at {:#x} exceeds stack buffer", addr);
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        data
    }

    /// Helper to drive a single unwind through the public API.
    fn run_unwind(
        proc: Process,
        rip: u64,
        rbp: u64,
        rsp: u64,
        stack_data: &[u8]) -> (UnwindResult, Vec<u64>) {
        let mut unwinder = default_unwinder();
        let mut machine = Machine::new();
        let accessor = NoFileAccessor;
        let mut stack_frames: Vec<u64> = Vec::new();

        assert!(machine.add_process(1, proc));
        let result = machine.unwind_process(
            1,
            &mut unwinder,
            &accessor,
            rip,
            rbp,
            rsp,
            stack_data,
            &mut stack_frames);
        assert!(machine.remove_process(1));

        (result, stack_frames)
    }

    #[test]
    fn prolog_rbp_chain_finds_return_address() {
        /* Single anonymous (Prolog-style) module covers both the
         * starting IP and the return address we expect to recover. */
        let module_start: u64 = 0x4000_0000;
        let module_end:   u64 = 0x4000_1000;
        let rip:          u64 = 0x4000_0500;
        let return_addr:  u64 = 0x4000_0700;

        let rsp: u64 = 0x7000_0000;
        let rbp: u64 = 0x7000_0040;
        let saved_rbp: u64 = 0x7000_0080;

        /* [rbp] = saved_rbp ; [rbp+8] = return_addr */
        let stack = build_stack(
            rsp,
            512,
            &[(rbp, saved_rbp), (rbp + 8, return_addr)]);

        let mut proc = Process::new();
        proc.add_module(Module::new_anon(module_start, module_end));

        let (result, frames) = run_unwind(proc, rip, rbp, rsp, &stack);

        /* Initial IP plus at least one unwound frame containing the
         * return address; the trailing frame is popped by the unwind
         * loop's "stopped" cleanup which is why we don't check the
         * very last entry. */
        assert!(
            frames.contains(&return_addr),
            "expected return_addr {:#x} in frames {:?}", return_addr, frames);
        assert!(result.frames_pushed >= 2);
    }

    #[test]
    fn prolog_skips_one_chain_link_to_find_caller() {
        /* The chain walker should follow [rbp] when [rbp+8] is junk
         * and stop at the first link whose [rbp+8] is a valid IP. */
        let module_start: u64 = 0x4000_0000;
        let module_end:   u64 = 0x4000_1000;
        let rip:          u64 = 0x4000_0500;
        let return_addr:  u64 = 0x4000_0900;
        let bogus_ra:     u64 = 0xdead_beef_dead_beef;

        let rsp:        u64 = 0x7000_0000;
        let rbp:        u64 = 0x7000_0040;
        let next_rbp:   u64 = 0x7000_0080;
        let final_rbp:  u64 = 0x7000_00c0;

        let stack = build_stack(
            rsp,
            512,
            &[
                (rbp,         next_rbp),    /* link 1: saved rbp */
                (rbp + 8,     bogus_ra),    /* link 1: junk return addr */
                (next_rbp,    final_rbp),   /* link 2: saved rbp */
                (next_rbp + 8, return_addr),/* link 2: real return addr */
            ]);

        let mut proc = Process::new();
        proc.add_module(Module::new_anon(module_start, module_end));

        let (_result, frames) = run_unwind(proc, rip, rbp, rsp, &stack);

        assert!(
            frames.contains(&return_addr),
            "expected return_addr {:#x} in frames {:?}", return_addr, frames);
        assert!(!frames.contains(&bogus_ra),
            "bogus_ra {:#x} should not have been pushed: frames {:?}",
            bogus_ra, frames);
    }

    #[test]
    fn prolog_scan_finds_return_address_when_chain_invalid() {
        /* Misalign rbp so the chain walker rejects it (alignment guard);
         * place a (cfa, ip) scan pair further up the stack. */
        let module_start: u64 = 0x4000_0000;
        let module_end:   u64 = 0x4000_1000;
        let rip:          u64 = 0x4000_0500;
        let return_addr:  u64 = 0x4000_0a00;

        let rsp:    u64 = 0x7000_0000;
        let rbp:    u64 = 0x7000_0041; /* misaligned, breaks chain walk */
        let new_rsp: u64 = 0x7000_0100;

        /* The scan looks for first > cfa && first <= cfa + len, then
         * checks that the following slot is a valid IP. cfa equals rsp
         * here because reset() seeds REG_RSP from rsp. */
        let stack = build_stack(
            rsp,
            512,
            &[(rsp + 0x40, new_rsp), (rsp + 0x48, return_addr)]);

        let mut proc = Process::new();
        proc.add_module(Module::new_anon(module_start, module_end));

        let (_result, frames) = run_unwind(proc, rip, rbp, rsp, &stack);

        assert!(
            frames.contains(&return_addr),
            "expected return_addr {:#x} in frames {:?}", return_addr, frames);
    }

    #[test]
    fn prolog_scan_exhausted_returns_no_frame() {
        /* Stack contains nothing that looks like a (cfa, ip) pair.
         * The unwinder must terminate without panicking and without
         * pushing any spurious frames beyond the initial IP. */
        let module_start: u64 = 0x4000_0000;
        let module_end:   u64 = 0x4000_1000;
        let rip:          u64 = 0x4000_0500;

        let rsp: u64 = 0x7000_0000;
        let rbp: u64 = 0x7000_0041; /* misaligned to defeat chain walk */

        let stack = vec![0u8; 512];

        let mut proc = Process::new();
        proc.add_module(Module::new_anon(module_start, module_end));

        let (result, frames) = run_unwind(proc, rip, rbp, rsp, &stack);

        /* Only the initial IP is recorded; nothing else is recoverable. */
        assert_eq!(frames, vec![rip]);
        assert_eq!(result.frames_pushed, 1);
    }

    #[test]
    fn dwarf_lookup_miss_falls_back_to_prolog_walk() {
        /* A DWARF-typed module whose backing file cannot be opened
         * (NoFileAccessor) triggers the "No module found" path in
         * unwind_module; the loop then falls back to the prolog walk,
         * which can recover the return address from the RBP chain. */
        let module_start: u64 = 0x4000_0000;
        let module_end:   u64 = 0x4000_1000;
        let rip:          u64 = 0x4000_0500;
        let return_addr:  u64 = 0x4000_0700;

        let rsp:        u64 = 0x7000_0000;
        let rbp:        u64 = 0x7000_0040;
        let saved_rbp:  u64 = 0x7000_0080;

        let stack = build_stack(
            rsp,
            512,
            &[(rbp, saved_rbp), (rbp + 8, return_addr)]);

        let mut proc = Process::new();
        proc.add_module(Module::new(
            module_start,
            module_end,
            0,
            0,
            42,
            42,
            UnwindType::DWARF));

        let (_result, frames) = run_unwind(proc, rip, rbp, rsp, &stack);

        assert!(
            frames.contains(&return_addr),
            "expected return_addr {:#x} in frames {:?}", return_addr, frames);
    }

    #[test]
    fn scan_recovery_when_unwound_ip_is_outside_any_module() {
        /* The prolog walker is given an [rbp+8] value that is NOT
         * inside any registered module, so the walk fails. The unwind
         * loop must terminate cleanly with just the initial IP. */
        let module_start: u64 = 0x4000_0000;
        let module_end:   u64 = 0x4000_1000;
        let rip:          u64 = 0x4000_0500;
        let bogus_ip:     u64 = 0xdead_beef_dead_beef;

        let rsp:       u64 = 0x7000_0000;
        let rbp:       u64 = 0x7000_0040;
        let saved_rbp: u64 = 0x7000_0080;

        let stack = build_stack(
            rsp,
            512,
            &[(rbp, saved_rbp), (rbp + 8, bogus_ip)]);

        let mut proc = Process::new();
        proc.add_module(Module::new_anon(module_start, module_end));

        let (result, frames) = run_unwind(proc, rip, rbp, rsp, &stack);

        assert_eq!(frames, vec![rip]);
        assert_eq!(result.frames_pushed, 1);
        assert!(!frames.contains(&bogus_ip));
    }
}
