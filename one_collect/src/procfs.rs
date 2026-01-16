// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::str::FromStr;
use std::fs::{self, File};
use std::path::{self, PathBuf};
use std::io::{BufRead, BufReader};
use tracing::{debug};

use crate::PathBufInteger;

/// Gets the `comm` value from a process's procfs entry. The `comm` value typically holds the process's name.
///
/// # Arguments
///
/// * `path` - A mutable reference to a PathBuf pointing to the procfs directory of a process (e.g. /proc/[pid]).
///
/// # Returns
///
/// * `Some(String)` - The `comm` value as a String if it can be read successfully.
/// * `None` - If there is an error reading the `comm` value.
///
/// # Remarks
///
/// If the `comm` value is exactly 15 characters long (the maximum length for this field), this can be an indication
/// that the process's actual name is longer. In such a case, the function attempts to retreive the full process name.
pub fn get_comm(
    path: &mut path::PathBuf) -> Option<String> {
    debug!("Retrieving comm: path={:?}", path);
    path.push("comm");
    let result = fs::read_to_string(&path);
    path.pop();

    match result {
        Ok(mut comm) => {
            /* Drop new line */
            comm.pop();

            /* Find long name */
            if comm.len() == 15 &&
               !comm.starts_with("kworker/") {
                if let Some(long_comm) =
                    parse_long_comm(path) {
                    debug!("Found long comm from cmdline: comm={}", long_comm);
                    return Some(long_comm);
                }
            }

            /* Best comm */
            debug!("Retrieved comm: comm={}", comm);
            Some(comm)
        },
        Err(_) => {
            debug!("Failed to read comm from procfs");
            None
        },
    }
}

const MOD_FLAG_READ: u8 = 1u8 << 0;
const MOD_FLAG_WRITE: u8 = 1u8 << 1;
const MOD_FLAG_EXEC: u8 = 1u8 << 2;
const MOD_FLAG_PRIVATE: u8 = 1u8 << 3;

/// `ModuleInfo` is a struct that provides information about a loaded module within a process.
///
/// This struct contains information about the start and end addresses of the module in memory,
/// the offset of the module, the inode number of the module, the major and minor device ID
/// where the module resides, and an optional path to the module.
///
/// # Struct Fields
///
/// * `start_addr` - A u64 representing the start address where the module is loaded in memory.
/// * `end_addr` - A u64 representing the end address where the module is loaded in memory.
/// * `offset` - A u64 representing the offset of the module.
/// * `ino` - A u64 representing the inode number of the module.
/// * `dev_maj` - A u32 representing the major ID of the device where the module resides.
/// * `dev_min` - A u32 representing the minor ID of the device where the module resides.
/// * `path` - An optional reference to a str representing the path to the module.
///
/// # Remarks
///
/// This struct is typically used in conjunction with other process-related information to provide
/// a comprehensive view of a process's state.
#[derive(Default)]
pub struct ModuleInfo<'a> {
    pub start_addr: u64,
    pub end_addr: u64,
    pub offset: u64,
    pub ino: u64,
    pub dev_maj: u32,
    pub dev_min: u32,
    pub path: Option<&'a str>,
    flags: u8,
}

impl<'a> ModuleInfo<'a> {
    /// Returns the size of the module in memory. Calculated as the difference between the end and start addresses.
    ///
    /// # Returns
    ///
    /// A `u64` representing the size of the module.
    pub fn len(&self) -> u64 {
        (self.end_addr - self.start_addr) + 1
    }

    /// Returns true if the module has read permission.
    ///
    /// # Returns
    ///
    /// A `bool` representing the permission.
    pub fn is_read(&self) -> bool { self.flags & MOD_FLAG_READ != 0 }

    /// Returns true if the module has write permission.
    ///
    /// # Returns
    ///
    /// A `bool` representing the permission.
    pub fn is_write(&self) -> bool { self.flags & MOD_FLAG_WRITE != 0 }

    /// Returns true if the module has execute permission.
    ///
    /// # Returns
    ///
    /// A `bool` representing the permission.
    pub fn is_exec(&self) -> bool { self.flags & MOD_FLAG_EXEC != 0 }

    /// Returns true if the module has private (copy-on-write) permission.
    ///
    /// # Returns
    ///
    /// A `bool` representing the permission.
    pub fn is_private(&self) -> bool { self.flags & MOD_FLAG_PRIVATE != 0 }

    /// Constructs a `ModuleInfo` instance from a line of text.
    ///
    /// The line should contain information about a module in the format used by the `/proc/[pid]/maps` file in a Linux system.
    ///
    /// # Parameters
    ///
    /// * `line`: A reference to a string slice containing the module information.
    ///
    /// # Returns
    ///
    /// An `Option` that contains a `ModuleInfo` instance if the line could be parsed successfully, or `None` otherwise.
    pub fn from_line(line: &'a str) -> Option<Self> {
        let parts = line.split_whitespace();
        let mut module = ModuleInfo::default();

        for (index, part) in parts.enumerate() {
            match index {
                0 => {
                    for address in part.split('-') {
                        if let Ok(address) = u64::from_str_radix(address, 16) {
                            if module.start_addr == 0 {
                                module.start_addr = address;
                            } else {
                                module.end_addr = address;
                            }
                        } else {
                            return None;
                        }
                    }
                },
                1 => {
                    if part.contains('r') {
                        module.flags |= MOD_FLAG_READ;
                    }

                    if part.contains('w') {
                        module.flags |= MOD_FLAG_WRITE;
                    }

                    if part.contains('x') {
                        module.flags |= MOD_FLAG_EXEC;
                    }

                    if part.contains('p') {
                        module.flags |= MOD_FLAG_PRIVATE;
                    }
                },
                2 => {
                    if let Ok(offset) = u64::from_str_radix(part, 16) {
                        module.offset = offset;
                    } else {
                        /* Odd format */
                        return None;
                    }
                },
                3 => {
                    let mut i = 0;

                    for index in part.split(':') {
                        if let Ok(value) = u32::from_str_radix(index, 16) {
                            if i == 0 {
                                module.dev_maj = value;
                            } else {
                                module.dev_min = value;
                            }

                            i += 1;
                        } else {
                            /* Odd format */
                            return None;
                        }
                    }
                },
                4 => {
                    if let Ok(ino) = u64::from_str(part) {
                        module.ino = ino;
                    } else {
                        /* Odd format */
                        return None;
                    }
                },
                5 => {
                    module.path = Some(part);
                },
                /* Default, not interesting */
                _ => {
                    break;
                }
            }
        }

        Some(module)
    }
}

/// Returns the namespace PID (process ID) associated with a given PID.
///
/// The function reads the `/proc/{pid}/status` file to get the namespace PID.
/// If the provided PID is zero, it reads the `/proc/self/status` file.
///
/// # Parameters
///
/// * `path_buf`: A mutable reference to a `PathBuf` instance. This buffer is cleared and used to build the path to the status file.
/// * `pid`: The process ID for which to get the namespace PID. If this is zero, the function will get the namespace PID for the current process.
///
/// # Returns
///
/// An `Option` that contains the namespace PID if it could be read successfully, or `None` otherwise.
pub fn ns_pid(
    path_buf: &mut PathBuf,
    pid: u32) -> Option<u32> {
    path_buf.clear();
    path_buf.push("/proc");
    if pid != 0 {
        path_buf.push_u32(pid);
    } else {
        path_buf.push("self");
    }
    path_buf.push("status");

    if let Ok(file) = File::open(&path_buf) {
        for line in BufReader::new(file).lines() {
            match line {
                Ok(line) => {
                    if line.starts_with("NSpid:\t") {
                        let (_, value) = line.split_at(7);

                        if let Ok(nspid) = value.parse::<u32>() {
                            return Some(nspid);
                        }
                    }
                },
                Err(_) => { break; },
            }
        }
    }

    None
}

/// Iterates over the current tasks within a process.
///
/// # Parameters
///
/// * `pid`: The process ID for which to iterate over.
/// * `callback`: A mutable closure that takes a `u32` reference as its argument and returns nothing.
///     This closure is called for each task.
///
pub fn iter_proc_tasks(
    pid: u32,
    mut callback: impl FnMut(u32)) {
    let mut path_buf = PathBuf::new();
    path_buf.push("/proc");
    path_buf.push_u32(pid);
    path_buf.push("task");

    let dirs = fs::read_dir(path_buf);

    if let Ok(dirs) = dirs {
        for entry in dirs {
            if let Ok(entry) = entry {
                let path = entry.path();

                if path.components().count() == 5 {
                    let mut iter = path.iter();

                    iter.next(); // "/"
                    iter.next(); // "proc"
                    iter.next(); // "<pid>"
                    iter.next(); // "task"

                    if let Some(task_str) = iter.next() { // "<task>"
                        let s = task_str.to_str().unwrap();

                        if let Ok(task) = s.parse::<u32>() {
                            if task != pid {
                                (callback)(task);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Iterates over the memory modules of a process and applies a callback function to each module.
///
/// The function reads the `/proc/{pid}/maps` file to get the list of memory modules.
/// If the provided PID is zero, it reads the `/proc/self/maps` file.
///
/// # Parameters
///
/// * `pid`: The process ID for which to iterate over the memory modules. If this is zero, the function
///     will iterate over the modules of the current process.
/// * `callback`: A mutable closure that takes a `ModuleInfo` reference as its argument and returns nothing.
///     This closure is called for each module.
///
pub fn iter_proc_modules(
    pid: u32,
    mut callback: impl FnMut(&ModuleInfo)) {
    let mut path_buf = PathBuf::new();
    path_buf.push("/proc");
    if pid != 0 {
        path_buf.push_u32(pid);
    } else {
        path_buf.push("self");
    }
    path_buf.push("maps");

    if let Ok(file) = File::open(&path_buf) {
        for line in BufReader::new(file).lines() {
            match line {
                Ok(line) => {
                    if let Some(module) = ModuleInfo::from_line(&line) {
                        (callback)(&module);
                    }
                },
                Err(_) => { break; },
            }
        }
    }
}

/// Iterates over each process and its modules in the system.
///
/// The function accepts a mutable callback function that is invoked for each module of every process.
/// The callback function receives the process identifier (PID) and a reference to the module information.
///
/// # Arguments
///
/// * `callback` - A mutable callback function that gets executed for each module of every process.
///     The callback function takes two parameters: a u32 representing the PID and a reference to the ModuleInfo struct.
///
pub fn iter_modules(
    mut callback: impl FnMut(u32, &ModuleInfo)) {
    iter_processes(|pid,path| {
        path.push("maps");
        let result = File::open(&path);
        path.pop();

        if let Ok(file) = result {
            for line in BufReader::new(file).lines() {
                match line {
                    Ok(line) => {
                        if let Some(module) = ModuleInfo::from_line(&line) {
                            (callback)(pid, &module);
                        }
                    },
                    Err(_) => { break; },
                }
            }
        }
    });
}

/// Parses the command line of a process from the proc filesystem.
///
/// This function reads the `cmdline` file from the `/proc` directory for a given process,
/// which contains the command that was used to launch the process. The function truncates
/// the command at the first null character and returns it.
///
/// # Arguments
///
/// * `path` - A mutable reference to a PathBuf containing the path to the proc directory of the process.
///
/// # Returns
///
/// * `Option<String>` - The command used to launch the process, or None if the file could not be read.
///
/// # Errors
///
/// This function will return None if the `cmdline` file could not be read.
///
fn parse_long_comm(
    path: &mut path::PathBuf) -> Option<String> {
    path.push("cmdline");
    let result = fs::read_to_string(&path);
    path.pop();

    match result {
        Ok(mut cmdline) => {
            if let Some(index) = cmdline.find('\0') {
                cmdline.truncate(index);
            }

            if cmdline.is_empty() {
                return None;
            }

            if let Some(index) = cmdline.rfind('/') {
                cmdline = cmdline.split_off(index + 1);
            }

            Some(cmdline)
        },
        Err(_) => {
            /* Nothing */
            None
        },
    }
}

/// Iterates over each process in the system.
///
/// The function accepts a mutable callback function that is invoked for each process.
/// The callback function receives the process identifier (PID) and a mutable reference to the process path.
///
/// # Arguments
///
/// * `callback` - A mutable callback function that gets executed for each process.
///     The callback function takes two parameters: a u32 representing the PID and a mutable reference to the
///     PathBuf instance representing the process path.
///
pub fn iter_processes(mut callback: impl FnMut(u32, &mut PathBuf)) {
    let mut path_buf = PathBuf::new();
    path_buf.push("/proc");

    for entry in fs::read_dir(path_buf)
        .expect("Unable to open procfs") {
            let entry = entry.expect("Unable to get path");
            let mut path = entry.path();

            if path.components().count() == 3 {
                let mut iter = path.iter();

                iter.next(); // "/"
                iter.next(); // "proc"

                if let Some(pid_str) = iter.next() { // "<pid>"
                    let s = pid_str.to_str().unwrap();

                    if let Ok(pid)= s.parse::<u32>() {
                        (callback)(pid, &mut path);
                    }
                }
            }
        }
    }
