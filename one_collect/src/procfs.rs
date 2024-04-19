use std::str::FromStr;
use std::fs::{self, File};
use std::path::{self, PathBuf};
use std::io::{BufRead, BufReader};

pub(crate) fn get_comm(
    path: &mut path::PathBuf) -> Option<String> {
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
                    return Some(long_comm);
                }
            }

            /* Best comm */
            Some(comm)
        },
        Err(_) => None,
    }
}

#[derive(Default)]
pub(crate) struct ModuleInfo<'a> {
    pub start_addr: u64,
    pub end_addr: u64,
    pub offset: u64,
    pub ino: u64,
    pub dev_maj: u32,
    pub dev_min: u32,
    pub path: Option<&'a str>,
}

impl<'a> ModuleInfo<'a> {
    pub fn len(&self) -> u64 {
        (self.end_addr - self.start_addr) + 1
    }

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
                    if let Some(exec) = part.chars().nth(2) {
                        /* Not executable */
                        if exec != 'x' {
                            return None;
                        }
                    } else {
                        /* Odd format */
                        return None;
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

pub(crate) fn ns_pid(
    pid: u32) -> Option<u32> {
    let mut path_buf = PathBuf::new();
    path_buf.push("/proc");
    if pid != 0 {
        path_buf.push(pid.to_string());
    } else {
        path_buf.push("self");
    }
    path_buf.push("status");

    if let Ok(file) = File::open(&path_buf) {
        for line in BufReader::new(file).lines().flatten() {
            if line.starts_with("NSpid:\t") {
                let (_, value) = line.split_at(7);

                if let Ok(nspid) = value.parse::<u32>() {
                    return Some(nspid);
                }
            }
        }
    }

    None
}

pub(crate) fn iter_proc_modules(
    pid: u32,
    mut callback: impl FnMut(&ModuleInfo)) {
    let mut path_buf = PathBuf::new();
    path_buf.push("/proc");
    if pid != 0 {
        path_buf.push(pid.to_string());
    } else {
        path_buf.push("self");
    }
    path_buf.push("maps");

    if let Ok(file) = File::open(&path_buf) {
        for line in BufReader::new(file).lines().flatten() {
            if let Some(module) = ModuleInfo::from_line(&line) {
                (callback)(&module);
            }
        }
    }
}

pub(crate) fn iter_modules(
    mut callback: impl FnMut(u32, &ModuleInfo)) {
    iter_processes(|pid,path| {
        path.push("maps");
        let result = File::open(&path);
        path.pop();

        if let Ok(file) = result {
            for line in BufReader::new(file).lines().flatten() {
                if let Some(module) = ModuleInfo::from_line(&line) {
                    (callback)(pid, &module);
                }
            }
        }
    });
}

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

pub(crate) fn iter_processes(mut callback: impl FnMut(u32, &mut PathBuf)) {
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
