use std::fs;
use std::path::{self, PathBuf};

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