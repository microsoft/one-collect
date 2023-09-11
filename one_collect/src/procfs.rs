use std::fs;
use std::path;

pub fn get_comm(
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