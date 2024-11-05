use std::mem::size_of;

#[cfg(target_os = "linux")]
use libc::*;
use super::*;

#[repr(C)]
#[derive(Default)]
struct bpf_get_id {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Default)]
struct bpf_obj {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    path_fd: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Default)]
struct bpf_element {
    fd: i32,
    _padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}

pub fn bpf_get_map_fd_by_path(
    path: &std::ffi::CStr) -> IOResult<i32> {
    let mut obj = bpf_obj::default();
    obj.pathname = path.as_ptr() as u64;

    unsafe {
        match syscall(
            SYS_bpf,
            7, /* BPF_OBJ_GET */
            &obj as *const bpf_obj as usize,
            size_of::<bpf_obj>()) {
            -1 => Err(std::io::Error::last_os_error()),
            fd => Ok(fd as i32),
        }
    }
}

pub fn bpf_get_map_fd(
    id: u32) -> IOResult<i32> {
    let mut get = bpf_get_id::default();
    get.start_id = id;

    unsafe {
        match syscall(
            SYS_bpf,
            15, /* BPF_MAP_GET_FD_BY_ID */
            &get as *const bpf_get_id as usize,
            size_of::<bpf_get_id>()) {
            -1 => Err(std::io::Error::last_os_error()),
            fd => Ok(fd as i32),
        }
    }
}

pub fn bpf_set_map_element(
    fd: i32,
    key: u64,
    value: u64) -> IOResult<()> {
    let mut element = bpf_element::default();
    element.fd = fd;
    element.key = std::ptr::addr_of!(key) as u64;
    element.value = std::ptr::addr_of!(value) as u64;

    unsafe {
        match syscall(
            SYS_bpf,
            2, /* BPF_MAP_UPDATE_ELEM */
            &element as *const bpf_element as usize,
            size_of::<bpf_element>()) {
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}
