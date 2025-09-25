// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub fn system_page_size() -> u64 {
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        if page_size > 0 {
            page_size as u64
        } else {
            panic!("Failed to get system page size via sysconf(_SC_PAGESIZE)");
        }
    }
}