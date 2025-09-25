// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub fn system_page_size() -> u64 {
    extern "system" {
        fn GetSystemInfo(lpSystemInfo: *mut SystemInfo);
    }

    #[repr(C)]
    struct SystemInfo {
        processor_architecture: u16,
        reserved: u16,
        page_size: u32,
        minimum_application_address: *mut std::ffi::c_void,
        maximum_application_address: *mut std::ffi::c_void,
        active_processor_mask: *mut std::ffi::c_void,
        number_of_processors: u32,
        processor_type: u32,
        allocation_granularity: u32,
        processor_level: u16,
        processor_revision: u16,
    }

    unsafe {
        let mut system_info: SystemInfo = std::mem::zeroed();
        GetSystemInfo(&mut system_info);
        system_info.page_size as u64
    }
}