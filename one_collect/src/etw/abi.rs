// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
 * std::os::windows::RawHandle is not available when
 * documenting windows code on non-windows builds.
 * Use the common definition to allow for this.
 */
type RawHandle = *mut std::os::raw::c_void;

use super::*;

#[link(name = "kernel32")]
extern "system" {
    fn GetActiveProcessorCount(
        group: u16) -> u32;

    fn StartTraceW(
        tracehandle: *mut u64,
        instancename: *const u16,
        properties: *mut EVENT_TRACE_PROPERTIES) -> u32;

    fn OpenTraceW(
        logfile: *const EVENT_TRACE_LOGFILE) -> u64;

    fn CloseTrace(
        handle: u64) -> u32;

    fn GetLastError() -> u32;

    fn ControlTraceW(
        tracehandle: u64,
        instancename: *const u16,
        properties: *mut EVENT_TRACE_PROPERTIES,
        controlcode: u32) -> u32;

    fn EnableTraceEx2(
        tracehandle: u64,
        provider: *const Guid,
        controlcode: u32,
        level: u8,
        matchanykeyword: u64,
        matchallkeyword: u64,
        timeout: u32,
        parameters: *const ENABLE_TRACE_PARAMETERS) -> u32;

    fn ProcessTrace(
        tracehandles: *const u64,
        count: u32,
        starttime: *const u64,
        endtime: *const u64) -> u32;

    fn LookupPrivilegeValueW(
        systemname: *const u16,
        name: *const u16,
        luid: *mut u64) -> u32;

    fn OpenProcessToken(
        processhandle: RawHandle,
        access: u32,
        tokenhandle: *mut RawHandle) -> u32;

    fn AdjustTokenPrivileges(
        tokenhandle: RawHandle,
        disableall: u32,
        newstate: *const TOKEN_PRIVILEGES,
        bufferlength: u32,
        oldstate: *mut TOKEN_PRIVILEGES,
        returnedlength: *mut u32) -> u32;

    fn CloseHandle(
        handle: RawHandle) -> bool;

    fn GetCurrentProcess() -> RawHandle;

    fn TraceQueryInformation(
        sessionhandle: u64,
        informationclass: i32,
        traceinformation: *mut u8,
        informationlength: u32,
        returnlength: *mut u32) -> u32;

    fn TraceSetInformation(
        sessionhandle: u64,
        informationclass: i32,
        traceinformation: *const u8,
        informationlength: u32) -> u32;
}

const EVENT_TRACE_CONTROL_STOP: u32 = 1;
const EVENT_TRACE_CONTROL_FLUSH: u32 = 3;

const WNODE_FLAG_TRACED_GUID: u32 = 131072;

const EVENT_TRACE_REAL_TIME_MODE: u32 = 256;
const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 33554432;
const EVENT_TRACE_INDEPENDENT_SESSION_MODE: u32 = 134217728;

const PROCESS_TRACE_MODE_REAL_TIME: u32 = 256;
const PROCESS_TRACE_MODE_RAW_TIMESTAMP: u32 = 4096;
const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 268435456;

const EVENT_FILTER_TYPE_PID: u32 = 0x80000004;
const EVENT_FILTER_TYPE_EVENT_ID: u32 = 0x80000200;
const EVENT_FILTER_TYPE_STACKWALK: u32 = 0x80001000;

pub const EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0: u32 = 64u32;
pub const EVENT_ENABLE_PROPERTY_ENABLE_SILOS: u32 = 1024u32;
pub const EVENT_ENABLE_PROPERTY_EVENT_KEY: u32 = 256u32;
pub const EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE: u32 = 512u32;
pub const EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0: u32 = 16u32;
pub const EVENT_ENABLE_PROPERTY_PROCESS_START_KEY: u32 = 128u32;
pub const EVENT_ENABLE_PROPERTY_PROVIDER_GROUP: u32 = 32u32;
pub const EVENT_ENABLE_PROPERTY_PSM_KEY: u32 = 8u32;
pub const EVENT_ENABLE_PROPERTY_SID: u32 = 1u32;
pub const EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING: u32 = 2048u32;
pub const EVENT_ENABLE_PROPERTY_STACK_TRACE: u32 = 4u32;
pub const EVENT_ENABLE_PROPERTY_TS_ID: u32 = 2u32;

pub const EVENT_HEADER_EXT_TYPE_CONTAINER_ID: u32 = 16u32;
pub const EVENT_HEADER_EXT_TYPE_CONTROL_GUID: u32 = 14u32;
pub const EVENT_HEADER_EXT_TYPE_EVENT_KEY: u32 = 10u32;
pub const EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL: u32 = 11u32;
pub const EVENT_HEADER_EXT_TYPE_INSTANCE_INFO: u32 = 4u32;
pub const EVENT_HEADER_EXT_TYPE_MAX: u32 = 19u32;
pub const EVENT_HEADER_EXT_TYPE_PEBS_INDEX: u32 = 7u32;
pub const EVENT_HEADER_EXT_TYPE_PMC_COUNTERS: u32 = 8u32;
pub const EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY: u32 = 13u32;
pub const EVENT_HEADER_EXT_TYPE_PROV_TRAITS: u32 = 12u32;
pub const EVENT_HEADER_EXT_TYPE_PSM_KEY: u32 = 9u32;
pub const EVENT_HEADER_EXT_TYPE_QPC_DELTA: u32 = 15u32;
pub const EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID: u32 = 1u32;
pub const EVENT_HEADER_EXT_TYPE_SID: u32 = 2u32;
pub const EVENT_HEADER_EXT_TYPE_STACK_KEY32: u32 = 17u32;
pub const EVENT_HEADER_EXT_TYPE_STACK_KEY64: u32 = 18u32;
pub const EVENT_HEADER_EXT_TYPE_STACK_TRACE32: u32 = 5u32;
pub const EVENT_HEADER_EXT_TYPE_STACK_TRACE64: u32 = 6u32;
pub const EVENT_HEADER_EXT_TYPE_TS_ID: u32 = 3u32;

pub const TRACE_LEVEL_CRITICAL: u8 = 1;
pub const TRACE_LEVEL_ERROR: u8 = 2;
pub const TRACE_LEVEL_WARNING: u8 = 3;
pub const TRACE_LEVEL_INFORMATION: u8 = 4;
pub const TRACE_LEVEL_VERBOSE: u8 = 5;

pub const EVENT_CONTROL_CODE_DISABLE_PROVIDER: u32 = 0;
pub const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 = 1;
pub const EVENT_CONTROL_CODE_CAPTURE_STATE: u32 = 2;

pub fn wide_string(
    name: &str) -> Vec<u16> {
    let mut name_wide: Vec<u16> = Vec::new();

    for c in name.chars() {
        name_wide.push(c as u16);
    }

    name_wide.push(0_u16);

    name_wide
}

const SE_PRIVILEGE_ENABLED: u32 = 2;
const TOKEN_ADJUST_PRIVILEGES: u32 = 32;

#[repr(C, packed)]
#[allow(non_snake_case)]
struct TOKEN_PRIVILEGES {
    pub PrivilegeCount: u32,
    pub Luid: u64,
    pub Attributes: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct TRACE_PROFILE_INTERVAL {
    pub Source: u32,
    pub Interval: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct WNODE_HEADER {
    pub BufferSize: u32,
    pub ProviderId: u32,
    pub HistoricalContext: u64,
    pub TimeStamp: i64,
    pub Guid: Guid,
    pub ClientContext: u32,
    pub Flags: u32,
}

impl Default for WNODE_HEADER {
    fn default() -> Self {
        Self {
            BufferSize: std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32,
            ProviderId: 0,
            HistoricalContext: 0,
            TimeStamp: 0,
            Guid: Guid::from_u128(0x123),
            ClientContext: 1,
            Flags: WNODE_FLAG_TRACED_GUID,
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct CLASSIC_EVENT_ID {
    pub EventGuid: Guid,
    pub Type: u8,
    pub Reserved: [u8; 7],
}

impl CLASSIC_EVENT_ID {
    pub fn new(
        provider: Guid,
        id: u8) -> Self {
        Self {
            EventGuid: provider,
            Type: id,
            Reserved: [0; 7],
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct TRACE_LOGFILE_HEADER {
    pub BufferSize: u32,
    pub Version: u32,
    pub ProviderVersion: u32,
    pub NumberOfProcessors: u32,
    pub EndTime: u64,
    pub TimerResolution: u32,
    pub MaximumFileSize: u32,
    pub LogFileMode: u32,
    pub BuffersWritten: u32,
    pub StartBuffers: u32,
    pub PointerSize: u32,
    pub EventsLost: u32,
    pub CpuSpeedInMhz: u32,
    pub LoggerName: *const u16,
    pub LogFileName: *const u16,
    pub TimeZone: [u8; 172],
    pub BootTime: u64,
    pub PerfFreq: u64,
    pub StartTime: u64,
    pub ReservedFlags: u32,
    pub BuffersLost: u32,
}

impl Default for TRACE_LOGFILE_HEADER {
    fn default() -> TRACE_LOGFILE_HEADER {
        TRACE_LOGFILE_HEADER {
            BufferSize: 0,
            Version: 0,
            ProviderVersion: 0,
            NumberOfProcessors: 0,
            EndTime: 0,
            TimerResolution: 0,
            MaximumFileSize: 0,
            LogFileMode: 0,
            BuffersWritten: 0,
            StartBuffers: 0,
            PointerSize: 0,
            EventsLost: 0,
            CpuSpeedInMhz: 0,
            LoggerName: std::ptr::null(),
            LogFileName: std::ptr::null(),
            TimeZone: [0; 172],
            BootTime: 0,
            PerfFreq: 0,
            StartTime: 0,
            ReservedFlags: 0,
            BuffersLost: 0,
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct EVENT_TRACE_HEADER {
    pub Size: u16,
    pub FieldTypeFlags: u16,
    pub Version: u32,
    pub ThreadId: u32,
    pub ProcessId: u32,
    pub TimeStamp: u64,
    pub Guid: Guid,
    pub ClientContext: u32,
    pub Flags: u32,
}

impl Default for EVENT_TRACE_HEADER {
    fn default() -> EVENT_TRACE_HEADER {
        EVENT_TRACE_HEADER {
            Size: 0,
            FieldTypeFlags: 0,
            Version: 0,
            ThreadId: 0,
            ProcessId: 0,
            TimeStamp: 0,
            Guid: Guid::from_u128(0),
            ClientContext: 0,
            Flags: 0,
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct EVENT_TRACE {
    pub Header: EVENT_TRACE_HEADER,
    pub InstanceId: u32,
    pub ParentInstanceId: u32,
    pub ParentGuid: Guid,
    pub MofData: *const u8,
    pub MofLength: u32,
    pub ProcessorIndex: u16,
    pub LoggerId: u16,
}

impl Default for EVENT_TRACE {
    fn default() -> EVENT_TRACE {
        EVENT_TRACE {
            Header: EVENT_TRACE_HEADER::default(),
            InstanceId: 0,
            ParentInstanceId: 0,
            ParentGuid: Guid::from_u128(0),
            MofData: std::ptr::null(),
            MofLength: 0,
            ProcessorIndex: 0,
            LoggerId: 0,
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct EVENT_TRACE_LOGFILE {
    pub LogFileName: *const u16,
    pub LoggerName: *const u16,
    pub CurrentTime: u64,
    pub BuffersRead: u32,
    pub ProcessTraceMode: u32,
    pub CurrentEvent: EVENT_TRACE,
    pub LogFileHeader: TRACE_LOGFILE_HEADER,
    pub BufferCallback: extern fn(*const TRACE_LOGFILE_HEADER) -> u32,
    pub BufferSize: u32,
    pub Filled: u32,
    pub EventsLost: u32,
    pub EventRecordCallback: extern fn (*const EVENT_RECORD),
    pub IsKernelTrace: u32,
    pub Context: *const std::ffi::c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
struct EVENT_TRACE_PROPERTIES {
    pub Wnode: WNODE_HEADER,
    pub BufferSize: u32,
    pub MinimumBuffers: u32,
    pub MaximumBuffers: u32,
    pub MaximumFileSize: u32,
    pub LogFileMode: u32,
    pub FlushTimer: u32,
    pub EnableFlags: u32,
    pub FlushThreshold: i32,
    pub NumberOfBuffers: u32,
    pub FreeBuffers: u32,
    pub EventsLost: u32,
    pub BuffersWritten: u32,
    pub LogBuffersLost: u32,
    pub RealTimeBuffersLost: u32,
    pub LoggerThreadId: RawHandle,
    pub LogFileNameOffset: u32,
    pub LoggerNameOffset: u32,
    /* Extension values, must align to 8-bytes */
    pub LoggerName: [u8; 1024],
}

impl Default for EVENT_TRACE_PROPERTIES {
    fn default() -> Self {
        let cpus = unsafe { GetActiveProcessorCount(0xFFFF) };

        Self {
            Wnode: WNODE_HEADER::default(),
            BufferSize: 64,
            MinimumBuffers: cpus * 4,
            MaximumBuffers: cpus * 32,
            MaximumFileSize: 0,
            LogFileMode: EVENT_TRACE_REAL_TIME_MODE |
                EVENT_TRACE_INDEPENDENT_SESSION_MODE |
                EVENT_TRACE_SYSTEM_LOGGER_MODE,
            FlushTimer: 0,
            EnableFlags: 0,
            FlushThreshold: 0,
            NumberOfBuffers: 0,
            FreeBuffers: 0,
            EventsLost: 0,
            BuffersWritten: 0,
            LogBuffersLost: 0,
            RealTimeBuffersLost: 0,
            LoggerThreadId: std::ptr::null_mut(),
            LogFileNameOffset: 0,
            LoggerNameOffset: 120,
            LoggerName: [0; 1024],
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct EVENT_FILTER_DESCRIPTOR {
    pub Filter: *const u8,
    pub Size: u32,
    pub Type: u32,
}

impl Default for EVENT_FILTER_DESCRIPTOR {
    fn default() -> Self {
        Self {
            Filter: std::ptr::null(),
            Size: 0,
            Type: 0,
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
struct ENABLE_TRACE_PARAMETERS {
    pub Version: u32,
    pub EnableProperty: u32,
    pub ControlFlags: u32,
    pub SourceId: Guid,
    pub EnableFilterDesc: *const EVENT_FILTER_DESCRIPTOR,
    pub FilterDescCount: u32,
}

impl Default for ENABLE_TRACE_PARAMETERS {
    fn default() -> Self {
        Self {
            Version: 2,
            EnableProperty: 0,
            ControlFlags: 0,
            SourceId: Guid::from_u128(0u128),
            EnableFilterDesc: std::ptr::null(),
            FilterDescCount: 0,
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct EVENT_DESCRIPTOR {
    pub Id: u16,
    pub Version: u8,
    pub Channel: u8,
    pub Level: u8,
    pub Opcode: u8,
    pub Task: u16,
    pub Keyword: u64,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct EVENT_HEADER {
    pub Size: u16,
    pub HeaderType: u16,
    pub Flags: u16,
    pub EventProperty: u16,
    pub ThreadId: u32,
    pub ProcessId: u32,
    pub TimeStamp: u64,
    pub ProviderId: Guid,
    pub EventDescriptor: EVENT_DESCRIPTOR,
    pub KernelTime: u32,
    pub UserTime: u32,
    pub ActivityId: Guid,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct EVENT_HEADER_EXTENDED_DATA_ITEM {
    pub Reserved1: u16,
    pub ExtType: u16,
    pub Linkage: u16,
    pub DataSize: u16,
    pub DataPtr: *const u8,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct EVENT_RECORD {
    pub EventHeader: EVENT_HEADER,
    pub ProcessorIndex: u16,
    pub LoggerId: u16,
    pub ExtendedDataCount: u16,
    pub UserDataLength: u16,
    pub ExtendedData: *const EVENT_HEADER_EXTENDED_DATA_ITEM,
    pub UserData: *const u8,
    pub UserContext: *const std::ffi::c_void,
}

impl EVENT_RECORD {
    pub fn user_data_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.UserData,
                self.UserDataLength as usize)
        }
    }
}

pub struct TraceEnable {
    provider: Guid,
    capture_environment: bool,
    rundown: bool,
    no_filtering: bool,
    properties: u32,
    level: u8,
    keyword: u64,
    events: Vec<u16>,
    callstacks: Vec<u16>,
}

impl TraceEnable {
    pub fn new(
        provider: Guid) -> Self {
        Self {
            provider,
            no_filtering: false,
            capture_environment: false,
            rundown: false,
            properties: 0,
            level: 0,
            keyword: 0,
            events: Vec::new(),
            callstacks: Vec::new(),
        }
    }

    pub fn needs_capture_environment(
        &self) -> bool {
        self.capture_environment
    }

    pub fn ensure_capture_environment(
        &mut self) {
        self.capture_environment = true;
    }

    pub fn needs_rundown(&self) -> bool { self.rundown }

    pub fn ensure_rundown(&mut self) { self.rundown = true; }

    pub fn ensure_no_filtering(
        &mut self) {
        self.no_filtering = true;
    }

    pub fn ensure_property(
        &mut self,
        property: u32) {
        self.properties |= property;
    }

    pub fn ensure_level(
        &mut self,
        level: u8) {
        if level > self.level {
            self.level = level;
        }
    }

    pub fn ensure_keyword(
        &mut self,
        keyword: u64) {
        self.keyword |= keyword;
    }

    pub fn add_event(
        &mut self,
        id: u16,
        callstacks: bool) {
        self.events.push(id);

        if callstacks {
            self.callstacks.push(id);
        }
    }

    fn build_event_filter(
        ids: &Vec<u16>) -> Vec<u8> {
        let mut data = Vec::new();

        /* Filter in */
        data.push(1u8);

        /* Reserved */
        data.push(0u8);

        /* Count */
        let count = ids.len() as u16;
        data.extend_from_slice(&count.to_ne_bytes());

        for id in ids {
            data.extend_from_slice(&id.to_ne_bytes());
        }

        data
    }

    pub fn disable(
        &self,
        handle: u64) -> anyhow::Result<()> {
        unsafe {
            let result = EnableTraceEx2(
                handle,
                &self.provider,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0,
                0,
                0,
                0,
                std::ptr::null());

            if result != 0 {
                anyhow::bail!("EnableTraceEx2 failed with {}", result);
            }
        }

        Ok(())
    }

    pub fn enable(
        &self,
        handle: u64,
        target_pids: &Option<Vec<i32>>) -> anyhow::Result<()> {
        let mut params = ENABLE_TRACE_PARAMETERS::default();

        if !self.no_filtering {
            let mut events = EVENT_FILTER_DESCRIPTOR::default();
            let events_filter = Self::build_event_filter(&self.events);
            events.Type = EVENT_FILTER_TYPE_EVENT_ID;
            events.Filter = events_filter.as_ptr();
            events.Size = events_filter.len() as u32;

            let mut callstacks = EVENT_FILTER_DESCRIPTOR::default();
            let callstacks_filter = Self::build_event_filter(&self.callstacks);
            callstacks.Type = EVENT_FILTER_TYPE_STACKWALK;
            callstacks.Filter = callstacks_filter.as_ptr();
            callstacks.Size = callstacks_filter.len() as u32;

            let mut pids = EVENT_FILTER_DESCRIPTOR::default();
            pids.Type = EVENT_FILTER_TYPE_PID;

            let mut filters = Vec::new();

            if !self.events.is_empty() && self.events.len() <= 64 {
                filters.push(events);
            }

            if !self.callstacks.is_empty() {
                if self.callstacks.len() <= 64 {
                    filters.push(callstacks);
                }

                params.EnableProperty |= EVENT_ENABLE_PROPERTY_STACK_TRACE;
            }

            if let Some(target_pids) = target_pids {
                if target_pids.len() <= 8 {
                    pids.Filter = target_pids.as_ptr() as *const u8;
                    pids.Size = target_pids.len() as u32 * 4;

                    filters.push(pids);
                }
            }

            params.EnableProperty |= self.properties;
            params.EnableFilterDesc = filters.as_ptr();
            params.FilterDescCount = filters.len() as u32;
        }

        unsafe {
            let result = EnableTraceEx2(
                handle,
                &self.provider,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                self.level,
                self.keyword,
                0,
                0,
                &params);

            if result != 0 {
                anyhow::bail!("EnableTraceEx2 failed with {}", result);
            }
        }

        Ok(())
    }
}

pub(crate) fn flush_trace(handle: u64) {
    let mut properties = EVENT_TRACE_PROPERTIES::default();

    unsafe {
        ControlTraceW(
            handle,
            std::ptr::null(),
            &mut properties,
            EVENT_TRACE_CONTROL_FLUSH);
    }
}

pub struct TraceSession {
    properties: EVENT_TRACE_PROPERTIES,
    name: String,
    handle: u64,
}

extern fn buffer_callback(_header: *const TRACE_LOGFILE_HEADER) -> u32 {
    1
}

extern fn event_callback(record: *const EVENT_RECORD) {
    let record = unsafe { &*record };

    /* Get dyn-typed thin pointer */
    let thin = record.UserContext as *mut Box<dyn FnMut(&EVENT_RECORD)>;

    /* Get back the fat pointer and ref */
    let processor = unsafe { &mut *thin };

    /* Process event */
    processor(record);
}

impl TraceSession {
    pub fn new(
        name: String,
        buf_size_kb: u32) -> Self {
        let mut session = Self {
            properties: EVENT_TRACE_PROPERTIES::default(),
            name,
            handle: 0,
        };

        session.properties.BufferSize = buf_size_kb;

        session
    }

    pub fn handle(&self) -> u64 { self.handle }

    pub fn id(&self) -> u64 { self.properties.Wnode.HistoricalContext }

    pub fn start(
        &mut self) -> anyhow::Result<()> {
        let trace_name = wide_string(&self.name);

        unsafe {
            /* Stop any previously running instance */
            ControlTraceW(
                0,
                trace_name.as_ptr(),
                &mut self.properties,
                EVENT_TRACE_CONTROL_STOP);

            /* Start new trace */
            let result = StartTraceW(
                &mut self.handle,
                trace_name.as_ptr(),
                &mut self.properties);

            if result != 0 {
                anyhow::bail!("StartTraceW failed with {}", result);
            }
        }

        Ok(())
    }

    fn open_trace(
        name: &str,
        context: *mut std::ffi::c_void) -> anyhow::Result<u64> {
        let mut log = EVENT_TRACE_LOGFILE {
                LogFileName: std::ptr::null(),
                LoggerName: std::ptr::null(),
                CurrentTime: 0,
                BuffersRead: 0,
                ProcessTraceMode: 0,
                CurrentEvent: EVENT_TRACE::default(),
                LogFileHeader: TRACE_LOGFILE_HEADER::default(),
                BufferCallback: buffer_callback,
                BufferSize: 0,
                Filled: 0,
                EventsLost: 0,
                EventRecordCallback: event_callback,
                IsKernelTrace: 0,
                Context: std::ptr::null(),
            };

        let log_name = wide_string(name);

        log.LoggerName = log_name.as_ptr();

        log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD |
                               PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_RAW_TIMESTAMP;

        log.Context = context;

        unsafe {
            let handle = OpenTraceW(&log);

            if handle == 0xFFFFFFFFFFFFFFFF {
                anyhow::bail!("OpenTraceW failed with {}", GetLastError());
            }

            Ok(handle)
        }
    }

    pub fn process(
        &self,
        parse: Box<dyn FnMut(&EVENT_RECORD)>) -> anyhow::Result<()> {
        /* Create thin pointer */
        let thin = Box::new(parse);

        /* Create raw pointer */
        let raw = Box::into_raw(thin);

        /* Use raw pointer with ETW */
        let context = raw as *mut std::ffi::c_void;

        let handle = Self::open_trace(
            &self.name,
            context)?;

        unsafe {
            /* Process traces */
            let result = ProcessTrace(
                &handle,
                1,
                std::ptr::null(),
                std::ptr::null());

            CloseTrace(handle);

            if result != 0 {
                anyhow::bail!("ProcessTrace failed with {}", GetLastError());
            }
        }

        Ok(())
    }

    pub fn remote_stop(
        handle: u64) {
        let mut properties = EVENT_TRACE_PROPERTIES::default();

        unsafe {
            ControlTraceW(
                handle,
                std::ptr::null::<u16>(),
                &mut properties,
                EVENT_TRACE_CONTROL_STOP);
        }
    }

    pub fn stop(
        &mut self) {
        unsafe {
            ControlTraceW(
                self.handle,
                std::ptr::null::<u16>(),
                &mut self.properties,
                EVENT_TRACE_CONTROL_STOP);
        }
    }

    pub fn enable_kernel_callstacks(
        &self,
        events: &Vec<CLASSIC_EVENT_ID>) -> anyhow::Result<()> {
        unsafe {
            let event_size = std::mem::size_of::<CLASSIC_EVENT_ID>() as u32;

            let result = TraceSetInformation(
                self.handle,
                3, /* TraceStackTracingInfo */
                events.as_ptr() as *const u8,
                events.len() as u32 * event_size);

            if result != 0 {
                anyhow::bail!("TraceSetInformation failed with {}", result);
            }
        }

        Ok(())
    }

    pub fn set_profile_interval(
        &self,
        milliseconds: u32) -> anyhow::Result<()> {
        let mut interval = TRACE_PROFILE_INTERVAL {
            Source: 0,
            Interval: 0 };
        let mut size: u32 = 0;
        let wanted: u32 = milliseconds * 10000;

        unsafe {
            let result = TraceQueryInformation(
                0,
                5, /* TraceSampledProfileIntervalInfo */
                &mut interval as *mut TRACE_PROFILE_INTERVAL as *mut u8,
                8,
                &mut size);

            if result != 0 {
                anyhow::bail!("TraceQueryInformation failed with {}", result);
            }

            if interval.Interval == wanted {
                return Ok(());
            }

            interval.Interval = wanted;

            let result = TraceSetInformation(
                0,
                5, /* TraceSampledProfileIntervalInfo */
                &interval as *const TRACE_PROFILE_INTERVAL as *const u8,
                8);

            if result != 0 {
                anyhow::bail!("TraceSetInformation failed with {}", result);
            }
        }

        Ok(())
    }

    pub fn enable_privilege(
        &self,
        name: &str) -> bool {
        let mut id: u64 = 0;
        let null_str = std::ptr::null::<u16>();
        let null_token = std::ptr::null_mut::<TOKEN_PRIVILEGES>();

        unsafe {
            let result = LookupPrivilegeValueW(
                null_str,
                wide_string(name).as_ptr(),
                &mut id);

            if result == 0 {
                return false;
            }
        }

        let mut token: RawHandle = std::ptr::null_mut();

        unsafe {
            let result = OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES,
                &mut token);

            if result == 0 {
                return false;
            }
        }

        let privs = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Luid: id,
            Attributes: SE_PRIVILEGE_ENABLED,
        };

        let mut return_size: u32 = 0;

        unsafe {
            let result = AdjustTokenPrivileges(
                token,
                0,
                &privs,
                std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                null_token,
                &mut return_size);

            CloseHandle(token);

            if result == 0 {
                return false;
            }
        }

        true
    }
}

impl Drop for TraceSession {
    fn drop(&mut self) {
        self.stop();
    }
}
