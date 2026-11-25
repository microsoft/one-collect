// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
 * std::os::windows::RawHandle is not available when
 * documenting windows code on non-windows builds.
 * Use the common definition to allow for this.
 */
type RawHandle = *mut std::os::raw::c_void;

use std::sync::{Arc, Mutex, RwLock, Weak};
use windows_sys::Win32::Foundation::{ERROR_ACTIVE_CONNECTIONS, ERROR_MORE_DATA, ERROR_WMI_INSTANCE_NOT_FOUND};
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
        logfile: *mut EVENT_TRACE_LOGFILE) -> u64;

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
const EVENT_FILTER_TYPE_STACKWALK_LEVEL_KW: u32 = 0x80004000;

pub(super) const EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0: u32 = 64u32;
pub(super) const EVENT_ENABLE_PROPERTY_ENABLE_SILOS: u32 = 1024u32;
pub(super) const EVENT_ENABLE_PROPERTY_EVENT_KEY: u32 = 256u32;
pub(super) const EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE: u32 = 512u32;
pub(super) const EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0: u32 = 16u32;
pub(super) const EVENT_ENABLE_PROPERTY_PROCESS_START_KEY: u32 = 128u32;
pub(super) const EVENT_ENABLE_PROPERTY_PROVIDER_GROUP: u32 = 32u32;
pub(super) const EVENT_ENABLE_PROPERTY_PSM_KEY: u32 = 8u32;
pub(super) const EVENT_ENABLE_PROPERTY_SID: u32 = 1u32;
pub(super) const EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING: u32 = 2048u32;
pub(super) const EVENT_ENABLE_PROPERTY_STACK_TRACE: u32 = 4u32;
pub(super) const EVENT_ENABLE_PROPERTY_TS_ID: u32 = 2u32;

pub(super) const EVENT_HEADER_EXT_TYPE_CONTAINER_ID: u32 = 16u32;
pub(super) const EVENT_HEADER_EXT_TYPE_CONTROL_GUID: u32 = 14u32;
pub(super) const EVENT_HEADER_EXT_TYPE_EVENT_KEY: u32 = 10u32;
pub(super) const EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL: u32 = 11u32;
pub(super) const EVENT_HEADER_EXT_TYPE_INSTANCE_INFO: u32 = 4u32;
pub(super) const EVENT_HEADER_EXT_TYPE_MAX: u32 = 19u32;
pub(super) const EVENT_HEADER_EXT_TYPE_PEBS_INDEX: u32 = 7u32;
pub(super) const EVENT_HEADER_EXT_TYPE_PMC_COUNTERS: u32 = 8u32;
pub(super) const EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY: u32 = 13u32;
pub(super) const EVENT_HEADER_EXT_TYPE_PROV_TRAITS: u32 = 12u32;
pub(super) const EVENT_HEADER_EXT_TYPE_PSM_KEY: u32 = 9u32;
pub(super) const EVENT_HEADER_EXT_TYPE_QPC_DELTA: u32 = 15u32;
pub(super) const EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID: u32 = 1u32;
pub(super) const EVENT_HEADER_EXT_TYPE_SID: u32 = 2u32;
pub(super) const EVENT_HEADER_EXT_TYPE_STACK_KEY32: u32 = 17u32;
pub(super) const EVENT_HEADER_EXT_TYPE_STACK_KEY64: u32 = 18u32;
pub(super) const EVENT_HEADER_EXT_TYPE_STACK_TRACE32: u32 = 5u32;
pub(super) const EVENT_HEADER_EXT_TYPE_STACK_TRACE64: u32 = 6u32;
pub(super) const EVENT_HEADER_EXT_TYPE_TS_ID: u32 = 3u32;

pub(super) const TRACE_LEVEL_CRITICAL: u8 = 1;
pub(super) const TRACE_LEVEL_ERROR: u8 = 2;
pub(super) const TRACE_LEVEL_WARNING: u8 = 3;
pub(super) const TRACE_LEVEL_INFORMATION: u8 = 4;
pub(super) const TRACE_LEVEL_VERBOSE: u8 = 5;

pub(super) const EVENT_CONTROL_CODE_DISABLE_PROVIDER: u32 = 0;
pub(super) const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 = 1;
pub(super) const EVENT_CONTROL_CODE_CAPTURE_STATE: u32 = 2;

pub(super) fn wide_string(
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

pub(super) fn is_system_provider(provider: Guid) -> bool {
    use windows_sys::Win32::System::Diagnostics::Etw::*;

    let providers = [
        SystemAlpcProviderGuid, SystemConfigProviderGuid, SystemCpuProviderGuid,
        SystemHypervisorProviderGuid, SystemInterruptProviderGuid,
        SystemIoFilterProviderGuid, SystemIoProviderGuid, SystemLockProviderGuid,
        SystemMemoryProviderGuid, SystemObjectProviderGuid, SystemPowerProviderGuid,
        SystemProcessProviderGuid, SystemProfileProviderGuid, SystemRegistryProviderGuid,
        SystemSchedulerProviderGuid, SystemSyscallProviderGuid, SystemTimerProviderGuid,
    ];

    providers.iter().any(|guid| super::providers::win32_guid_to_guid(guid) == provider)
}

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Default)]
struct EVENT_FILTER_LEVEL_KW {
    pub MatchAnyKeyword: u64,
    pub MatchAllKeyword: u64,
    pub Level: u8,
    pub FilterIn: u8,
}

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

impl WNODE_HEADER {
    /// Namespace for deriving an ETW session's `Wnode.Guid` from its session
    /// name. Must be a fixed byte string, distinct from the `EventSource`
    /// provider-name namespace used by
    /// `helpers::dotnet::scripting::guid_from_provider` so session-name and
    /// provider-name GUIDs never collide.
    ///
    /// Any change to this string changes every derived GUID. That only affects
    /// GUID identity, not crash recovery, which is name-based (see
    /// [`TraceSession::start`]).
    const SESSION_NAMESPACE: &[u8] = b"one_collect ETW session namespace";

    /// Construct a `WNODE_HEADER` for a named ETW session destined for
    /// `StartTraceW`. `Guid` is derived from `session_name` and
    /// `WNODE_FLAG_TRACED_GUID` is set, so the kernel enforces per-name
    /// uniqueness while sessions with distinct names coexist. Because the same
    /// name always maps to the same GUID, the by-name `ControlTraceW(STOP)` in
    /// `TraceSession::start` can reclaim a stale session across processes.
    fn new(session_name: &str) -> Self {
        Self {
            BufferSize: std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32,
            ProviderId: 0,
            HistoricalContext: 0,
            TimeStamp: 0,
            Guid: Guid::v5_from_name(
                Self::SESSION_NAMESPACE,
                session_name.as_bytes()),
            ClientContext: 1,
            Flags: WNODE_FLAG_TRACED_GUID,
        }
    }

    /// Construct a `WNODE_HEADER` for a control operation, not a new logger.
    fn for_control() -> Self {
        Self {
            BufferSize: std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32,
            ProviderId: 0,
            HistoricalContext: 0,
            TimeStamp: 0,
            Guid: Guid::from_u128(0),
            ClientContext: 1,
            Flags: 0,
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
pub(super) struct CLASSIC_EVENT_ID {
    pub EventGuid: Guid,
    pub Type: u8,
    pub Reserved: [u8; 7],
}

impl CLASSIC_EVENT_ID {
    pub(super) fn new(
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
    pub BufferCallback: extern "C" fn(*const TRACE_LOGFILE_HEADER) -> u32,
    pub BufferSize: u32,
    pub Filled: u32,
    pub EventsLost: u32,
    pub EventRecordCallback: extern "C" fn (*const EVENT_RECORD),
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

impl EVENT_TRACE_PROPERTIES {
    /// Construct properties for a named ETW session to be started with
    /// `StartTraceW`; see [`WNODE_HEADER::new`].
    fn new(session_name: &str, system_logger: bool) -> Self {
        let mut properties = Self::with_wnode(WNODE_HEADER::new(session_name));
        if system_logger {
            properties.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
        }
        properties
    }

    /// Construct properties for driving `ControlTraceW`;
    /// see [`WNODE_HEADER::for_control`].
    fn for_control() -> Self {
        Self::with_wnode(WNODE_HEADER::for_control())
    }

    fn with_wnode(wnode: WNODE_HEADER) -> Self {
        let cpus = unsafe { GetActiveProcessorCount(0xFFFF) };

        Self {
            Wnode: wnode,
            BufferSize: 64,
            MinimumBuffers: cpus * 4,
            MaximumBuffers: cpus * 32,
            MaximumFileSize: 0,
            LogFileMode: EVENT_TRACE_REAL_TIME_MODE |
                EVENT_TRACE_INDEPENDENT_SESSION_MODE,
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

// The four ETW types that surface on the crate's public API
// (`AncillaryData::record()` returns a `&EVENT_RECORD`, and the upcoming
// `TdhDecoder` will take one) come from `windows-sys` so consumers and the
// decoder share a single type identity. The rest of this file's ETW
// surface (`EVENT_TRACE_PROPERTIES`, `WNODE_HEADER`, `ENABLE_TRACE_PARAMETERS`,
// the extern entry points, etc.) is internal-only and stays hand-rolled
// to keep the migration localized.
pub(super) use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXTENDED_DATA_ITEM,
    EVENT_RECORD,
    EVENT_TRACE_CONTROL_QUERY,
};

/// Extension trait providing the few ergonomic accessors the rest of the
/// `etw` module needs on `EVENT_RECORD`. `EVENT_RECORD` is a foreign type
/// now, so inherent methods aren't allowed; importing `EventRecordExt`
/// preserves call-site syntax like `record.user_data_slice()`. Crate-
/// internal only — external consumers receive `&EVENT_RECORD` and hand it
/// to the decoder, they never need these accessors themselves.
pub(crate) trait EventRecordExt {
    fn user_data_slice(&self) -> &[u8];
    fn processor_index(&self) -> u16;
    fn provider_guid(&self) -> Guid;
    fn activity_guid(&self) -> Guid;

    /// Searches the event's extended-data items for the first entry
    /// matching `ext_type`.  Returns a pointer to the matching
    /// [`EVENT_HEADER_EXTENDED_DATA_ITEM`], or `None` if not found.
    ///
    /// This is the single central place for extended-data lookup; both
    /// [`AncillaryData`] and the TDH decoder delegate to this method.
    fn find_extended_data(
        &self,
        ext_type: u16,
    ) -> Option<*const EVENT_HEADER_EXTENDED_DATA_ITEM>;
}

// SAFETY guard for the `provider_guid` / `activity_guid` transmutes below.
// `mem::transmute` already enforces same size at compile time, but spelling
// the assumption out gives a clear error message if a future `windows-sys`
// bump ever changes the `GUID` layout.
const _: () = assert!(
    std::mem::size_of::<Guid>() == std::mem::size_of::<windows_sys::core::GUID>(),
    "Guid and windows_sys::core::GUID must have identical size",
);
const _: () = assert!(
    std::mem::align_of::<Guid>() == std::mem::align_of::<windows_sys::core::GUID>(),
    "Guid and windows_sys::core::GUID must have identical alignment",
);

// SAFETY guard for the `processor_index` union read below. The
// `BufferContext.Anonymous` union has two arms (`ProcessorIndex: u16` and
// a packed `{ProcessorNumber: u8, Alignment: u8}`) that both occupy the
// same two bytes. If `windows-sys` ever grows the union to a third, larger
// variant or marks it `#[repr(packed)]`, our `u16` read would silently
// miss bytes or become unaligned; catch either at build time instead.
const _: () = assert!(
    std::mem::size_of::<
        windows_sys::Win32::System::Diagnostics::Etw::ETW_BUFFER_CONTEXT_0
    >() == 2,
    "ETW_BUFFER_CONTEXT_0 union must remain 2 bytes",
);
const _: () = assert!(
    std::mem::align_of::<
        windows_sys::Win32::System::Diagnostics::Etw::ETW_BUFFER_CONTEXT_0
    >() >= std::mem::align_of::<u16>(),
    "ETW_BUFFER_CONTEXT_0 union must be at least u16-aligned",
);

impl EventRecordExt for EVENT_RECORD {
    #[inline]
    fn user_data_slice(&self) -> &[u8] {
        if self.UserData.is_null() || self.UserDataLength == 0 {
            return &[];
        }
        unsafe {
            std::slice::from_raw_parts(
                self.UserData as *const u8,
                self.UserDataLength as usize)
        }
    }

    #[inline]
    fn processor_index(&self) -> u16 {
        // SAFETY: `BufferContext.Anonymous` is a union whose two arms
        // (`ProcessorIndex: u16` and `{ProcessorNumber: u8, Alignment: u8}`)
        // alias the same two bytes; either arm always contains a valid
        // bit-pattern for a `u16`. The const assertion above guards the
        // 2-byte size against future `windows-sys` layout drift.
        unsafe { self.BufferContext.Anonymous.ProcessorIndex }
    }

    #[inline]
    fn provider_guid(&self) -> Guid {
        // SAFETY: `Guid` and `windows_sys::core::GUID` are both `#[repr(C)]`
        // with identical field order, widths, and (asserted above) size and
        // alignment, so a bit-for-bit transmute is sound.
        unsafe { std::mem::transmute(self.EventHeader.ProviderId) }
    }

    #[inline]
    fn activity_guid(&self) -> Guid {
        // SAFETY: see `provider_guid` above.
        unsafe { std::mem::transmute(self.EventHeader.ActivityId) }
    }

    fn find_extended_data(
        &self,
        ext_type: u16,
    ) -> Option<*const EVENT_HEADER_EXTENDED_DATA_ITEM> {
        if self.ExtendedDataCount == 0 || self.ExtendedData.is_null() {
            return None;
        }
        unsafe {
            let ext = self.ExtendedData;
            for i in 0..self.ExtendedDataCount as usize {
                let item = ext.add(i);
                if (*item).ExtType == ext_type {
                    return Some(item);
                }
            }
        }
        None
    }
}

pub(super) struct TraceFilter {
    filter_type: u32,
    filter_data: Vec<u8>,
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
    callstack_keyword: Option<u64>,
    custom_filter: Option<TraceFilter>,
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
            callstack_keyword: None,
            custom_filter: None,
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

    pub fn ensure_callstack_keyword(
        &mut self,
        keyword: u64) {
        self.callstack_keyword = Some(keyword);
    }

    pub fn ensure_no_filtering(
        &mut self) {
        self.no_filtering = true;
    }

    pub fn ensure_custom_filter(
        &mut self,
        filter_type: u32,
        filter_data: Vec<u8>) {
        self.custom_filter = Some(TraceFilter {
            filter_type,
            filter_data,
        });
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
        self.with_enable_parameters(target_pids, |params| {
            let result = unsafe {
                EnableTraceEx2(
                    handle,
                    &self.provider,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    self.level,
                    self.keyword,
                    0,
                    0,
                    params)
            };

            if result != 0 {
                anyhow::bail!("EnableTraceEx2 failed with {}", result);
            }

            Ok(())
        })
    }

    fn with_enable_parameters(
        &self,
        target_pids: &Option<Vec<i32>>,
        enable: impl FnOnce(&ENABLE_TRACE_PARAMETERS) -> anyhow::Result<()>) -> anyhow::Result<()> {
        let mut params = ENABLE_TRACE_PARAMETERS::default();

        // Keep every descriptor and backing buffer alive through the enable call.
        let events_filter;
        let callstacks_filter;
        let callstack_kw_filter;
        let mut filters = Vec::new();

        if !self.no_filtering {
            let mut events = EVENT_FILTER_DESCRIPTOR::default();
            events_filter = Self::build_event_filter(&self.events);
            events.Type = EVENT_FILTER_TYPE_EVENT_ID;
            events.Filter = events_filter.as_ptr();
            events.Size = events_filter.len() as u32;

            let mut callstacks = EVENT_FILTER_DESCRIPTOR::default();
            callstacks_filter = Self::build_event_filter(&self.callstacks);
            callstacks.Type = EVENT_FILTER_TYPE_STACKWALK;
            callstacks.Filter = callstacks_filter.as_ptr();
            callstacks.Size = callstacks_filter.len() as u32;

            let mut pids = EVENT_FILTER_DESCRIPTOR::default();
            pids.Type = EVENT_FILTER_TYPE_PID;

            if let Some(custom) = &self.custom_filter {
                let mut custom_desc = EVENT_FILTER_DESCRIPTOR::default();
                custom_desc.Type = custom.filter_type;
                custom_desc.Filter = custom.filter_data.as_ptr();
                custom_desc.Size = custom.filter_data.len() as u32;

                filters.push(custom_desc);
            }

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

            if let Some(callstack_keyword) = self.callstack_keyword {
                callstack_kw_filter = EVENT_FILTER_LEVEL_KW {
                    MatchAnyKeyword: callstack_keyword,
                    FilterIn: 1,
                    ..EVENT_FILTER_LEVEL_KW::default()
                };
                let mut callstack_kw = EVENT_FILTER_DESCRIPTOR::default();
                callstack_kw.Type = EVENT_FILTER_TYPE_STACKWALK_LEVEL_KW;
                callstack_kw.Filter = &callstack_kw_filter as *const EVENT_FILTER_LEVEL_KW as *const u8;
                callstack_kw.Size = std::mem::size_of::<EVENT_FILTER_LEVEL_KW>() as u32;

                filters.push(callstack_kw);
            }

            params.EnableProperty |= self.properties;
            params.EnableFilterDesc = filters.as_ptr();
            params.FilterDescCount = filters.len() as u32;
        }

        enable(&params)
    }
}

pub(super) fn query_stats(handle: u64) -> anyhow::Result<super::SessionStats> {
    let mut properties = EVENT_TRACE_PROPERTIES::for_control();

    let result = unsafe {
        ControlTraceW(
            handle,
            std::ptr::null(),
            &mut properties,
            EVENT_TRACE_CONTROL_QUERY)
    };

    if result != 0 {
        anyhow::bail!("ControlTraceW query failed with {}", result);
    }

    Ok(session_stats(&properties))
}

fn session_stats(
    properties: &EVENT_TRACE_PROPERTIES) -> super::SessionStats {
    super::SessionStats {
        events_lost: properties.EventsLost,
        real_time_buffers_lost: properties.RealTimeBuffersLost,
        log_buffers_lost: properties.LogBuffersLost,
        buffers_written: properties.BuffersWritten,
    }
}

pub(crate) fn flush_trace(handle: u64) {
    let mut properties = EVENT_TRACE_PROPERTIES::for_control();

    unsafe {
        ControlTraceW(
            handle,
            std::ptr::null(),
            &mut properties,
            EVENT_TRACE_CONTROL_FLUSH);
    }
}

pub(super) struct TraceSession {
    properties: EVENT_TRACE_PROPERTIES,
    name: String,
    handle: u64,
}

// Serialize in-process starts against generation-checked native operations.
// Never hold this lock across user callbacks, ProcessTrace, or a stop wait.
static LOGGER_LIFECYCLE: RwLock<Vec<Weak<StartedLogger>>> = RwLock::new(Vec::new());

extern "C" fn buffer_callback(_header: *const TRACE_LOGFILE_HEADER) -> u32 {
    1
}

extern "C" fn event_callback(record: *const EVENT_RECORD) {
    let record = unsafe { &*record };

    /* Get dyn-typed thin pointer */
    let thin = record.UserContext as *mut Box<dyn FnMut(&EVENT_RECORD)>;

    /* Get back the fat pointer and ref */
    let processor = unsafe { &mut *thin };

    /* Process event */
    processor(record);
}

impl TraceSession {
    pub(super) fn new(
        name: String,
        buf_size_kb: u32,
        system_logger: bool) -> Self {
        let mut properties = EVENT_TRACE_PROPERTIES::new(&name, system_logger);

        properties.BufferSize = buf_size_kb;

        Self {
            properties,
            name,
            handle: 0,
        }
    }

    pub(super) fn handle(&self) -> u64 { self.handle }

    pub(super) fn id(&self) -> u64 { self.properties.Wnode.HistoricalContext }

    pub(super) fn start(
        &mut self) -> anyhow::Result<StopOwner> {
        let trace_name = wide_string(&self.name);
        let mut loggers = LOGGER_LIFECYCLE.write().unwrap();

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
                if result == 5 {
                    anyhow::bail!(
                        "StartTraceW failed with 5 (access denied): the account needs ETW session permissions (for ordinary sessions, e.g. Performance Log Users membership) or elevation; system tracing may require additional permissions");
                }
                anyhow::bail!("StartTraceW failed with {}", result);
            }
        }

        let logger = Arc::new(StartedLogger {
            name: trace_name,
            id: self.id(),
            thread_id: self.properties.LoggerThreadId as usize,
            stop_attempts_left: Mutex::new(2), // Initial stop plus one cleanup retry.
        });
        // Retire previous in-process owners even if Windows also reused the thread ID.
        loggers.retain(|weak| {
            let Some(old) = weak.upgrade() else { return false };
            if old.id == logger.id || old.name == logger.name { old.ended(); }
            old.can_stop()
        });
        loggers.push(Arc::downgrade(&logger));
        Ok(StopOwner(logger))
    }

    fn open_trace(
        name: &[u16],
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

        log.LoggerName = name.as_ptr();

        log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD |
                               PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_RAW_TIMESTAMP;

        log.Context = context;

        unsafe {
            let handle = OpenTraceW(&mut log);

            if handle == 0xFFFFFFFFFFFFFFFF {
                anyhow::bail!("OpenTraceW failed with {}", GetLastError());
            }

            Ok(handle)
        }
    }

    pub(super) fn enable_kernel_callstacks(
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

    pub(super) fn set_profile_interval(
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

    pub(super) fn enable_privilege(
        &self,
        name: &str) -> anyhow::Result<()> {
        let mut id: u64 = 0;
        let null_str = std::ptr::null::<u16>();
        let null_token = std::ptr::null_mut::<TOKEN_PRIVILEGES>();

        unsafe {
            let result = LookupPrivilegeValueW(
                null_str,
                wide_string(name).as_ptr(),
                &mut id);

            if result == 0 {
                anyhow::bail!("LookupPrivilegeValueW({name}) failed with {}", GetLastError());
            }
        }

        let mut token: RawHandle = std::ptr::null_mut();

        unsafe {
            let result = OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES,
                &mut token);

            if result == 0 {
                anyhow::bail!("OpenProcessToken for {name} failed with {}", GetLastError());
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

            let error = GetLastError();
            CloseHandle(token);

            if result == 0 {
                anyhow::bail!("AdjustTokenPrivileges({name}) failed with {error}");
            }
            if error != 0 {
                anyhow::bail!(
                    "AdjustTokenPrivileges({name}) failed with {error}: the privilege must be assigned to the account before it can be enabled");
            }
        }

        Ok(())
    }
}

// A TRACEHANDLE is a reusable logger slot, not a reference to a session.
// Keep the name for native STOP, the logger thread ID to detect replacement,
// and a bounded stop budget shared with the consumer's error path.
pub(super) struct StartedLogger {
    name: Vec<u16>,
    id: u64,
    thread_id: usize,
    stop_attempts_left: Mutex<u8>,
}

impl StartedLogger {
    pub(super) fn ended(&self) {
        *self.stop_attempts_left.lock().unwrap() = 0;
    }

    fn can_stop(&self) -> bool {
        *self.stop_attempts_left.lock().unwrap() != 0
    }

    fn control(&self, code: u32, props: &mut EVENT_TRACE_PROPERTIES) -> u32 {
        unsafe { ControlTraceW(0, self.name.as_ptr(), props, code) }
    }

    fn verify_identity(&self, attempts: &mut u8, query: impl FnOnce(&mut EVENT_TRACE_PROPERTIES) -> u32)
        -> anyhow::Result<()> {
        let mut props = EVENT_TRACE_PROPERTIES::for_control();
        let status = query(&mut props);
        if status == ERROR_WMI_INSTANCE_NOT_FOUND { *attempts = 0; }
        anyhow::ensure!(status == 0, "ControlTraceW identity query failed with {}", status);
        if props.Wnode.HistoricalContext != self.id || props.LoggerThreadId as usize != self.thread_id {
            *attempts = 0;
            anyhow::bail!("ETW session was replaced");
        }
        Ok(())
    }

    pub(super) fn current_handle(&self, handle: u64) -> u64 {
        self.with_current(|| Ok(handle)).unwrap_or(0)
    }

    pub(super) fn with_current<T>(&self, operate: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
        let _no_restarts = LOGGER_LIFECYCLE.read().unwrap();
        let mut attempts = self.stop_attempts_left.lock().unwrap();
        anyhow::ensure!(*attempts != 0, "ETW session is no longer owned");
        self.verify_identity(&mut attempts, |p| self.control(EVENT_TRACE_CONTROL_QUERY, p))?;
        operate()
    }

    pub(super) fn open_consumer(
        &self,
        parse: Box<dyn FnMut(&EVENT_RECORD)>) -> anyhow::Result<TraceConsumer> {
        let mut callback = Box::new(parse);
        let context = std::ptr::from_mut(callback.as_mut()).cast();
        // OpenTraceW resolves by name. A start must not replace us between
        // checking who owns that name and opening the consumer.
        let handle = self.with_current(|| TraceSession::open_trace(&self.name, context))?;
        Ok(TraceConsumer { handle, _callback: callback })
    }

    pub(super) fn stop(&self) -> anyhow::Result<super::SessionStats> {
        self.stop_using(|code, p| self.control(code, p))
    }

    fn stop_using(&self, mut control: impl FnMut(u32, &mut EVENT_TRACE_PROPERTIES) -> u32)
        -> anyhow::Result<super::SessionStats> {
        let _no_restarts = LOGGER_LIFECYCLE.read().unwrap();
        let mut attempts = self.stop_attempts_left.lock().unwrap();
        anyhow::ensure!(*attempts != 0, "ETW stop ownership has ended");
        *attempts -= 1;
        self.verify_identity(&mut attempts, |p| control(EVENT_TRACE_CONTROL_QUERY, p))?;
        let mut props = EVENT_TRACE_PROPERTIES::for_control();
        let status = control(EVENT_TRACE_CONTROL_STOP, &mut props);
        // MORE_DATA on STOP means the logger stopped but ETW couldn't return all
        // properties. ACTIVE_CONNECTIONS means stop is already in progress.
        if matches!(status, 0 | ERROR_MORE_DATA | ERROR_ACTIVE_CONNECTIONS | ERROR_WMI_INSTANCE_NOT_FOUND) {
            *attempts = 0;
        }
        anyhow::ensure!(status == 0, "ControlTraceW stop failed with {}", status);
        Ok(session_stats(&props))
    }

    pub(super) fn cleanup(&self) {
        while self.can_stop() {
            if let Err(err) = self.stop() {
                tracing::warn!("ETW cleanup: {}", err);
            }
        }
    }
}

pub(super) struct StopOwner(pub(super) Arc<StartedLogger>);

impl Drop for StopOwner {
    fn drop(&mut self) {
        self.0.cleanup();
    }
}

pub(super) struct TraceConsumer {
    handle: u64,
    // ETW needs a stable, thin pointer to the boxed trait object until CloseTrace.
    _callback: Box<Box<dyn FnMut(&EVENT_RECORD)>>,
}

impl TraceConsumer {
    pub(super) fn process(self) -> anyhow::Result<()> {
        let status = unsafe { ProcessTrace(&self.handle, 1, std::ptr::null(), std::ptr::null()) };
        if status != 0 {
            anyhow::bail!("ProcessTrace failed with {}", status);
        }
        Ok(())
    }
}

impl Drop for TraceConsumer {
    fn drop(&mut self) {
        unsafe { CloseTrace(self.handle); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires ETW session permissions"]
    fn logger_ownership_stale_open_stop_and_drop_leave_the_replacement_running() {
        let name = format!("one_collect_stop_ownership_{}", std::process::id());
        let start = || TraceSession::new(name.clone(), 64, false).start().unwrap();
        let first = start();
        // start() reclaims the previous logger by name. The old owner is still
        // around and Windows is free to reuse its numeric slot immediately.
        let second = start();
        assert!(first.0.open_consumer(Box::new(|_| {})).is_err(),
            "superseded owner opened a consumer on the replacement");
        drop(second.0.open_consumer(Box::new(|_| {})).expect("replacement must open its own consumer"));
        assert!(first.0.stop().is_err(), "old owner returned the new logger's statistics");
        drop(first);
        second.0.stop().expect("stale teardown stopped the replacement");

        let third = start();
        drop(second); // Already explicitly stopped; Drop must not send another STOP.
        third.0.stop().expect("dropping a completed owner stopped a later capture");
    }

    #[test]
    #[ignore = "requires ETW session permissions"]
    fn logger_ownership_drop_retries_transient_query_and_stop_failures() {
        use windows_sys::Win32::Foundation::ERROR_BUSY;
        let name = format!("one_collect_retry_test_{}", std::process::id());
        for fail_op in [EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP] {
            let owner = TraceSession::new(name.clone(), 64, false).start().unwrap();
            let logger = owner.0.clone();
            let result = logger.stop_using(|op, p| {
                if op == fail_op { ERROR_BUSY } else { logger.control(op, p) }
            });
            assert!(result.is_err(), "failed stop must not produce final statistics");
            drop(owner);
            let mut props = EVENT_TRACE_PROPERTIES::for_control();
            let status = logger.control(EVENT_TRACE_CONTROL_QUERY, &mut props);
            if status == 0 { logger.control(EVENT_TRACE_CONTROL_STOP, &mut props); }
            assert_eq!(status, ERROR_WMI_INSTANCE_NOT_FOUND, "cleanup left the original logger running");
        }
    }

    #[test]
    fn logger_ownership_retry_rechecks_identity_and_is_bounded() {
        use windows_sys::Win32::Foundation::ERROR_BUSY;
        for replaced in [false, true] {
            let logger = StartedLogger {
                name: Vec::new(), id: 10, thread_id: 20, stop_attempts_left: Mutex::new(2),
            };
            let mut stops = 0;
            for attempt in 0..2 {
                let result = logger.stop_using(|op, p| {
                    if op == EVENT_TRACE_CONTROL_QUERY {
                        p.Wnode.HistoricalContext = logger.id;
                        let tid = if replaced && attempt == 1 { 21 } else { logger.thread_id };
                        p.LoggerThreadId = tid as RawHandle;
                        0
                    } else {
                        stops += 1;
                        ERROR_BUSY
                    }
                });
                assert!(result.is_err());
            }
            assert_eq!(stops, if replaced { 1 } else { 2 });
            assert!(logger.stop_using(|_, _| panic!("unbounded stop retry")).is_err());
        }
    }

    #[test]
    fn ordinary_session_does_not_use_system_logger_mode() {
        let properties = EVENT_TRACE_PROPERTIES::new("one_collect_ordinary_mode_test", false);
        assert_eq!(properties.LogFileMode,
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_INDEPENDENT_SESSION_MODE);
    }

    #[test]
    fn system_session_preserves_system_logger_mode() {
        let properties = EVENT_TRACE_PROPERTIES::new("one_collect_system_mode_test", true);
        assert_eq!(properties.LogFileMode,
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_INDEPENDENT_SESSION_MODE |
            EVENT_TRACE_SYSTEM_LOGGER_MODE);
    }

    #[test]
    fn invalid_privilege_reports_lookup_failure() {
        let session = TraceSession::new("one_collect_privilege_test".into(), 64, false);
        let error = session.enable_privilege("OneCollectNonexistentPrivilege").unwrap_err();
        assert!(error.to_string().contains("LookupPrivilegeValueW"));
    }
}
