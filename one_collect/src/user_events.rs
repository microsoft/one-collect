// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::CString;
use std::mem;
use std::fs::File;
use std::io::{self, Result};
use std::rc::Rc;
use tracing::{debug, warn};

#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

#[cfg(target_os = "linux")]
use libc::*;

pub trait UserEventDesc {
    fn format(&self) -> String;
}

pub struct RawEventDesc {
    name: String,
    description: String,
}

impl RawEventDesc {
    pub fn new(
        name: &str,
        description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl UserEventDesc for RawEventDesc {
    fn format(&self) -> String {
        format!(
            "{} {}",
            self.name,
            self.description
        )
    }
}

const EVENT_HEADER_FIELDS: &str = "u8 eventheader_flags u8 version u16 id u16 tag u8 opcode u8 level";

pub struct EventHeaderDesc {
    name: String,
}

impl EventHeaderDesc {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl UserEventDesc for EventHeaderDesc {
    fn format(&self) -> String {
        format!(
            "{} {}",
            self.name, 
            EVENT_HEADER_FIELDS
        )
    }
}

pub struct UserEvent {
    user_event_data: Rc<File>,
    descr: String,
    enabled: u32,
    write_index: u32,
}

impl UserEvent {
    fn new(
        user_events_data: &Rc<File>,
        descr: &dyn UserEventDesc) -> Self {
        Self {
            user_event_data: Rc::clone(user_events_data),
            descr: descr.format(),
            enabled: 0,
            write_index: UNREGISTERED_WRITE_INDEX,
        }
    }

    fn register(&mut self) -> Result<()> {
        let name_args = CString::new(self.descr.as_str())?;
        let mut reg = UserReg {
            size: mem::size_of::<UserReg>() as u32,
            enable_bit: 0,
            enable_size: 4,
            flags: 0,
            enable_addr: &mut self.enabled as *const u32 as u64,
            name_args: name_args.as_ptr() as u64,
            write_index: UNREGISTERED_WRITE_INDEX,
        };

        let ret = unsafe {
            libc::ioctl(self.user_event_data.as_raw_fd(), DIAG_IOCSREG, &mut reg)
        };

        if ret < 0 {
            warn!("User event registration failed: name_args={}", self.descr);
            return Err(io::Error::last_os_error());
        }

        self.write_index = reg.write_index;

        debug!("User event registered: write_index={}", self.write_index);
        Ok(())
    }

    fn unregister(&mut self) -> Result<()> {
        let unreg = UserUnreg {
            size: mem::size_of::<UserUnreg>() as u32,
            disable_bit: 0,
            reserved: 0,
            reserved2: 0,
            disable_addr: &mut self.enabled as *const u32 as u64,
        };

        let ret = unsafe {
            libc::ioctl(self.user_event_data.as_raw_fd(), DIAG_IOCSUNREG, &unreg)
        };

        if ret < 0 {
            warn!("User event unregistration failed");
            return Err(io::Error::last_os_error());
        }

        self.write_index = UNREGISTERED_WRITE_INDEX;

        Ok(())
    }
}

impl Drop for UserEvent {
    fn drop(&mut self) {
        if self.write_index != UNREGISTERED_WRITE_INDEX {
            let _ = self.unregister();
            self.write_index = UNREGISTERED_WRITE_INDEX;
        }
    }
}

pub struct UserEventsFactory {
    user_events_data: Rc<File>,
}

impl UserEventsFactory {
    pub (crate) fn new(user_events_data: File) -> Self {
        Self {
            user_events_data: Rc::new(user_events_data),
        }
    }

    pub fn create(
        &self,
        event_desc: &dyn UserEventDesc) -> Result<Box<UserEvent>> {
        let mut event = Box::new(UserEvent::new(&self.user_events_data, event_desc));
        event.register()?;

        Ok(event)
    }
}

#[repr(C, packed)]
#[derive(Debug)]
pub (crate) struct UserReg {
    /// Input: Size of the UserReg structure being used
    size: u32,

    /// Input: Bit in enable address to use
    enable_bit: u8,

    /// Input: Enable size in bytes at address
    enable_size: u8,

    /// Input: Flags to use, if any
    flags: u16,

    /// Input: Address to update when enabled
    enable_addr: u64,

    /// Input: Pointer to string with event name, description and flags
    name_args: u64,

    /// Output: Index of the event to use when writing data
    pub (crate) write_index: u32,
}

#[repr(C, packed)]
#[derive(Debug)]
pub (crate) struct UserUnreg {
    /// Input: Size of the user_unreg structure being used
    size: u32,

    /// Input: Bit to unregister
    disable_bit: u8,

    /// Input: Reserved, set to 0
    reserved: u8,

    /// Input: Reserved, set to 0
    reserved2: u16,

    /// Input: Address to unregister
    disable_addr: u64,
}

pub (crate) const UNREGISTERED_WRITE_INDEX: u32 = u32::MAX;

#[cfg(target_os = "linux")]
// ioctl request type differs between glibc (c_ulong) and musl (c_int)
// Use libc::Ioctl which is platform-specific
type IoctlRequest = libc::Ioctl;

#[cfg(target_os = "linux")]
const IOC_WRITE: IoctlRequest = 1;
#[cfg(target_os = "linux")]
const IOC_READ: IoctlRequest = 2;
#[cfg(target_os = "linux")]
const DIAG_IOC_MAGIC: IoctlRequest = '*' as IoctlRequest;
#[cfg(target_os = "linux")]
pub (crate) const DIAG_IOCSREG: IoctlRequest = ioc(IOC_WRITE | IOC_READ, DIAG_IOC_MAGIC, 0);
#[cfg(target_os = "linux")]
pub (crate) const DIAG_IOCSUNREG: IoctlRequest = ioc(IOC_WRITE, DIAG_IOC_MAGIC, 2);

#[cfg(target_os = "linux")]
const fn ioc(dir: IoctlRequest, typ: IoctlRequest, nr: IoctlRequest) -> IoctlRequest {
    const IOC_NRBITS: u8 = 8;
    const IOC_TYPEBITS: u8 = 8;
    const IOC_SIZEBITS: u8 = 14;
    const IOC_NRSHIFT: u8 = 0;
    const IOC_TYPESHIFT: u8 = IOC_NRSHIFT + IOC_NRBITS;
    const IOC_SIZESHIFT: u8 = IOC_TYPESHIFT + IOC_TYPEBITS;
    const IOC_DIRSHIFT: u8 = IOC_SIZESHIFT + IOC_SIZEBITS;

    (dir << IOC_DIRSHIFT)
        | (typ << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | ((mem::size_of::<usize>() as IoctlRequest) << IOC_SIZESHIFT)
}

pub trait WithUserEventFD {
    fn write_all_with_user_events_fd(
        &mut self,
        buf: &[u8]) -> anyhow::Result<()>;
}

#[cfg(target_os = "linux")]
impl WithUserEventFD for UnixStream {
    fn write_all_with_user_events_fd(
        &mut self,
        buf: &[u8]) -> anyhow::Result<()> {
        let fd_len = std::mem::size_of::<RawFd>() as u32;

        let mut iov = iovec {
            iov_base: buf.as_ptr() as *mut c_void,
            iov_len: buf.len(),
        };

        unsafe {
            let path = CString::new("/sys/kernel/tracing/user_events_data")?;

            let user_fd = libc::open(path.as_ptr(), libc::O_RDWR);

            if user_fd == -1 {
                anyhow::bail!(
                    "Unable to open user_events_data file, error={}",
                    *libc::__errno_location());
            }

            let mut cmsg = Vec::with_capacity(
                libc::CMSG_SPACE(fd_len) as usize);

            // Initialize msghdr - on musl, this struct has private padding fields
            // and msg_controllen is u32, not usize
            let mut msg: msghdr = unsafe { mem::zeroed() };
            msg.msg_name = std::ptr::null_mut();
            msg.msg_namelen = 0;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg.as_mut_ptr();
            msg.msg_controllen = libc::CMSG_LEN(fd_len) as _;
            msg.msg_flags = 0;

            /* Init Control Message */
            let cmsg_raw = libc::CMSG_FIRSTHDR(&msg);
            let cmsg = &mut *cmsg_raw;

            cmsg.cmsg_len = libc::CMSG_LEN(fd_len) as _;
            cmsg.cmsg_level = libc::SOL_SOCKET;
            cmsg.cmsg_type = libc::SCM_RIGHTS;

            /* Set the user events FD */
            let cmsg_data = libc::CMSG_DATA(cmsg_raw) as *mut RawFd;
            *cmsg_data = user_fd;

            /* Send message with control message */
            let result = libc::sendmsg(self.as_raw_fd(), &msg, libc::MSG_NOSIGNAL);

            /* Always close */
            libc::close(user_fd);

            if result == -1 {
                anyhow::bail!(
                    "Unable to send message, error={}",
                    *libc::__errno_location());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracefs::TraceFS;

    #[test]
    fn raw_event_description() {
        let event = RawEventDesc::new("test_event", "u32 num");
        assert_eq!(event.name(), "test_event");
        assert_eq!(event.format(), "test_event u32 num");
    }

    #[test]
    fn event_header_description() {
        let event = EventHeaderDesc::new("test_event");
        assert_eq!(event.format(), format!("test_event {}", EVENT_HEADER_FIELDS));
    }

    #[test]
    #[ignore]
    fn user_events_reg_unreg() {
        println!("NOTE: Requires sudo/SYS_CAP_ADMIN/tracefs access.");
        let tracefs1 = TraceFS::open().unwrap();
        let factory1 = tracefs1.user_events_factory().unwrap();
        assert!(tracefs1.find_event("user_events", "test_user_event1").is_err());
        assert!(tracefs1.find_event("user_events", "test_user_event2").is_err());
        assert!(tracefs1.find_event("user_events", "test_user_event3").is_err());

        let event_descr = RawEventDesc::new("test_user_event1", "u32 num");
        let event1 = factory1.create(&event_descr).unwrap();
        assert!(tracefs1.find_event("user_events", "test_user_event1").is_ok());

        let event_descr = RawEventDesc::new("test_user_event2", "u32 num");
        let event2 = factory1.create(&event_descr).unwrap();
        assert!(tracefs1.find_event("user_events", "test_user_event2").is_ok());

        let tracefs2 = TraceFS::open().unwrap();
        let factory2 = tracefs2.user_events_factory().unwrap();
        let event_descr = RawEventDesc::new("test_user_event3", "u32 num");
        let event3 = factory2.create(&event_descr).unwrap();
        assert!(tracefs2.find_event("user_events", "test_user_event3").is_ok());

        drop(tracefs1);
        drop(tracefs2);
        drop(factory1);
        drop(factory2);

        // Wait for the changes to propagate.
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Events should still exist because the file is held alive by each event.
        let tracefs = TraceFS::open().unwrap();
        assert!(tracefs.find_event("user_events", "test_user_event1").is_ok());
        assert!(tracefs.find_event("user_events", "test_user_event2").is_ok());
        assert!(tracefs.find_event("user_events", "test_user_event3").is_ok());

        drop(event1);
        drop(event2);
        drop(event3);

        // Wait for the changes to propagate.
        std::thread::sleep(std::time::Duration::from_secs(1));

        let tracefs = TraceFS::open().unwrap();
        assert!(tracefs.find_event("user_events", "test_user_event1").is_err());
        assert!(tracefs.find_event("user_events", "test_user_event2").is_err());
        assert!(tracefs.find_event("user_events", "test_user_event3").is_err());
    }

    #[test]
    #[ignore]
    fn user_events_max_events_reg() {
        println!("NOTE: Requires sudo/SYS_CAP_ADMIN/tracefs access.");
        let tracefs = TraceFS::open().unwrap();
        let factory = tracefs.user_events_factory().unwrap();
        let mut events: Vec<Box<UserEvent>> = vec![];
        /*
         * In theory you can have up to 2^16 events on the system.
         * However, we only need to test a reasonable amount.
         */
        for i in 0..1024 {
            let event_descr = RawEventDesc::new(
                format!("test_max_user_event{}", i).as_str(),
                "u32 num");
            let event = factory.create(&event_descr).unwrap();
            events.push(event);
        }
    }
}
