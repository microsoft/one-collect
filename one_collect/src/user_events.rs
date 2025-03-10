use core::ffi;
use std::ffi::CString;
use std::mem;
use std::fs::File;
use std::io::{self, Result};
use std::rc::Rc;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

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
        let reg = UserReg {
            size: mem::size_of::<UserReg>() as u32,
            enable_bit: 0,
            enable_size: 4,
            flags: 0,
            enable_addr: &mut self.enabled as *const u32 as u64,
            name_args: name_args.as_ptr() as u64,
            write_index: UNREGISTERED_WRITE_INDEX,
        };

        let ret = unsafe {
            libc::ioctl(self.user_event_data.as_raw_fd(), DIAG_IOCSREG, &reg)
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        self.write_index = reg.write_index;

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

const IOC_WRITE: ffi::c_ulong = 1;
const IOC_READ: ffi::c_ulong = 2;
const DIAG_IOC_MAGIC: ffi::c_ulong = '*' as ffi::c_ulong;
pub (crate) const DIAG_IOCSREG: ffi::c_ulong = ioc(IOC_WRITE | IOC_READ, DIAG_IOC_MAGIC, 0);
pub (crate) const DIAG_IOCSUNREG: ffi::c_ulong = ioc(IOC_WRITE, DIAG_IOC_MAGIC, 2);

const fn ioc(dir: ffi::c_ulong, typ: ffi::c_ulong, nr: ffi::c_ulong) -> ffi::c_ulong {
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
        | ((mem::size_of::<usize>() as ffi::c_ulong) << IOC_SIZESHIFT)
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
        for i in 0..u32::MAX - 2 {
            let event_descr = RawEventDesc::new(
                format!("test_user_event{}", i).as_str(),
                "u32 num");
            let event = factory.create(&event_descr).unwrap();
            events.push(event);
        }
    }
}