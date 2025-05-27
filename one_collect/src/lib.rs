pub mod event;
pub mod sharing;
pub mod helpers;
pub mod intern;

#[cfg(any(doc, target_os = "linux"))]
pub mod tracefs;
#[cfg(any(doc, target_os = "linux"))]
pub mod procfs;
#[cfg(any(doc, target_os = "linux"))]
pub mod perf_event;
#[cfg(any(doc, target_os = "linux"))]
pub mod openat;
#[cfg(any(doc, target_os = "linux"))]
pub mod user_events;

#[cfg(any(doc, target_os = "windows"))]
pub mod etw;

#[cfg(feature = "scripting")]
pub mod scripting;

pub use sharing::{Writable, ReadOnly};

pub mod pathbuf_ext;
pub use pathbuf_ext::{PathBufInteger};

pub type IOResult<T> = std::io::Result<T>;
pub type IOError = std::io::Error;

pub fn io_error(message: &str) -> IOError {
    IOError::new(
        std::io::ErrorKind::Other,
        message)
}
