pub mod event;
pub mod sharing;
pub mod helpers;
pub mod intern;
pub mod state;

#[cfg(target_os = "linux")]
pub mod session;
#[cfg(target_os = "linux")]
pub mod tracefs;
#[cfg(target_os = "linux")]
pub mod procfs;
#[cfg(target_os = "linux")]
pub mod perf_event;
#[cfg(target_os = "linux")]
pub mod openat;

pub use sharing::{Writable, ReadOnly};

pub mod pathbuf_ext;
use pathbuf_ext::{PathBufInteger};

pub type IOResult<T> = std::io::Result<T>;
pub type IOError = std::io::Error;

pub fn io_error(message: &str) -> IOError {
    IOError::new(
        std::io::ErrorKind::Other,
        message)
}
