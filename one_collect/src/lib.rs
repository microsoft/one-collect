pub mod event;
pub mod sharing;
pub mod tracefs;
pub mod perf_event;
pub mod session;
pub mod state;
pub mod helpers;

pub use sharing::{Writable, ReadOnly};

pub type IOResult<T> = std::io::Result<T>;
pub type IOError = std::io::Error;

pub fn io_error(message: &str) -> IOError {
    IOError::new(
        std::io::ErrorKind::Other,
        message)
}
