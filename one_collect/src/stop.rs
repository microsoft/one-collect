// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_os = "linux"))]
use std::sync::Condvar;

/// The sending half of a one-capture stop notification. Dropping it does not stop capture.
#[derive(Clone)]
pub struct StopHandle(Arc<State>);

/// The receiving half, consumed by one `parse_until_stop_requested` call.
pub struct StopToken(Arc<State>);

/// `parse_until_stop_requested` was called with an already-stopped token.
/// The call skipped parsing and did not process any events.
#[derive(Debug)]
pub struct ParseCancelledBeforeStart;

impl std::fmt::Display for ParseCancelledBeforeStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("parsing cancelled before start")
    }
}

impl std::error::Error for ParseCancelledBeforeStart {}

struct State {
    #[cfg(target_os = "linux")]
    requested: AtomicBool,
    #[cfg(target_os = "linux")]
    sender: Mutex<Option<UnixStream>>,
    #[cfg(target_os = "linux")]
    receiver: UnixStream,
    #[cfg(not(target_os = "linux"))]
    requested: Mutex<bool>,
    #[cfg(not(target_os = "linux"))]
    changed: Condvar,
}

impl StopHandle {
    /// Create a handle and token for one capture. A request made before parsing is remembered.
    pub fn pair() -> io::Result<(Self, StopToken)> {
        #[cfg(target_os = "linux")]
        let state = {
            let (sender, receiver) = UnixStream::pair()?;
            State { requested: AtomicBool::new(false), sender: Mutex::new(Some(sender)), receiver }
        };
        #[cfg(not(target_os = "linux"))]
        let state = State { requested: Mutex::new(false), changed: Condvar::new() };
        let state = Arc::new(state);
        Ok((Self(state.clone()), StopToken(state)))
    }

    /// Signal shutdown without waiting for it to finish. Safe to call repeatedly.
    /// Call from a normal thread or callback, not directly from a POSIX signal handler.
    pub fn request_stop(&self) {
        #[cfg(target_os = "linux")]
        {
            self.0.requested.store(true, Ordering::Release);
            if let Some(sender) = self.0.sender.lock().unwrap().take() {
                // Closing alone does not wake poll if a forked child still has a copy.
                if let Err(err) = sender.shutdown(std::net::Shutdown::Write) {
                    tracing::error!("shutting down capture stop socket failed: {}", err);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            *self.0.requested.lock().unwrap() = true;
            self.0.changed.notify_all();
        }
    }
}

impl StopToken {
    pub(crate) fn check_before_start(&self) -> Result<(), ParseCancelledBeforeStart> {
        if self.requested() { Err(ParseCancelledBeforeStart) } else { Ok(()) }
    }

    #[cfg(not(target_os = "linux"))]
    fn requested(&self) -> bool { *self.0.requested.lock().unwrap() }

    #[cfg(target_os = "linux")]
    pub(crate) fn requested(&self) -> bool { self.0.requested.load(Ordering::Acquire) }

    #[cfg(target_os = "linux")]
    pub(crate) fn poll_fd(&self) -> BorrowedFd<'_> { self.0.receiver.as_fd() }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn wait(&self) {
        drop(self.0.changed.wait_while(self.0.requested.lock().unwrap(), |stop| !*stop).unwrap());
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn handle(&self) -> StopHandle { StopHandle(self.0.clone()) }
}

pub(crate) enum CaptureStop {
    Predicate(Box<dyn Fn() -> bool + Send>),
    Token(StopToken),
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn stop_wakes_receiver_with_an_inherited_sender() {
        let (handle, token) = StopHandle::pair().unwrap();
        // dup holds the same open file description as a descriptor inherited across fork.
        let _inherited = handle.0.sender.lock().unwrap().as_ref().unwrap().try_clone().unwrap();
        let mut receiver = UnixStream::from(token.poll_fd().try_clone_to_owned().unwrap());
        receiver.set_nonblocking(true).unwrap();
        handle.request_stop();
        assert_eq!(receiver.read(&mut [0]).unwrap(), 0);
    }
}
