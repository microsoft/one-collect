// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::ffi::CString;
use std::path::Path;
use tracing::{warn, debug};

#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::fd::{RawFd, FromRawFd, IntoRawFd};

/* Required for cross-platform docs */
#[cfg(not(target_os = "linux"))]
struct RawFd {}

/// `DupFd` is a wrapper around a raw file descriptor.
///
/// This struct provides a safe interface for duplicating file descriptors,
/// which can be useful in multithreaded contexts or when dealing with processes.
#[derive(Clone)]
pub struct DupFd {
    fd: RawFd,
}

impl DupFd {
    /// Creates a new `DupFd` from a `File`.
    ///
    /// # Parameters
    /// * `file`: The `File` to be wrapped.
    ///
    /// # Returns
    /// * `Self`: A new `DupFd` instance.
    pub fn new(file: File) -> Self {
        Self {
            fd: file.into_raw_fd()
        }
    }

    /// Opens a new `File` from the file descriptor.
    ///
    /// This method duplicates the file descriptor, ensuring that the new `File`
    /// has its own separate file descriptor that can be used independently of others.
    ///
    /// # Returns
    /// * `Option<File>`: The new `File` that was opened or None if call to dup failed.
    pub fn open(&self) -> Option<File> {
        unsafe {
            let cloned_fd = libc::dup(self.fd);
            if cloned_fd != -1 {
                return Some(File::from_raw_fd(cloned_fd));
            }

            None
        }
    }
}

/// `OpenAt` provides a safe interface for opening and manipulating files relative to a directory file descriptor.
///
#[derive(Clone)]
pub struct OpenAt {
    fd: RawFd,
}

impl OpenAt {
    /// Creates a new `OpenAt` from a `File`.
    ///
    /// # Parameters
    /// * `dir`: The directory `File` object that will be used as the base for relative operations.
    ///
    /// # Returns
    /// * `Self`: A new `OpenAt` instance.
    pub fn new(dir: File) -> Self {
        Self {
            fd: dir.into_raw_fd()
        }
    }

    /// Opens a file relative to the directory file descriptor.
    ///
    /// # Parameters
    /// * `path`: The path to the file to open, relative to the directory file descriptor.
    ///
    /// # Returns
    /// * `anyhow::Result<File>`: The `File` that was opened, or an error if the operation failed.
    pub fn open_file(
        &self,
        path: &Path) -> anyhow::Result<File> {
        let path_cstring = CString::new(path.as_os_str().as_bytes())?;
        let mut path_bytes = path_cstring.as_bytes_with_nul();

        if path_bytes[0] == b'/' {
            path_bytes = &path_bytes[1..]
        }

        unsafe {
            let fd = libc::openat(
                self.fd,
                path_bytes.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC);

            if fd == -1 {
                warn!("Failed to open file with openat: path={:?}", path);
                return Err(std::io::Error::last_os_error().into());
            }

            debug!("File opened via openat: path={:?}, fd={}", path, fd);
            Ok(File::from_raw_fd(fd))
        }
    }

    /// Removes a file or directory relative to the directory file descriptor.
    ///
    /// # Parameters
    /// * `path`: The path to the file or directory to remove, relative to the directory file descriptor.
    ///
    /// # Returns
    /// * `anyhow::Result<()>`: `Ok(())` if the operation was successful, or an error if it failed.
    pub fn remove(
        &self,
        path: &Path) -> anyhow::Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let mut path = path.as_bytes_with_nul();

        if path[0] == b'/' {
            path = &path[1..]
        }

        unsafe {
            let result = libc::unlinkat(
                self.fd,
                path.as_ptr() as *const libc::c_char,
                0);

            /* ENOENT (Not Found) is considered success */
            if result != 0 && result != libc::ENOENT {
                return Err(std::io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    /// Finds file or directory paths with a specific prefix, relative to the directory file descriptor.
    ///
    /// # Parameters
    /// * `path`: The path to start the search from, relative to the directory file descriptor.
    /// * `prefix`: The prefix to match paths against.
    ///
    /// # Returns
    /// * `Option<Vec<String>>`: A `Vec` of matching paths if any were found, or `None` if no matches were found.
    pub fn find(
        &self,
        path: &Path,
        prefix: &str) -> Option<Vec<String>> {
        let file = self.open_file(path);

        if file.is_err() {
            debug!("Failed to open directory for find operation: path={:?}, prefix={}", path, prefix);
            return None;
        }

        let file = file.unwrap();
        let fd = file.into_raw_fd();

        let mut paths = Vec::new();

        unsafe {
            let dir = libc::fdopendir(fd);

            if dir.is_null() {
                debug!("Failed to open directory stream: path={:?}", path);
                return None;
            }

            loop {
                let entry = libc::readdir(dir);

                if entry.is_null() {
                    break;
                }

                #[cfg(target_arch = "x86_64")]
                let name = &(*entry).d_name as *const i8;
                #[cfg(target_arch = "aarch64")]
                let name = &(*entry).d_name as *const u8;

                let len = libc::strlen(name);

                let name = std::str::from_utf8_unchecked(
                    std::slice::from_raw_parts(
                        name as *const u8,
                        len));

                if name.starts_with(prefix) {
                    paths.push(name.to_string());
                }
            }

            libc::closedir(dir);
        }

        if paths.is_empty() {
            debug!("No matching paths found: path={:?}, prefix={}", path, prefix);
            return None;
        }

        debug!("Found matching paths: path={:?}, count={}, prefix={}", path, paths.len(), prefix);
        Some(paths)
    }
}

impl Drop for OpenAt {
    /// Closes the directory file descriptor when the `OpenAt` struct is dropped.
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
