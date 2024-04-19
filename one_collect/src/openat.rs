use std::fs::File;
use std::ffi::CString;
use std::path::Path;
use std::os::unix::ffi::OsStrExt;
use std::os::fd::{RawFd, FromRawFd, IntoRawFd};

#[derive(Clone)]
pub struct OpenAt {
    fd: RawFd,
}

impl OpenAt {
    pub fn new(dir: File) -> Self {
        Self {
            fd: dir.into_raw_fd()
        }
    }

    pub fn open_file(
        &self,
        path: &Path) -> anyhow::Result<File> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let mut path = path.as_bytes_with_nul();

        if path[0] == b'/' {
            path = &path[1..]
        }

        unsafe {
            let fd = libc::openat(
                self.fd,
                path.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC);

            if fd == -1 {
                return Err(std::io::Error::last_os_error().into());
            }

            Ok(File::from_raw_fd(fd))
        }
    }
}

impl Drop for OpenAt {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
