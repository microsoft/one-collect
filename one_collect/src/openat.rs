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

    pub fn find(
        &self,
        path: &Path,
        prefix: &str) -> Option<Vec<String>> {
        let file = self.open_file(path);

        if file.is_err() {
            return None;
        }

        let file = file.unwrap();
        let fd = file.into_raw_fd();

        let mut paths = Vec::new();

        unsafe {
            let dir = libc::fdopendir(fd);

            if dir.is_null() {
                return None;
            }

            loop {
                let entry = libc::readdir(dir);

                if entry.is_null() {
                    break;
                }

                let name = &(*entry).d_name as *const i8;
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
            return None;
        }

        Some(paths)
    }
}

impl Drop for OpenAt {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
