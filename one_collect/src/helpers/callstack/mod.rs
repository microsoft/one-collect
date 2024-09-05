#[cfg_attr(target_os = "linux", path = "os/linux.rs")]
#[cfg_attr(target_os = "windows", path = "os/windows.rs")]
pub mod os;

pub type CallstackReader = os::CallstackReader;
pub type CallstackHelper = os::CallstackHelper;

pub trait CallstackHelp {
    fn with_callstack_help(
        self,
        helper: &CallstackHelper) -> Self;
}
