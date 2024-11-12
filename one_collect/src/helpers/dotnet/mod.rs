pub mod os;
use os::OSDotNetHelper;

/* Make it easy for callers to use public OS extensions */
#[cfg(target_os = "linux")]
pub use os::linux::DotNetHelperLinuxExt;

#[cfg(target_os = "windows")]
pub use os::windows::DotNetHelperWindowsExt;

pub struct DotNetHelper {
    pub(crate) os: OSDotNetHelper,
}

impl DotNetHelper {
    pub fn new() -> Self {
        Self {
            os: OSDotNetHelper::new(),
        }
    }
}

pub trait DotNetHelp {
    fn with_dotnet_help(
        self,
        helper: &mut DotNetHelper) -> Self;
}

pub mod universal;

pub type UniversalDotNetHelper = universal::UniversalDotNetHelper;

pub trait UniversalDotNetHelp {
    fn with_dotnet_help(
        self,
        universal: UniversalDotNetHelper) -> Self;
}
