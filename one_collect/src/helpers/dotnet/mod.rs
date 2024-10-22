#[cfg_attr(target_os = "linux", path = "os/linux.rs")]
#[cfg_attr(target_os = "windows", path = "os/windows.rs")]
pub mod os;

pub type DotNetHelper = os::DotNetHelper;

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
        helper: &UniversalDotNetHelper) -> Self;
}
