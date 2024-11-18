use crate::helpers::dotnet::*;
use crate::helpers::dotnet::universal::UniversalDotNetHelperOSHooks;

use crate::etw::EtwSession;

pub(crate) struct OSDotNetHelper {
    /* Placeholder */
}

impl OSDotNetHelper {
    pub fn new() -> Self {
        Self {
            /* Placeholder */
        }
    }
}

pub trait DotNetHelperWindowsExt {
    /* Placeholder */
}

#[cfg(target_os = "windows")]
impl UniversalDotNetHelperOSHooks for DotNetHelper {
    fn os_with_dynamic_symbols(self) -> Self {
        /* Placeholder */

        self
    }

    fn os_cleanup_dynamic_symbols(&mut self) {
        /* Placeholder */
    }
}

impl DotNetHelp for EtwSession {
    fn with_dotnet_help(
        self,
        _helper: &mut DotNetHelper) -> Self {
        /* Placeholder */

        self
    }
}
