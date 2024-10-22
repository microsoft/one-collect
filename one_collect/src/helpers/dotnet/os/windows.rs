use super::*;

use crate::etw::EtwSession;

pub struct DotNetHelper {
    /* Placeholder */
}

impl DotNetHelper {
    pub fn new() -> Self {
        Self {
            /* Placeholder */
        }
    }
}

impl DotNetHelp for EtwSession {
    fn with_dotnet_help(
        self,
        helper: &mut DotNetHelper) -> Self {
        /* Placeholder */

        self
    }
}
