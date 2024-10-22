use super::*;

use crate::Writable;
use crate::helpers::exporting::UniversalExporter;

pub struct UniversalDotNetHelper {
    os: Writable<Option<os::DotNetHelper>>,
}

impl Default for UniversalDotNetHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl UniversalDotNetHelper {
    pub fn new() -> Self {
        let helper = os::DotNetHelper::new();

        Self {
            os: Writable::new(Some(helper)),
        }
    }

    pub fn with_dynamic_symbols(self) -> Self {
        let os = self.os.borrow_mut().take();

        match os {
            Some(helper) => {
                /* OS specific implementation */
                #[cfg(target_os = "linux")]
                let helper = helper.with_perf_maps();

                /* Universally replace */
                self.os.borrow_mut().replace(helper);
            },
            None => { /* Nothing */ }
        }

        self
    }

    pub fn cleanup_dynamic_symbols(&mut self) {
        if let Some(helper) = self.os.borrow_mut().as_mut() {
            /* OS specific implementation */
            #[cfg(target_os = "linux")]
            helper.remove_perf_maps();
        }
    }

    pub fn disable_dynamic_symbols(&mut self) {
        if let Some(helper) = self.os.borrow_mut().as_mut() {
            /* OS specific implementation */
            #[cfg(target_os = "linux")]
            helper.disable_perf_maps();
        }
    }
}

impl UniversalDotNetHelp for UniversalExporter {
    fn with_dotnet_help(
        self,
        helper: &UniversalDotNetHelper) -> Self {
        let os = helper.os.clone();

        self.with_build_hook(move |mut builder, _context| {
            let mut helper_option = os.borrow_mut();

            /* Hook OS specific details universally */
            if let Some(helper) = helper_option.as_mut() {
                builder = builder.with_dotnet_help(helper);
            }

            Ok(builder)
        })
    }
}
