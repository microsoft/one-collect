use super::*;

use crate::Writable;
use crate::helpers::exporting::UniversalExporter;

pub struct UniversalDotNetHelper {
    helper: DotNetHelper,
}

impl Default for UniversalDotNetHelper {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) trait UniversalDotNetHelperOSHooks {
    fn os_with_dynamic_symbols(self) -> Self;

    fn os_cleanup_dynamic_symbols(&mut self);
}

impl UniversalDotNetHelper {
    pub fn new() -> Self {
        Self {
            helper: DotNetHelper::new(),
        }
    }

    pub fn with_dynamic_symbols(mut self) -> Self {
        self.helper = self.helper.os_with_dynamic_symbols();

        self
    }
}

impl UniversalDotNetHelp for UniversalExporter {
    fn with_dotnet_help(
        self,
        universal: UniversalDotNetHelper) -> Self {
        let helper = Writable::new(universal.helper);

        let build_helper = helper.clone();
        let export_helper = helper.clone();
        let drop_helper = helper.clone();

        self.with_build_hook(move |mut builder, _context| {
            let mut helper = build_helper.borrow_mut();

            /* Hook SessionBuilder */
            builder = builder.with_dotnet_help(&mut helper);

            Ok(builder)
        }).with_export_hook(move |exporter| {
            let mut helper = export_helper.borrow_mut();
            let sym_exporter = exporter.clone();

            /* Hook JIT symbols to exporter */
            helper.add_jit_symbol_hook(move |symbol| {
                let _ = sym_exporter.borrow_mut().add_dynamic_symbol(symbol);
            });

            Ok(())
        }).with_export_drop_hook(move || {
            /* Hook OS specific cleanup on ExportMachine drop */
            drop_helper.borrow_mut().os_cleanup_dynamic_symbols();
        })
    }
}
