// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub mod os;
use os::OSDotNetHelper;

#[cfg(feature = "scripting")]
pub mod scripting;

#[cfg(feature = "scripting")]
pub use scripting::DotNetScripting;

use crate::Writable;
use crate::helpers::exporting::DynamicSymbol;

/* Make it easy for callers to use public OS extensions */
#[cfg(target_os = "linux")]
pub use os::linux::DotNetHelperLinuxExt;

#[cfg(target_os = "windows")]
pub use os::windows::DotNetHelperWindowsExt;

pub struct DotNetHelper {
    pub(crate) os: OSDotNetHelper,
    jit_symbol_hooks: Writable<Vec<Box<dyn FnMut(&DynamicSymbol)>>>,
}

impl DotNetHelper {
    pub fn new() -> Self {
        Self {
            os: OSDotNetHelper::new(),
            jit_symbol_hooks: Writable::new(Vec::new()),
        }
    }

    fn add_jit_symbol_hook(
        &mut self,
        hook: impl FnMut(&DynamicSymbol) + 'static) {
        self.jit_symbol_hooks.borrow_mut().push(Box::new(hook));
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
