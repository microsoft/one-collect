// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/* Windows */
#[cfg(any(doc, target_os = "windows"))]
pub mod windows;

#[cfg(target_os = "windows")]
pub use windows::*;

/* Linux */
#[cfg(any(doc, target_os = "linux"))]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;
