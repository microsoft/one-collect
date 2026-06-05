// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/* Windows */
#[cfg(any(doc, target_os = "windows"))]
pub(super) mod windows;

#[cfg(target_os = "windows")]
pub(super) use windows::*;

/* Linux */
#[cfg(any(doc, target_os = "linux"))]
pub(crate) mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::*;
