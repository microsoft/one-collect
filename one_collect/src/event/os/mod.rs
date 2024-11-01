/* Windows */
#[cfg(any(doc, target_os = "windows"))]
pub mod windows;

#[cfg(target_os = "windows")]
pub type EventExtension = windows::EventExtension;

/* Linux */
#[cfg(any(doc, target_os = "linux"))]
pub mod linux;

#[cfg(target_os = "linux")]
pub type EventExtension = linux::EventExtension;
