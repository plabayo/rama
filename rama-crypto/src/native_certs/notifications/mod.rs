#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(super) use macos::StoreNotifications;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(super) use windows::StoreNotifications;
