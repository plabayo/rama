pub use ::socket2 as core;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
mod device_name;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
)]
#[doc(inline)]
pub use device_name::DeviceName;

pub mod opts;
#[doc(inline)]
pub use opts::SocketOptions;

mod svc;
#[doc(inline)]
pub use svc::SocketService;
