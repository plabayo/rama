pub use socket2 as core;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
mod device_name;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
)]
#[doc(inline)]
pub use device_name::DeviceName;

mod interfaces;
#[doc(inline)]
pub use interfaces::{
    HardwareAddress, Interface, InterfaceAddress, InterfaceFlags, interfaces, local_addresses,
    route_source_address,
};

pub mod opts;
#[doc(inline)]
pub use opts::SocketOptions;

mod svc;
#[doc(inline)]
pub use svc::SocketService;

#[cfg(target_os = "linux")]
#[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
pub mod linux;

#[cfg(target_os = "windows")]
#[cfg_attr(docsrs, doc(cfg(target_os = "windows")))]
pub mod windows;
