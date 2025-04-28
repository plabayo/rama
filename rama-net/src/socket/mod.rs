pub use ::socket2 as core;

mod interface;
#[doc(inline)]
pub use interface::Interface;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
#[doc(inline)]
pub use interface::DeviceName;

pub mod opts;
#[doc(inline)]
pub use opts::SocketOptions;
