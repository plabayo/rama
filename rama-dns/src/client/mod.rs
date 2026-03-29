pub mod resolver;

#[cfg(feature = "hickory")]
pub mod hickory;
#[cfg(feature = "hickory")]
#[doc(inline)]
pub use self::hickory::HickoryDnsResolver;

mod tokio;
#[doc(inline)]
pub use self::tokio::{TokioDnsResolver, TokioDnsTxtUnsupportedError};

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(target_vendor = "apple")]
#[doc(inline)]
pub use self::apple::AppleDnsResolver;
#[cfg(target_vendor = "apple")]
pub type NativeDnsResolver = AppleDnsResolver;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
#[doc(inline)]
pub use self::windows::WindowsDnsResolver;
#[cfg(target_os = "windows")]
pub type NativeDnsResolver = WindowsDnsResolver;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
#[doc(inline)]
pub use self::linux::LinuxDnsResolver;
#[cfg(target_os = "linux")]
pub type NativeDnsResolver = LinuxDnsResolver;

#[cfg(not(any(target_vendor = "apple", target_os = "windows", target_os = "linux")))]
pub type NativeDnsResolver = TokioDnsResolver;

mod deny_all;
#[doc(inline)]
pub use self::deny_all::{DenyAllDnsResolver, DnsDeniedError};

mod empty;
#[doc(inline)]
pub use self::empty::EmptyDnsResolver;

mod global;
#[doc(inline)]
pub use global::{GlobalDnsResolver, init_global_dns_resolver, try_init_global_dns_resolver};

mod chain;
mod tuple;
mod variant;
