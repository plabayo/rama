//! Proxy (service) utilities

// TODO: in future we probably want to get rid of all these http feature gates in rama-tcp and rama-net...
//
// this is a clear sign of wrong boundaries that we need to fix soon, probably
// still before the actual 0.3 release

#[cfg(feature = "http")]
mod io_to_bridge_io;
#[cfg(feature = "http")]
pub use self::io_to_bridge_io::{IoToProxyBridgeIo, IoToProxyBridgeIoLayer};
