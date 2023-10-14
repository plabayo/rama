#[cfg(feature = "tokio")]
mod listener_tokio;
#[cfg(feature = "tokio")]
pub use listener_tokio::*;

// TODO: organise this better:
// - features should be aditative, so what if we also would support and use smol at the same time?
// - add compatible smol support
