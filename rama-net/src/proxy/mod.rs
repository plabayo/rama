//! Proxy utilities and types.

mod request;
#[doc(inline)]
pub use request::ProxyRequest;

mod forward;
#[doc(inline)]
pub use forward::StreamForwardService;
