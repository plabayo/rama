//! http net support added as part of rama's net support
//!
//! See `rama-http` and `rama-http-backend` for most
//! http support. In this module lives only the stuff
//! directly connected to `rama-net` types.

mod request_context;
#[doc(inline)]
pub use request_context::{RequestContext, try_request_ctx_from_http_parts};

pub mod server;
