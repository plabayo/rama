//! service utilities for (http) clients

pub mod blocking;

pub mod ext;
#[doc(inline)]
pub use ext::{BlockingRequestBuilder, HttpClientExt, IntoUrl, RequestBuilder};

#[cfg(feature = "multipart")]
pub mod multipart;
