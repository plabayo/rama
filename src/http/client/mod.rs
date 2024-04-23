//! Rama HTTP client module,
//! which provides the [`HttpClient`] type to serve HTTP requests.

mod service;
#[doc(inline)]
pub use service::{HttpClient, HttpClientError};

mod ext;
#[doc(inline)]
pub use ext::{HttpClientExt, IntoUrl, RequestBuilder};
