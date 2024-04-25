//! Rama HTTP client module,
//! which provides the [`HttpClient`] type to serve HTTP requests.

mod error;
#[doc(inline)]
pub use error::HttpClientError;

mod service;
#[doc(inline)]
pub use service::HttpClient;

mod ext;
#[doc(inline)]
pub use ext::{HttpClientExt, IntoUrl, RequestBuilder};
