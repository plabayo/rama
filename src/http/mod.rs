//! Rama http modules.

pub(crate) mod body;
pub use body::{Body, BodyDataStream};

/// Type alias for [`http::Request`] whose body type
/// defaults to [`Body`], the most common body type used with rama.
pub type Request<T = Body> = http::Request<T>;

/// Type alias for [`http::Response`] whose body type
/// defaults to [`Body`], the most common body type used with rama.
pub type Response<T = Body> = http::Response<T>;

pub mod headers;
pub mod utils;

pub use http::header::HeaderMap;
pub use http::header::HeaderName;
pub use http::header::HeaderValue;
pub use http::method::Method;
pub use http::status::StatusCode;
pub use http::uri::Uri;
pub use http::version::Version;

pub mod layer;

pub mod dep {
    //! Dependencies for rama http modules.

    pub use http;
    pub use http_body;
}
