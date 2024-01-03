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

pub mod layer;

pub mod dep {
    //! Dependencies for rama http modules.
    //!
    //! Exported for your convenience.

    pub mod http {
        //! Re-export of the [`http`] crate.
        //!
        //! A general purpose library of common HTTP types.
        //!
        //! [`http`]: https://docs.rs/http

        pub use http::*;
    }

    pub mod http_body {
        //! Re-export of the [`http-body`] crate.
        //!
        //! Asynchronous HTTP request or response body.
        //!
        //! [`http-body`]: https://docs.rs/http-body

        pub use http_body::*;
    }
}

pub use self::dep::http::header::HeaderMap;
pub use self::dep::http::header::HeaderName;
pub use self::dep::http::header::HeaderValue;
pub use self::dep::http::method::Method;
pub use self::dep::http::status::StatusCode;
pub use self::dep::http::uri::Uri;
pub use self::dep::http::version::Version;
