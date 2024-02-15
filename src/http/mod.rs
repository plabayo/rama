//! Rama http modules.

pub(crate) mod body;
pub use body::{Body, BodyDataStream};

pub mod utils;

pub mod headers;

/// Type alias for [`http::Request`] whose body type
/// defaults to [`Body`], the most common body type used with rama.
pub type Request<T = Body> = http::Request<T>;

pub mod response;
pub use response::{IntoResponse, Response};

pub mod layer;
pub mod service;

pub mod server;

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

    pub mod http_body_util {
        //! Re-export of the [`http-body-util`] crate.
        //!
        //! Utilities for working with [`http-body`] types.
        //!
        //! [`http-body`]: https://docs.rs/http-body
        //! [`http-body-util`]: https://docs.rs/http-body-util

        pub use http_body_util::*;
    }

    pub mod mime {
        //! Re-export of the [`mime`] crate.
        //!
        //! Support MIME (Media Types) as strong types in Rust.
        //!
        //! [`mime`]: https://docs.rs/mime

        pub use mime::*;
    }

    pub mod mime_guess {
        //! Re-export of the [`mime_guess`] crate.
        //!
        //! Guessing of MIME types by file extension.
        //!
        //! [`mime_guess`]: https://docs.rs/mime_guess

        pub use mime_guess::*;
    }
}

pub use self::dep::http::header;
pub use self::dep::http::header::HeaderMap;
pub use self::dep::http::header::HeaderName;
pub use self::dep::http::header::HeaderValue;
pub use self::dep::http::method::Method;
pub use self::dep::http::status::StatusCode;
pub use self::dep::http::uri::Uri;
pub use self::dep::http::version::Version;
