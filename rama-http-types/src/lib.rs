//! rama http types and minimal utilities
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![warn(
    clippy::all,
    clippy::todo,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::mem_forget,
    clippy::unused_self,
    clippy::filter_map_next,
    clippy::needless_continue,
    clippy::needless_borrow,
    clippy::match_wildcard_for_single_variants,
    clippy::if_let_mutex,
    clippy::mismatched_target_os,
    clippy::await_holding_lock,
    clippy::match_on_vec_items,
    clippy::imprecise_flops,
    clippy::suboptimal_flops,
    clippy::lossy_float_literal,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::fn_params_excessive_bools,
    clippy::exit,
    clippy::inefficient_to_string,
    clippy::linkedlist,
    clippy::macro_use_imports,
    clippy::option_option,
    clippy::verbose_file_reads,
    clippy::unnested_or_patterns,
    clippy::str_to_string,
    rust_2018_idioms,
    future_incompatible,
    nonstandard_style,
    missing_debug_implementations,
    missing_docs
)]
#![deny(unreachable_pub)]
#![allow(elided_lifetimes_in_paths, clippy::type_complexity)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

pub(crate) mod body;
#[doc(inline)]
pub use body::{Body, BodyDataStream};

mod body_limit;
#[doc(inline)]
pub use body_limit::BodyLimit;

mod body_ext;
#[doc(inline)]
pub use body_ext::BodyExtractExt;

/// Type alias for [`http::Request`] whose body type
/// defaults to [`Body`], the most common body type used with rama.
pub type Request<T = Body> = http::Request<T>;

pub mod response;
pub use response::{IntoResponse, Response};

pub mod headers;

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

pub mod header {
    //! HTTP header types

    pub use crate::dep::http::header::*;

    macro_rules! static_header {
        ($($name_bytes:literal),+ $(,)?) => {
            $(
                paste::paste! {
                    #[doc = concat!("header name constant for `", $name_bytes, "`.")]
                    pub static [<$name_bytes:snake:upper>]: super::HeaderName = super::HeaderName::from_static($name_bytes);
                }
            )+
        };
    }

    // non-std conventional
    static_header!["x-forwarded-host", "x-forwarded-for", "x-forwarded-proto",];

    // standard
    static_header!["keep-alive", "proxy-connection", "via",];

    // non-std client ip forward headers
    static_header![
        "cf-connecting-ip",
        "true-client-ip",
        "client-ip",
        "x-client-ip",
        "x-real-ip",
    ];

    /// Static Header Value that is can be used as `User-Agent` or `Server` header.
    pub static RAMA_ID_HEADER_VALUE: HeaderValue = HeaderValue::from_static(
        const_format::formatcp!("{}/{}", super::NAME, super::VERSION,),
    );
}

pub use self::dep::http::header::{HeaderMap, HeaderName, HeaderValue};
pub use self::dep::http::method::Method;
pub use self::dep::http::status::StatusCode;
pub use self::dep::http::uri::{Scheme, Uri};
pub use self::dep::http::version::Version;

/// The name of the crate.
const NAME: &str = "rama";

/// The version of the crate.
const VERSION: &str = env!("CARGO_PKG_VERSION");
