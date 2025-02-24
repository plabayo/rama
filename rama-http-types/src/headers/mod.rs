//! typed http headers
//!
//! rama has the opinion that headers should be strongly-typed,
//! because that’s why we’re using Rust in the first place. To set or get any header,
//! an object must implement the Header trait from this module.
//! Several common headers are already provided, such as Host, ContentType, UserAgent, and others.
//!
//! ## Why typed?
//!
//! Or, why not stringly-typed? Types give the following advantages:
//! - More difficult to typo, since typos in types should be caught by the compiler
//! - Parsing to a proper type by default
//!
//! ## Defining Custom Headers
//!
//! ### Implementing the [`Header`] trait
//!
//! Consider a Do Not Track header. It can be true or false,
//! but it represents that via the numerals 1 and 0.
//!
//! ```rust
//! use rama_http_types::{headers::Header, HeaderName, HeaderValue};
//!
//! struct Dnt(bool);
//!
//! impl Header for Dnt {
//!     fn name() -> &'static HeaderName {
//!          &http::header::DNT
//!     }
//!
//!     fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
//!     where
//!         I: Iterator<Item = &'i HeaderValue>,
//!     {
//!         let value = values
//!             .next()
//!             .ok_or_else(headers::Error::invalid)?;
//!
//!         if value == "0" {
//!             Ok(Dnt(false))
//!         } else if value == "1" {
//!             Ok(Dnt(true))
//!         } else {
//!             Err(headers::Error::invalid())
//!         }
//!     }
//!
//!     fn encode<E>(&self, values: &mut E)
//!     where
//!         E: Extend<HeaderValue>,
//!     {
//!         let s = if self.0 {
//!             "1"
//!         } else {
//!             "0"
//!         };
//!
//!         let value = HeaderValue::from_static(s);
//!
//!         values.extend(std::iter::once(value));
//!     }
//! }
//! ```

#[doc(inline)]
pub use headers::{Header, HeaderMapExt};

#[doc(inline)]
pub use headers::{
    AcceptRanges, AccessControlAllowCredentials, AccessControlAllowHeaders,
    AccessControlAllowMethods, AccessControlAllowOrigin, AccessControlExposeHeaders,
    AccessControlMaxAge, AccessControlRequestHeaders, AccessControlRequestMethod, Age, Allow,
    Authorization, CacheControl, Connection, ContentDisposition, ContentEncoding, ContentLength,
    ContentLocation, ContentRange, ContentType, Cookie, Date, ETag, Error, Expect, Expires, Host,
    IfMatch, IfModifiedSince, IfNoneMatch, IfRange, IfUnmodifiedSince, LastModified, Location,
    Origin, Pragma, ProxyAuthorization, Range, Referer, ReferrerPolicy, RetryAfter,
    SecWebsocketAccept, SecWebsocketKey, SecWebsocketVersion, Server, SetCookie,
    StrictTransportSecurity, Te, TransferEncoding, Upgrade, UserAgent, Vary,
};

pub mod authorization {
    //! Authorization header and types.

    #[doc(inline)]
    pub use headers::authorization::Credentials;
    #[doc(inline)]
    pub use headers::authorization::{Authorization, Basic, Bearer};
}

mod ext;
#[doc(inline)]
pub use ext::HeaderExt;

pub mod encoding;
pub mod specifier;

pub mod util;

mod common;
pub use common::Accept;

mod client_hints;
pub use client_hints::{
    ClientHint, all_client_hint_header_name_strings, all_client_hint_header_names,
};
