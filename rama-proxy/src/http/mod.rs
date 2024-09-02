//! Http Proxy Support
//!
//! As defined in <https://www.ietf.org/rfc/rfc2068.txt>.
//!
//! Client side lives in the [`client`] module.
//!
//! There is no explicit server side support for HTTP Proxies,
//! as this is achieved by using the [`HttpServer`] in combination
//! with the upgrade mechanism to establish a tunnel for https
//! or forwarding the request to the target server for http.
//!
//! [`HttpServer`]: crate::http::server::HttpServer

pub mod client;
