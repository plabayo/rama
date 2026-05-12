//! FastCGI support for Rama.
//!
//! # FastCGI
//!
//! FastCGI is a binary protocol for interfacing interactive programs with a web
//! server. It is a successor to CGI that avoids the overhead of spawning a new
//! process for every request by keeping the application process alive and
//! reusing it across many requests over a persistent connection.
//!
//! The full specification is embedded in this crate at
//! `specifications/fastcgi_spec.txt`.
//!
//! ## Server
//!
//! Use [`FastCgiServer`] to accept FastCGI connections (typically from nginx or
//! Apache acting as the web server front-end). It handles the protocol framing and
//! dispatches each assembled request to your inner [`rama_core::Service`].
//!
//! The inner service receives a [`FastCgiRequest`] containing the CGI environment
//! variables (params) and the request body (stdin), and must return a
//! [`FastCgiResponse`] whose `stdout` bytes are sent back as the CGI response.
//!
//! ## Client
//!
//! Use [`FastCgiClient`] to connect to a FastCGI backend application (e.g. PHP-FPM).
//! It sends a [`FastCgiClientRequest`] (params + stdin) and returns a
//! [`FastCgiClientResponse`] containing the raw stdout bytes from the application.
//!
//! This is the piece a reverse proxy uses: it accepts HTTP, constructs CGI environment
//! variables, and calls the FastCGI backend via the client.
//!
//! ## Protocol building blocks
//!
//! The [`proto`] module exposes all protocol types and codec primitives if you need
//! lower-level control:
//!
//! - [`proto::RecordHeader`] — the 8-byte header shared by every record.
//! - [`proto::BeginRequestBody`] / [`proto::EndRequestBody`] — fixed-length record bodies.
//! - [`proto::params`] — FastCGI name-value pair encoding and decoding.
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
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]

pub mod proto;

pub mod body;
#[doc(inline)]
pub use body::FastCgiBody;

pub mod server;
#[doc(inline)]
pub use server::{FastCgiRequest, FastCgiResponse, FastCgiServer, ServerOptions};

pub mod client;
#[cfg(feature = "transport")]
#[doc(inline)]
pub use client::FastCgiTcpConnector;
#[cfg(all(feature = "transport", target_family = "unix"))]
#[doc(inline)]
pub use client::FastCgiUnixConnector;
#[doc(inline)]
pub use client::{
    ClientError, ClientOptions, FastCgiClient, FastCgiClientRequest, FastCgiClientResponse,
};

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub mod http;
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
#[doc(inline)]
pub use http::{FastCgiHttpClient, FastCgiHttpClientConnector, FastCgiHttpService};
