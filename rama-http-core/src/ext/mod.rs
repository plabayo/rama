//! Extensions for HTTP messages in Rama.
//!
//! This module provides types and utilities that extend the capabilities of HTTP requests and responses
//! in Rama. Extensions are additional pieces of information or features that can be attached to HTTP
//! messages via the [`rama_core::extensions::Extensions`] map, which is
//! accessible through the methods provided by the
//! [`rama_core::extensions::ExtensionsRef`] and [`rama_core::extensions::ExtensionsMut`]
//! traits implemented for [`rama_http_types::Request`] and [`rama_http_types::Response`].
//!
//! # What are extensions?
//!
//! Extensions allow Rama to associate extra metadata or behaviors with HTTP messages, beyond the standard
//! headers and body. These can be used by advanced users and library authors to access protocol-specific
//! features, track original header casing, handle informational responses, and more.
//!
//! See for more information the rama book:
//! <https://ramaproxy.org/book/intro/state.html#extensions>
//!
//! # How to access extensions
//!
//! Extensions are stored in the `Extensions` map of a request or response. You can access them using:
//!
//! ```rust
//! # use rama_core::extensions::ExtensionsRef;
//! # let response = rama_http_types::Response::new(());
//! if let Some(ext) = response.extensions().get::<rama_http_core::ext::ReasonPhrase>() {
//!     // use the extension
//! }
//! ```
//!
//! # Extension Groups
//!
//! The extensions in this module can be grouped as follows:
//!
//! - **HTTP/1 Reason Phrase**: [`ReasonPhrase`] — Access non-canonical reason phrases in HTTP/1 responses.
//! - **Informational Responses**: [`on_informational`] — Register callbacks for 1xx HTTP/1 responses on the client.
//!
//! Some other crates such as [`rama_http_types`] also provide extension types used by this crate:
//! - **Header Case Tracking**: Internal types for tracking the original casing and order of headers as received.
//! - **HTTP/2 Protocol Extensions**: Access the `:protocol` pseudo-header for Extended CONNECT in HTTP/2.
//!
//! See the documentation on each item for details about its usage and requirements.

mod h1_reason_phrase;
pub use h1_reason_phrase::ReasonPhrase;

mod informational;
pub(crate) use informational::OnInformational;
pub use informational::on_informational;
// pub(crate) use informational::{on_informational_raw, OnInformationalCallback}; // ffi feature in hyperium/hyper
