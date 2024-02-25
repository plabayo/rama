//! Http [`Layer`]s provided by Rama.
//!
//! A [`Layer`], as defined in [`crate::service`],
//! is a middleware that can modify the request and/or response of a [`Service`]s.
//! It is also capable of branching between two or more [`Service`]s.
//!
//! Examples:
//! - [`auth`]: A layer that can be used to authenticate requests, branching
//!   in case the request is not authenticated (read: rejected).
//! - [`cors`]: A layer that can be used to add CORS headers to the response.
//! - [`dns`]: A layer that can be used to resolve the hostname of the request.
//!
//! Most layers are implemented as a [`Service`], and then wrapped in a [`Layer`].
//! This is done to allow the layer to be used as a service, and to allow it to be
//! composed with other layers.
//!
//! [`Layer`]: crate::service::Layer
//! [`Service`]: crate::service::Service

pub mod auth;
pub mod catch_panic;
pub mod classify;
pub mod cors;
pub mod dns;
pub mod header_config;
pub mod hijack;
pub mod map_request_body;
pub mod map_response_body;
pub mod normalize_path;
pub mod propagate_headers;
pub mod request_id;
pub mod sensitive_headers;
pub mod set_header;
pub mod set_status;
pub mod timeout;
pub mod trace;
pub mod validate_request;

pub(crate) mod util;

#[cfg(feature = "compression")]
pub mod compression;
#[cfg(feature = "compression")]
pub mod decompression;
