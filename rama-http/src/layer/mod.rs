//! Http [`Layer`]s provided by Rama.
//!
//! A [`Layer`], as defined in [`rama_core::Service`],
//! is a middleware that can modify the request and/or response of a [`Service`]s.
//! It is also capable of branching between two or more [`Service`]s.
//!
//! Examples:
//! - [`auth`]: A layer that can be used to authenticate requests, branching
//!   in case the request is not authenticated (read: rejected).
//! - [`cors`]: A layer that can be used to add CORS headers to the response.
//!
//! Most layers are implemented as a [`Service`], and then wrapped in a [`Layer`].
//! This is done to allow the layer to be used as a service, and to allow it to be
//! composed with other layers.
//!
//! [`Layer`]: rama_core::Layer
//! [`Service`]: rama_core::Service

pub mod auth;
pub mod body_limit;
pub mod catch_panic;
pub mod classify;
pub mod collect_body;
pub mod cors;
pub mod dns;
pub mod error_handling;
pub mod follow_redirect;
pub mod forwarded;
pub mod header_config;
pub mod header_from_str_config;
pub mod header_option_value;
pub mod map_request_body;
pub mod map_response_body;
pub mod normalize_path;
pub mod propagate_headers;
pub mod proxy_auth;
pub mod remove_header;
pub mod request_id;
pub mod required_header;
pub mod retry;
pub mod sensitive_headers;
pub mod set_header;
pub mod set_status;
pub mod timeout;
pub mod trace;
pub mod traffic_writer;
pub mod ua;
pub mod validate_request;

#[cfg(feature = "opentelemetry")]
pub mod opentelemetry;

pub(crate) mod util;

#[cfg(feature = "compression")]
pub mod compress_adapter;
#[cfg(feature = "compression")]
pub mod compression;
#[cfg(feature = "compression")]
pub mod decompression;
