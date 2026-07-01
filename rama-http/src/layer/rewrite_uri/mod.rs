//! Middleware to rewrite the [`Uri`] of a request.
//!
//! [`Uri`]: rama_net::uri::Uri

mod layer;
mod service;

pub use self::{layer::RewriteUriLayer, service::RewriteUriService};
