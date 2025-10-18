//! Middleware to rewrite the [`Uri`] of a request.
//!
//! [`Uri`]: crate::Uri

mod layer;
mod service;

pub use self::{layer::RewriteUriLayer, service::RewriteUriService};
