//! Middleware to redirect a request using dynamic [`Uri`] derived
//! from the input request or a static one.
//!
//! [`Uri`]: rama_net::uri::Uri

mod layer;
mod service;

pub use self::{layer::UriMatchRedirectLayer, service::UriMatchRedirectService};
