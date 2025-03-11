//! Middleware to adapt the server compression
//! to something the client supports, if anything at all.

mod layer;
mod service;

pub use self::{layer::CompressAdaptLayer, service::CompressAdaptService};
