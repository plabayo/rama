//! Serve non-network request URIs from a client stack.
//!
//! `file:` and `data:` uris carry their content locally, so these layers
//! answer them and pass every other scheme to the inner service — one
//! client then serves local and remote uris alike.
//!
//! Place them *outside* any
//! [`FollowRedirectLayer`][crate::layer::follow_redirect::FollowRedirectLayer]:
//! redirects are followed by the inner service, so a remote response can
//! never redirect into the local filesystem.

pub mod data;
pub mod file;

#[doc(inline)]
pub use data::{DataUriLayer, DataUriService};
#[doc(inline)]
pub use file::{FileUriLayer, FileUriService};
