//! High level pertaining to the HTTP message protocol.
//!
//! For low-level proto details you can refer to the `proto` module
//! in the `rama-http-core` crate.

use std::{ops::Deref, sync::Arc};

use rama_core::context::Extensions;

pub mod h1;
pub mod h2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Byte length of the raw bytes of the request/response headers (excl. trailers).
pub struct HeaderByteLength(pub usize);

#[derive(Debug, Clone)]
/// Read-only copy of the parent request headers.
///
/// This extension can be made available in [`RequestHeaders`].
pub struct RequestHeaders(Arc<h1::Http1HeaderMap>);

impl From<h1::Http1HeaderMap> for RequestHeaders {
    fn from(value: h1::Http1HeaderMap) -> Self {
        Self(Arc::new(value))
    }
}

impl Deref for RequestHeaders {
    type Target = h1::Http1HeaderMap;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone)]
/// Read-only copy of the parent request extensions.
///
/// This extension can be made available as part of a response.
pub struct RequestExtensions(Arc<Extensions>);

impl From<Extensions> for RequestExtensions {
    fn from(value: Extensions) -> Self {
        Self(Arc::new(value))
    }
}

// TODO: once we have a more advanced req/resp extension system,
// as replacement of current rama Context, this could also perhaps
// act as some kind of automated parent extensions that are fallen back to if
// not available in response extensions?

impl Deref for RequestExtensions {
    type Target = Extensions;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
