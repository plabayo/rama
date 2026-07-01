//! High level pertaining to the HTTP message protocol.
//!
//! For low-level proto details you can refer to the `proto` module
//! in the `rama-http-core` crate.

use std::{ops::Deref, sync::Arc};

use rama_core::extensions::Extension;

use crate::HeaderMap;

pub mod h1;
pub mod h2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Extension)]
#[extension(tags(http))]
/// Byte length of the raw bytes of the request/response headers (excl. trailers).
pub struct HeaderByteLength(pub usize);

#[derive(Debug, Clone, Extension)]
#[extension(tags(http))]
/// Read-only copy of the parent request headers.
///
/// This extension can be made available in [`RequestHeaders`].
pub struct RequestHeaders(Arc<HeaderMap>);

impl From<HeaderMap> for RequestHeaders {
    fn from(value: HeaderMap) -> Self {
        Self(Arc::new(value))
    }
}

impl Deref for RequestHeaders {
    type Target = HeaderMap;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
