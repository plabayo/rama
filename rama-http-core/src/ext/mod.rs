//! HTTP extensions.

use rama_http_types::proto::h2::ext;
use std::fmt;

mod h1_reason_phrase;
pub use h1_reason_phrase::ReasonPhrase;

mod informational;
pub(crate) use informational::OnInformational;
pub use informational::on_informational;
// pub(crate) use informational::{on_informational_raw, OnInformationalCallback}; // ffi feature in hyperium/hyper

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    inner: ext::Protocol,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            inner: ext::Protocol::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    pub(crate) fn from_inner(inner: ext::Protocol) -> Self {
        Self { inner }
    }

    pub(crate) fn into_inner(self) -> ext::Protocol {
        self.inner
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            inner: ext::Protocol::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}
