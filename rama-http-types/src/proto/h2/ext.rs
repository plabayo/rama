//! Extensions specific to the HTTP/2 protocol.

use crate::proto::h2::hpack::BytesStr;

use rama_core::bytes::Bytes;
use std::fmt;

/// The `Protocol` extension allows access to the value of the `:protocol` pseudo-header
/// used by the [Extended CONNECT Protocol](https://datatracker.ietf.org/doc/html/rfc8441#section-4).
/// This extension is only sent on HTTP/2 CONNECT requests, most commonly with the value `websocket`.
///
/// # Example
///
/// ```rust
/// use rama_core::extensions::ExtensionsMut;
/// use rama_http_types::proto::h2::ext::Protocol;
/// use rama_http_types::{Request, Method, Version};
///
/// let mut req = Request::new(());
/// *req.method_mut() = Method::CONNECT;
/// *req.version_mut() = Version::HTTP_2;
/// req.extensions_mut().insert(Protocol::from_static("websocket"));
/// // Now the request will include the `:protocol` pseudo-header with value "websocket"
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    #[must_use]
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}
