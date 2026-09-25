//! Extensions specific to the HTTP/2 protocol.

use crate::proto::h2::{frame::Reason, hpack::BytesStr};

use rama_core::bytes::Bytes;
use rama_core::extensions::Extension;
use rama_utils::byte_set::{set_ascii_alphanum, set_each};
use std::fmt;

/// The `Protocol` extension carries the value of the `:protocol` pseudo-header used by the
/// [Extended CONNECT Protocol](https://datatracker.ietf.org/doc/html/rfc8441#section-4).
///
/// It is shared by HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220): both carry the same `:protocol`
/// pseudo-header, most commonly with the value `websocket`.
///
/// The value is a validated, non-empty HTTP token (RFC 9110 §5.6.2). Every construction path
/// enforces that invariant, so a `Protocol` can never hold an empty or non-token value that
/// would be illegal on the wire.
///
/// # Example
///
/// ```rust
/// use rama_core::extensions::ExtensionsRef;
/// use rama_http_types::proto::h2::ext::Protocol;
/// use rama_http_types::{Request, Method, Version};
///
/// let mut req = Request::new(());
/// *req.method_mut() = Method::CONNECT;
/// *req.version_mut() = Version::HTTP_2;
/// req.extensions().insert(Protocol::WEBSOCKET);
/// // Now the request will include the `:protocol` pseudo-header with value "websocket"
/// ```
#[derive(Clone, Eq, PartialEq, Extension)]
#[extension(tags(http))]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// `websocket`, the token registered by RFC 8441 for the WebSocket Protocol.
    ///
    /// It is used for Extended CONNECT over both HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220).
    pub const WEBSOCKET: Self = Self::from_static("websocket");

    /// Converts a static string to a protocol name.
    ///
    /// # Panics
    ///
    /// Panics if `value` is not a non-empty HTTP token. Because a `:protocol` value that is not
    /// a token cannot be sent on the wire, an invalid literal is a programming error rather than
    /// a runtime condition.
    #[must_use]
    pub const fn from_static(value: &'static str) -> Self {
        assert!(
            is_token(value.as_bytes()),
            "`:protocol` value must be a non-empty HTTP token"
        );
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    /// Parses a `:protocol` value from raw wire bytes, validating that it is a non-empty token.
    pub fn try_from_bytes(bytes: Bytes) -> Result<Self, InvalidProtocol> {
        if !is_token(bytes.as_ref()) {
            return Err(InvalidProtocol::new());
        }
        // a token is ASCII, so the bytes are valid UTF-8; validate defensively rather than
        // reaching for an unchecked conversion.
        let value = BytesStr::try_from(bytes)?;
        Ok(Self { value })
    }
}

impl TryFrom<Bytes> for Protocol {
    type Error = InvalidProtocol;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl<'a> TryFrom<&'a str> for Protocol {
    type Error = InvalidProtocol;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::try_from_bytes(Bytes::copy_from_slice(value.as_bytes()))
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

/// RFC 9110 §5.6.2 `tchar` lookup table.
const TCHAR_SET: [bool; 256] = set_each(set_ascii_alphanum([false; 256]), b"!#$%&'*+-.^_`|~");

/// Returns whether `bytes` is a non-empty HTTP token (RFC 9110 §5.6.2, `1*tchar`).
const fn is_token(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        if !TCHAR_SET[bytes[i] as usize] {
            return false;
        }
        i += 1;
    }
    true
}

rama_utils::macros::error::static_str_error! {
    #[doc = "`:protocol` pseudo-header value is not a non-empty HTTP token"]
    #[derive(Copy)]
    pub struct InvalidProtocol;
}

impl From<std::str::Utf8Error> for InvalidProtocol {
    fn from(_: std::str::Utf8Error) -> Self {
        // a validated token is ASCII, so this is unreachable in practice; map it defensively.
        Self::new()
    }
}

/// Reset the HTTP/2 stream with this [`Reason`] instead of sending the
/// response carrying it.
///
/// Only the HTTP/2 server acts on it; other versions send the response
/// as is, so attach it to a response that is a sane fallback.
///
/// [`Reason::REFUSED_STREAM`] tells the client the request was not
/// processed, which makes it safe to retry (RFC 9113 section 8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
#[extension(tags(http))]
pub struct ResetStream(pub Reason);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_constant() {
        assert_eq!(Protocol::WEBSOCKET.as_str(), "websocket");
    }

    #[test]
    fn from_static_valid() {
        assert_eq!(Protocol::from_static("connect-udp").as_str(), "connect-udp");
    }

    #[test]
    #[should_panic(expected = "non-empty HTTP token")]
    fn from_static_empty_panics() {
        let _p = Protocol::from_static("");
    }

    #[test]
    #[should_panic(expected = "non-empty HTTP token")]
    fn from_static_non_token_panics() {
        let _p = Protocol::from_static("bad protocol");
    }

    #[test]
    fn try_from_bytes_valid() {
        let p = Protocol::try_from_bytes(Bytes::from_static(b"websocket")).unwrap();
        assert_eq!(p.as_str(), "websocket");
    }

    #[test]
    fn try_from_bytes_rejects_empty() {
        Protocol::try_from_bytes(Bytes::new()).unwrap_err();
    }

    #[test]
    fn try_from_bytes_rejects_non_token() {
        // space is not a tchar
        Protocol::try_from_bytes(Bytes::from_static(b"web socket")).unwrap_err();
        // control byte
        Protocol::try_from_bytes(Bytes::from_static(b"web\x01")).unwrap_err();
        // delimiter
        Protocol::try_from_bytes(Bytes::from_static(b"a/b")).unwrap_err();
    }

    #[test]
    fn try_from_str() {
        assert_eq!(Protocol::try_from("h2c").unwrap().as_str(), "h2c");
        Protocol::try_from("").unwrap_err();
        Protocol::try_from("a b").unwrap_err();
    }
}
