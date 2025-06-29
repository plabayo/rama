use rama_http_types::HeaderValue;

/// `Upgrade` header, defined in [RFC7230](https://datatracker.ietf.org/doc/html/rfc7230#section-6.7)
///
/// The `Upgrade` header field is intended to provide a simple mechanism
/// for transitioning from HTTP/1.1 to some other protocol on the same
/// connection.  A client MAY send a list of protocols in the Upgrade
/// header field of a request to invite the server to switch to one or
/// more of those protocols, in order of descending preference, before
/// sending the final response.  A server MAY ignore a received Upgrade
/// header field if it wishes to continue using the current protocol on
/// that connection.  Upgrade cannot be used to insist on a protocol
/// change.
///
/// ## ABNF
///
/// ```text
/// Upgrade          = 1#protocol
///
/// protocol         = protocol-name ["/" protocol-version]
/// protocol-name    = token
/// protocol-version = token
/// ```
///
/// ## Example values
///
/// * `HTTP/2.0, SHTTP/1.3, IRC/6.9, RTA/x11`
///
/// # Note
///
/// In practice, the `Upgrade` header is never that complicated. In most cases,
/// it is only ever a single value, such as `"websocket"`.
///
/// # Examples
///
/// ```
/// use rama_http_headers::Upgrade;
///
/// let ws = Upgrade::websocket();
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Upgrade(HeaderValue);

derive_header! {
    Upgrade(_),
    name: UPGRADE
}

impl Upgrade {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for Upgrade {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Upgrade {
    /// Constructs an `Upgrade: websocket` header.
    pub fn websocket() -> Upgrade {
        Upgrade(HeaderValue::from_static("websocket"))
    }

    /// Returns true if this is an `Upgrade: websocket` header.
    pub fn is_websocket(&self) -> bool {
        self.0
            .as_bytes()
            .trim_ascii()
            .eq_ignore_ascii_case(b"websocket")
    }
}
