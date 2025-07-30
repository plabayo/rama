use rama_http_types::HeaderValue;

use crate::util::FlatCsv;

/// `TE` header, defined in
/// [RFC7230](https://datatracker.ietf.org/doc/html/rfc7230#section-4.3)
///
/// As RFC7230 states, "The "TE" header field in a request indicates what transfer codings,
/// besides chunked, the client is willing to accept in response, and
/// whether or not the client is willing to accept trailer fields in a
/// chunked transfer coding."
///
/// For HTTP/1.1 compliant clients `chunked` transfer codings are assumed to be acceptable and
/// so should never appear in this header.
///
/// # ABNF
///
/// ```text
/// TE        = "TE" ":" #( t-codings )
/// t-codings = "trailers" | ( transfer-extension [ accept-params ] )
/// ```
///
/// # Example values
/// * `trailers`
/// * `trailers, deflate;q=0.5`
/// * ``
///
/// # Examples
///
#[derive(Clone, Debug, PartialEq)]
pub struct Te(FlatCsv);

derive_header! {
    Te(_),
    name: TE
}

impl Te {
    /// Create a `TE: trailers` header.
    #[must_use]
    pub fn trailers() -> Self {
        Self(HeaderValue::from_static("trailers").into())
    }
}
