//! `data:` URI payloads, as defined by
//! [RFC 2397](https://datatracker.ietf.org/doc/html/rfc2397).
//!
//! The scheme carries its content inline —
//! `data:[<mediatype>][;base64],<data>` — so a consumer decodes it in
//! place instead of dialing or opening anything.

use std::sync::LazyLock;

use base64::{
    Engine as _,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD as BASE64_STANDARD},
    },
};
use mime::Mime;
use rama_core::bytes::Bytes;

use crate::std::{borrow::Cow, string::String};

use super::Uri;

/// Media type a `data:` URI without one defaults to (RFC 2397 §2).
pub const DEFAULT_DATA_MEDIA_TYPE: &str = "text/plain;charset=US-ASCII";

/// The `base64` token, matched ASCII-case-insensitively (RFC 2397 §3).
const BASE64_TOKEN: &str = "base64";

/// Decoding tolerates missing padding, which producers in the wild emit
/// and browsers accept; encoding still pads.
static BASE64_DECODE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

static DEFAULT_MEDIA_TYPE: LazyLock<Mime> =
    LazyLock::new(|| DEFAULT_DATA_MEDIA_TYPE.parse().unwrap_or(mime::TEXT_PLAIN));

/// The decoded content of a `data:` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataUri {
    media_type: Option<Mime>,
    data: Bytes,
}

/// Why a `data:` URI could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataUriError {
    /// The uri is not a `data:` uri.
    NotADataUri,
    /// The `,` separating the metadata from the payload is missing.
    MissingSeparator,
    /// The payload is not valid base64.
    InvalidBase64,
    /// The media type is not a valid mime type.
    InvalidMediaType,
}

impl core::fmt::Display for DataUriError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotADataUri => f.write_str("not a data: uri"),
            Self::MissingSeparator => f.write_str("data: uri is missing its `,` payload separator"),
            Self::InvalidBase64 => f.write_str("data: uri payload is not valid base64"),
            Self::InvalidMediaType => f.write_str("data: uri media type is not a valid mime"),
        }
    }
}

impl core::error::Error for DataUriError {}

impl DataUri {
    /// Decode the payload of a `data:` [`Uri`].
    ///
    /// A `?` is payload; a `#` starts a uri fragment and ends it.
    pub fn try_from_uri(uri: &Uri) -> Result<Self, DataUriError> {
        if uri.scheme() != Some(&crate::Protocol::DATA) {
            return Err(DataUriError::NotADataUri);
        }
        // a generic RFC 3986 parse splits the payload at `?`, while for
        // `data:` the query is part of the body; only the fragment is dropped
        let path = uri.path().ok_or(DataUriError::MissingSeparator)?;
        let path = path.as_encoded_str();
        match uri.query() {
            Some(query) => {
                let query = query.as_encoded_str();
                let mut raw = String::with_capacity(path.len() + 1 + query.len());
                raw.push_str(&path);
                raw.push('?');
                raw.push_str(&query);
                Self::parse(&raw)
            }
            None => Self::parse(&path),
        }
    }

    /// Decode a `data:` payload given on its own, without the scheme:
    /// `[<mediatype>][;base64],<data>`.
    ///
    /// Every byte given is payload. Parsing a full `data:` uri instead — via
    /// [`Self::try_from_uri`] or [`FromStr`][core::str::FromStr] — drops the
    /// fragment first, since `#` ends a uri rather than belonging to it.
    pub fn parse(raw: &str) -> Result<Self, DataUriError> {
        let (meta, payload) = raw.split_once(',').ok_or(DataUriError::MissingSeparator)?;

        let (media_type, is_base64) = match strip_base64_suffix(meta) {
            Some(media_type) => (media_type, true),
            None => (meta, false),
        };

        let media_type = percent_encoding::percent_decode_str(media_type)
            .decode_utf8()
            .map_err(|_err| DataUriError::InvalidMediaType)?;

        // percent-decoding borrows unless the payload really carries an
        // escape, so the usual payload is decoded with a single allocation
        let payload = Cow::<[u8]>::from(percent_encoding::percent_decode_str(payload));

        let data = if is_base64 {
            let payload = strip_whitespace(payload);
            BASE64_DECODE
                .decode(payload)
                .map_err(|_err| DataUriError::InvalidBase64)
                .map(Bytes::from)?
        } else {
            into_bytes(payload)
        };

        // parsed once here, so consumers get a typed media type
        let media_type = if media_type.is_empty() {
            None
        } else if media_type.starts_with(';') {
            // RFC 2397 allows a parameters-only media type: the default type applies
            let mut full =
                String::with_capacity(mime::TEXT_PLAIN.as_ref().len() + media_type.len());
            full.push_str(mime::TEXT_PLAIN.as_ref());
            full.push_str(&media_type);
            Some(
                full.parse()
                    .map_err(|_err| DataUriError::InvalidMediaType)?,
            )
        } else {
            Some(
                media_type
                    .parse()
                    .map_err(|_err| DataUriError::InvalidMediaType)?,
            )
        };

        Ok(Self { media_type, data })
    }

    /// The media type, or the RFC 2397 default when the uri omitted one.
    #[must_use]
    pub fn media_type(&self) -> &Mime {
        self.media_type.as_ref().unwrap_or(&DEFAULT_MEDIA_TYPE)
    }

    /// Returns `true` when the uri carried no media type of its own.
    #[must_use]
    pub fn is_default_media_type(&self) -> bool {
        self.media_type.is_none()
    }

    /// The decoded payload.
    #[must_use]
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Consume into the decoded payload.
    #[must_use]
    pub fn into_data(self) -> Bytes {
        self.data
    }

    /// The decoded payload as a string, when it is valid utf-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.data).ok()
    }
}

/// Strip the `;base64` marker, which is case-insensitive. The Fetch
/// algorithm also accepts U+0020 spaces between the semicolon and token.
fn strip_base64_suffix(meta: &str) -> Option<&str> {
    let index = meta.len().checked_sub(BASE64_TOKEN.len())?;
    let (head, suffix) = meta.split_at_checked(index)?;
    if !suffix.eq_ignore_ascii_case(BASE64_TOKEN) {
        return None;
    }
    head.trim_end_matches(' ').strip_suffix(';')
}

/// Drop the whitespace base64 payloads may be wrapped with, in place
/// when the buffer is already owned.
fn strip_whitespace(mut payload: Cow<'_, [u8]>) -> Cow<'_, [u8]> {
    if payload.iter().any(u8::is_ascii_whitespace) {
        payload.to_mut().retain(|byte| !byte.is_ascii_whitespace());
    }
    payload
}

fn into_bytes(payload: Cow<'_, [u8]>) -> Bytes {
    match payload {
        // an owned buffer moves into `Bytes` without copying
        Cow::Owned(payload) => Bytes::from(payload),
        Cow::Borrowed(payload) => Bytes::copy_from_slice(payload),
    }
}

impl TryFrom<&Uri> for DataUri {
    type Error = DataUriError;

    fn try_from(uri: &Uri) -> Result<Self, Self::Error> {
        Self::try_from_uri(uri)
    }
}

impl core::str::FromStr for DataUri {
    type Err = DataUriError;

    /// Parse either a full `data:` uri or a bare payload.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once(':') {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case(crate::Protocol::DATA_SCHEME) => {
                // a full uri ends at its fragment, exactly as `try_from_uri`
                // sees it once a uri parse has split one off
                Self::parse(strip_fragment(rest))
            }
            _ => Self::parse(s),
        }
    }
}

/// A uri ends at its fragment.
fn strip_fragment(raw: &str) -> &str {
    raw.split_once('#')
        .map_or(raw, |(payload, _fragment)| payload)
}

/// Render `data` as a `data:` uri payload, base64-encoding the bytes.
///
/// The media type is written verbatim; pass `None` for the RFC default.
#[must_use]
pub fn encode_data_uri(media_type: Option<&str>, data: &[u8]) -> String {
    let mut out = String::from("data:");
    if let Some(media_type) = media_type {
        out.push_str(media_type);
    }
    out.push_str(";base64,");
    out.push_str(&BASE64_STANDARD.encode(data));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_payload() {
        let uri = DataUri::parse(",hello%20world").unwrap();
        assert_eq!(uri.as_str(), Some("hello world"));
        assert_eq!(uri.media_type(), &*DEFAULT_MEDIA_TYPE);
        assert!(uri.is_default_media_type());
    }

    #[test]
    fn base64_payload_with_media_type() {
        let uri = DataUri::parse("text/javascript;base64,RElSRUNU").unwrap();
        assert_eq!(uri.as_str(), Some("DIRECT"));
        assert_eq!(uri.media_type(), &mime::TEXT_JAVASCRIPT);
        assert!(!uri.is_default_media_type());
    }

    #[test]
    fn base64_payload_ignores_whitespace() {
        let uri = DataUri::parse("text/plain;base64,SGVsbG8%20gUEFD").unwrap();
        assert_eq!(uri.as_str(), Some("Hello PAC"));
    }

    #[test]
    fn media_type_with_parameters_is_preserved() {
        let uri = DataUri::parse("text/plain;charset=utf-8,hi").unwrap();
        assert_eq!(uri.media_type(), &mime::TEXT_PLAIN_UTF_8);
    }

    #[test]
    fn base64_marker_is_case_insensitive() {
        for raw in [
            "text/plain;BASE64,SGk=",
            "text/plain;Base64,SGk=",
            "text/plain;base64,SGk=",
        ] {
            let uri = DataUri::parse(raw).unwrap();
            assert_eq!(uri.as_str(), Some("Hi"), "{raw}");
            assert_eq!(uri.media_type(), &mime::TEXT_PLAIN, "{raw}");
        }

        // ... also without a media type of its own
        let uri = DataUri::parse(";BASE64,SGk=").unwrap();
        assert_eq!(uri.as_str(), Some("Hi"));
        assert!(uri.is_default_media_type());
    }

    #[test]
    fn base64_marker_accepts_browser_space_compatibility() {
        for raw in ["text/plain; base64,SGk=", "text/plain;   BASE64,SGk="] {
            let uri = DataUri::parse(raw).unwrap();
            assert_eq!(uri.as_str(), Some("Hi"), "{raw}");
            assert_eq!(uri.media_type(), &mime::TEXT_PLAIN, "{raw}");
        }
    }

    #[test]
    fn escaped_media_type_is_decoded() {
        let uri = DataUri::parse("text%2Fplain%3Bcharset%3Dutf-8,hi").unwrap();
        assert_eq!(uri.as_str(), Some("hi"));
        assert_eq!(uri.media_type(), &mime::TEXT_PLAIN_UTF_8);
    }

    #[test]
    fn parameters_only_media_type_uses_default_type() {
        let uri = DataUri::parse(";charset=utf-8,x").unwrap();
        assert_eq!(uri.as_str(), Some("x"));
        assert_eq!(uri.media_type(), &mime::TEXT_PLAIN_UTF_8);
        assert!(!uri.is_default_media_type());
    }

    #[test]
    fn unpadded_base64_is_accepted() {
        let uri = DataUri::parse("text/plain;base64,SGk").unwrap();
        assert_eq!(uri.as_str(), Some("Hi"));
    }

    #[test]
    fn binary_payload_need_not_be_utf8() {
        let uri = DataUri::parse("application/octet-stream;base64,//79").unwrap();
        assert_eq!(uri.data().as_ref(), &[0xff, 0xfe, 0xfd]);
        assert_eq!(uri.as_str(), None);
    }

    #[test]
    fn errors() {
        assert_eq!(
            DataUri::parse("text/plain"),
            Err(DataUriError::MissingSeparator)
        );
        assert_eq!(
            DataUri::parse("text/plain;base64,!!!nope!!!"),
            Err(DataUriError::InvalidBase64)
        );
        assert_eq!(
            DataUri::parse("not a mime,payload"),
            Err(DataUriError::InvalidMediaType)
        );
    }

    #[test]
    fn from_uri_and_from_str() {
        let uri: Uri = "data:text/plain,hi".parse().unwrap();
        assert_eq!(DataUri::try_from_uri(&uri).unwrap().as_str(), Some("hi"));

        let http: Uri = "http://example.com/".parse().unwrap();
        assert_eq!(DataUri::try_from_uri(&http), Err(DataUriError::NotADataUri));

        // the scheme is optional when parsing a payload directly
        assert_eq!("data:,hi".parse::<DataUri>().unwrap().as_str(), Some("hi"));
        assert_eq!(",hi".parse::<DataUri>().unwrap().as_str(), Some("hi"));
        // case-insensitive scheme
        assert_eq!("DATA:,hi".parse::<DataUri>().unwrap().as_str(), Some("hi"));
    }

    #[test]
    fn payload_keeps_query_and_drops_fragment() {
        for (raw, expected) in [
            ("data:,a?b", "a?b"),
            ("data:,a?b?c", "a?b?c"),
            ("data:,a#b", "a"),
            ("data:,a?b#c", "a?b"),
            (
                "data:application/x-ns-proxy-autoconfig,function FindProxyForURL(u,h){return h==\"a\"?\"DIRECT\":\"PROXY p:1\";}",
                "function FindProxyForURL(u,h){return h==\"a\"?\"DIRECT\":\"PROXY p:1\";}",
            ),
        ] {
            let uri: Uri = raw.parse().unwrap();
            assert_eq!(
                DataUri::try_from_uri(&uri).unwrap().as_str(),
                Some(expected),
                "{raw}"
            );
        }

        // and `try_from_uri` agrees with `from_str` on the query
        let raw = "data:,a?b";
        let uri: Uri = raw.parse().unwrap();
        assert_eq!(
            DataUri::try_from_uri(&uri).unwrap(),
            raw.parse::<DataUri>().unwrap()
        );
    }

    #[test]
    fn from_uri_and_from_str_agree_on_query_and_fragment() {
        for (raw, expected) in [
            ("data:,a?b", "a?b"),
            ("data:,a#b", "a"),
            ("data:,a?b#c", "a?b"),
            ("data:,a#b?c", "a"),
            (
                r#"data:text/html,<p style="color:#fff">hi</p>"#,
                r#"<p style="color:"#,
            ),
            // an encoded `#` stays payload
            ("data:,a%23b", "a#b"),
        ] {
            let uri: Uri = raw.parse().unwrap_or_else(|err| panic!("`{raw}`: {err}"));
            let from_uri = DataUri::try_from_uri(&uri).unwrap();
            let from_str = raw.parse::<DataUri>().unwrap();
            assert_eq!(from_uri.as_str(), Some(expected), "{raw}");
            assert_eq!(from_uri, from_str, "{raw}");
        }
    }

    #[test]
    fn encode_round_trips() {
        let encoded = encode_data_uri(Some("text/plain"), b"round trip");
        assert!(encoded.starts_with("data:text/plain;base64,"), "{encoded}");

        let uri: Uri = encoded.parse().unwrap();
        let decoded = DataUri::try_from_uri(&uri).unwrap();
        assert_eq!(decoded.as_str(), Some("round trip"));
        assert_eq!(decoded.media_type(), &mime::TEXT_PLAIN);

        // and without a media type the default applies on the way back
        let encoded = encode_data_uri(None, b"x");
        assert_eq!(encoded, "data:;base64,eA==");
        let uri: Uri = encoded.parse().unwrap();
        assert!(DataUri::try_from_uri(&uri).unwrap().is_default_media_type());
    }
}
