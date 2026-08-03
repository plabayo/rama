//! `data:` URI payloads, as defined by
//! [RFC 2397](https://datatracker.ietf.org/doc/html/rfc2397).
//!
//! The scheme carries its content inline —
//! `data:[<mediatype>][;base64],<data>` — so a consumer decodes it in
//! place instead of dialing or opening anything.

use std::sync::LazyLock;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use mime::Mime;
use rama_core::bytes::Bytes;

use crate::std::{borrow::Cow, string::String};

use super::Uri;

/// Media type a `data:` URI without one defaults to (RFC 2397 §2).
pub const DEFAULT_DATA_MEDIA_TYPE: &str = "text/plain;charset=US-ASCII";

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
            Self::MissingSeparator => f.write_str("data: uri is missing its `,` separator"),
            Self::InvalidBase64 => f.write_str("data: uri payload is not valid base64"),
            Self::InvalidMediaType => f.write_str("data: uri media type is not a valid mime"),
        }
    }
}

impl core::error::Error for DataUriError {}

impl DataUri {
    /// Decode the payload of a `data:` [`Uri`].
    pub fn try_from_uri(uri: &Uri) -> Result<Self, DataUriError> {
        if uri.scheme() != Some(&crate::Protocol::DATA) {
            return Err(DataUriError::NotADataUri);
        }
        // `data:` has an opaque path: everything after the scheme
        let path = uri.path().ok_or(DataUriError::MissingSeparator)?;
        Self::parse(path.as_encoded_str().as_ref())
    }

    /// Decode a `data:` payload given on its own, without the scheme:
    /// `[<mediatype>][;base64],<data>`.
    pub fn parse(raw: &str) -> Result<Self, DataUriError> {
        let (meta, payload) = raw.split_once(',').ok_or(DataUriError::MissingSeparator)?;

        let (media_type, is_base64) = match meta.strip_suffix(";base64") {
            Some(media_type) => (media_type, true),
            None => (meta, false),
        };

        // percent-decoding borrows unless the payload really carries an
        // escape, so the usual payload is decoded with a single allocation
        let payload = Cow::<[u8]>::from(percent_encoding::percent_decode_str(payload));

        let data = if is_base64 {
            let payload = strip_whitespace(payload);
            BASE64_STANDARD
                .decode(payload)
                .map_err(|_err| DataUriError::InvalidBase64)
                .map(Bytes::from)?
        } else {
            into_bytes(payload)
        };

        let media_type = if media_type.is_empty() {
            None
        } else {
            // parsed once here, so consumers get a typed media type
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
                Self::parse(rest)
            }
            _ => Self::parse(s),
        }
    }
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
