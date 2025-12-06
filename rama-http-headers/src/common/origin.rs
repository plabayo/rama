use std::convert::TryFrom;
use std::fmt;

use rama_core::bytes::Bytes;
use rama_core::telemetry::tracing;
use rama_error::{ErrorContext as _, OpaqueError};
use rama_http_types::HeaderValue;
use rama_http_types::uri::{self, Authority, Scheme, Uri};

use crate::Error;
use crate::util::{IterExt, TryFromValues};

/// The `Origin` header.
///
/// The `Origin` header is a version of the `Referer` header that is used for all HTTP fetches and `POST`s whose CORS flag is set.
/// This header is often used to inform recipients of the security context of where the request was initiated.
///
/// Following the spec, [https://fetch.spec.whatwg.org/#origin-header][url], the value of this header is composed of
/// a String (scheme), Host (host/port)
///
/// [url]: https://fetch.spec.whatwg.org/#origin-header
///
/// # Examples
///
/// ```
/// use rama_http_headers::Origin;
///
/// let origin = Origin::NULL;
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin(OriginOrNull);

impl crate::TypedHeader for Origin {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::ORIGIN
    }
}

impl crate::HeaderDecode for Origin {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        crate::util::TryFromValues::try_from_values(values).map(Origin)
    }
}

impl crate::HeaderEncode for Origin {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!("failed to encode origin value as header: {err}");
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum OriginOrNull {
    Origin(Scheme, Authority),
    Null,
}

impl Origin {
    /// The literal `null` Origin header.
    pub const NULL: Self = Self(OriginOrNull::Null);

    /// Checks if `Origin` is `null`.
    #[inline]
    pub fn is_null(&self) -> bool {
        matches!(self.0, OriginOrNull::Null)
    }

    /// Get the "scheme" part of this origin.
    #[inline]
    pub fn scheme(&self) -> &str {
        match self.0 {
            OriginOrNull::Origin(ref scheme, _) => scheme.as_str(),
            OriginOrNull::Null => "",
        }
    }

    /// Get the "hostname" part of this origin.
    #[inline]
    pub fn hostname(&self) -> &str {
        match self.0 {
            OriginOrNull::Origin(_, ref auth) => auth.host(),
            OriginOrNull::Null => "",
        }
    }

    /// Get the "port" part of this origin.
    #[inline]
    pub fn port(&self) -> Option<u16> {
        match self.0 {
            OriginOrNull::Origin(_, ref auth) => auth.port_u16(),
            OriginOrNull::Null => None,
        }
    }

    /// Tries to build a `Origin` from three parts, the scheme, the host and an optional port.
    pub fn try_from_parts(
        scheme: &str,
        host: &str,
        port: impl Into<Option<u16>>,
    ) -> Result<Self, InvalidOrigin> {
        struct MaybePort(Option<u16>);

        impl fmt::Display for MaybePort {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                if let Some(port) = self.0 {
                    write!(f, ":{port}")
                } else {
                    Ok(())
                }
            }
        }

        let bytes = Bytes::from(format!("{}://{}{}", scheme, host, MaybePort(port.into())));
        HeaderValue::from_maybe_shared(bytes)
            .ok()
            .and_then(|val| Self::try_from_value(&val))
            .ok_or(InvalidOrigin)
    }

    // Used in AccessControlAllowOrigin
    pub(super) fn try_from_value(value: &HeaderValue) -> Option<Self> {
        OriginOrNull::try_from_value(value).map(Origin)
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            OriginOrNull::Origin(ref scheme, ref auth) => write!(f, "{scheme}://{auth}"),
            OriginOrNull::Null => f.write_str("null"),
        }
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "origin is not valid"]
    pub struct InvalidOrigin;
}

impl OriginOrNull {
    fn try_from_value(value: &HeaderValue) -> Option<Self> {
        if value == "null" {
            return Some(Self::Null);
        }

        let uri = Uri::try_from(value.as_bytes()).ok()?;

        let (scheme, auth) = match uri.into_parts() {
            uri::Parts {
                scheme: Some(scheme),
                authority: Some(auth),
                path_and_query: None,
                ..
            } => (scheme, auth),
            uri::Parts {
                scheme: Some(ref scheme),
                authority: Some(ref auth),
                path_and_query: Some(ref p),
                ..
            } if p == "/" => (scheme.clone(), auth.clone()),
            _ => {
                return None;
            }
        };

        Some(Self::Origin(scheme, auth))
    }
}

impl TryFromValues for OriginOrNull {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .just_one()
            .and_then(Self::try_from_value)
            .ok_or_else(Error::invalid)
    }
}

impl<'a> TryFrom<&'a OriginOrNull> for HeaderValue {
    type Error = OpaqueError;

    fn try_from(origin: &'a OriginOrNull) -> Result<Self, Self::Error> {
        match origin {
            OriginOrNull::Origin(scheme, auth) => {
                let s = format!("{scheme}://{auth}");
                let bytes = Bytes::from(s);
                Self::from_maybe_shared(bytes)
                    .context("parse Scheme and Authority as a valid header value")
            }
            // Serialized as "null" per ASCII serialization of an origin
            // https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin
            OriginOrNull::Null => Ok(Self::from_static("null")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;

    #[test]
    fn origin() {
        let s = "http://web-platform.test:8000";
        let origin = test_decode::<Origin>(&[s]).unwrap();
        assert_eq!(origin.scheme(), "http");
        assert_eq!(origin.hostname(), "web-platform.test");
        assert_eq!(origin.port(), Some(8000));

        let headers = test_encode(origin);
        assert_eq!(headers["origin"], s);
    }

    #[test]
    fn null() {
        assert_eq!(test_decode::<Origin>(&["null"]), Some(Origin::NULL),);

        let headers = test_encode(Origin::NULL);
        assert_eq!(headers["origin"], "null");
    }
}
