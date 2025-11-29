use rama_http_types::HeaderValue;
use std::convert::TryFrom;

use super::origin::Origin;
use crate::Error;
use crate::util::{IterExt, TryFromValues};

/// `Access-Control-Allow-Origin` header, as defined on
/// [mdn](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin).
///
/// The `Access-Control-Allow-Origin` header indicates whether a resource
/// can be shared based by returning the value of the Origin request header,
/// `*`, or `null` in the response.
///
/// ## ABNF
///
/// ```text
/// Access-Control-Allow-Origin = "Access-Control-Allow-Origin" ":" origin-list-or-null | "*"
/// ```
///
/// ## Example values
/// * `null`
/// * `*`
/// * `http://google.com/`
///
/// # Examples
///
/// ```
/// use rama_http_headers::AccessControlAllowOrigin;
/// use std::convert::TryFrom;
///
/// let any_origin = AccessControlAllowOrigin::ANY;
/// let null_origin = AccessControlAllowOrigin::NULL;
/// let origin = AccessControlAllowOrigin::try_from("http://web-platform.test:8000");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccessControlAllowOrigin(OriginOrAny);

impl crate::TypedHeader for AccessControlAllowOrigin {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::ACCESS_CONTROL_ALLOW_ORIGIN
    }
}

impl crate::HeaderDecode for AccessControlAllowOrigin {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        crate::util::TryFromValues::try_from_values(values).map(AccessControlAllowOrigin)
    }
}

impl crate::HeaderEncode for AccessControlAllowOrigin {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match &self.0 {
            OriginOrAny::Origin(origin) => origin.encode(values),
            OriginOrAny::Any => values.extend(::std::iter::once(HeaderValue::from_static("*"))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum OriginOrAny {
    Origin(Origin),
    /// Allow all origins
    Any,
}

impl AccessControlAllowOrigin {
    /// `Access-Control-Allow-Origin: *`
    pub const ANY: Self = Self(OriginOrAny::Any);
    /// `Access-Control-Allow-Origin: null`
    pub const NULL: Self = Self(OriginOrAny::Origin(Origin::NULL));

    /// Returns the origin if there's one specified.
    pub fn origin(&self) -> Option<&Origin> {
        match self.0 {
            OriginOrAny::Origin(ref origin) => Some(origin),
            OriginOrAny::Any => None,
        }
    }

    pub fn try_from_origin_header_value(header_value: &HeaderValue) -> Option<Self> {
        let origin = Origin::try_from_value(header_value)?;
        Some(Self(OriginOrAny::Origin(origin)))
    }
}

impl TryFrom<&str> for AccessControlAllowOrigin {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Error> {
        let header_value = HeaderValue::from_str(s).map_err(|_| Error::invalid())?;
        let origin = OriginOrAny::try_from(&header_value)?;
        Ok(Self(origin))
    }
}

impl TryFrom<&HeaderValue> for OriginOrAny {
    type Error = Error;

    fn try_from(header_value: &HeaderValue) -> Result<Self, Error> {
        Origin::try_from_value(header_value)
            .map(OriginOrAny::Origin)
            .ok_or_else(Error::invalid)
    }
}

impl TryFromValues for OriginOrAny {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .just_one()
            .and_then(|value| {
                if value == "*" {
                    return Some(Self::Any);
                }

                Origin::try_from_value(value).map(OriginOrAny::Origin)
            })
            .ok_or_else(Error::invalid)
    }
}

#[cfg(test)]
mod tests {

    use super::super::{test_decode, test_encode};
    use super::*;

    #[test]
    fn origin() {
        let s = "http://web-platform.test:8000";

        let allow_origin = test_decode::<AccessControlAllowOrigin>(&[s]).unwrap();
        {
            let origin = allow_origin.origin().unwrap();
            assert_eq!(origin.scheme(), "http");
            assert_eq!(origin.hostname(), "web-platform.test");
            assert_eq!(origin.port(), Some(8000));
        }

        let headers = test_encode(allow_origin);
        assert_eq!(headers["access-control-allow-origin"], s);
    }

    #[test]
    fn try_from_origin() {
        let s = "http://web-platform.test:8000";

        let allow_origin = AccessControlAllowOrigin::try_from(s).unwrap();
        {
            let origin = allow_origin.origin().unwrap();
            assert_eq!(origin.scheme(), "http");
            assert_eq!(origin.hostname(), "web-platform.test");
            assert_eq!(origin.port(), Some(8000));
        }

        let headers = test_encode(allow_origin);
        assert_eq!(headers["access-control-allow-origin"], s);
    }

    #[test]
    fn any() {
        let allow_origin = test_decode::<AccessControlAllowOrigin>(&["*"]).unwrap();
        assert_eq!(allow_origin, AccessControlAllowOrigin::ANY);

        let headers = test_encode(allow_origin);
        assert_eq!(headers["access-control-allow-origin"], "*");
    }

    #[test]
    fn null() {
        let allow_origin = test_decode::<AccessControlAllowOrigin>(&["null"]).unwrap();
        assert_eq!(allow_origin, AccessControlAllowOrigin::NULL);

        let headers = test_encode(allow_origin);
        assert_eq!(headers["access-control-allow-origin"], "null");
    }
}
