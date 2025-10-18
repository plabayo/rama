use crate::{HeaderDecode, HeaderEncode, TypedHeader};
use rama_core::telemetry::tracing;
use rama_http_types::{HeaderName, HeaderValue};

#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
/// The `Sec-GPC` header, or the Global Privacy Control header.
///
/// It is an HTTP response and request header used specifically to allow the user to
/// communicate their privacy preferences to the server.
///
/// This enables the user to exercise control over the privacy of their personal
/// information against tracking, data selling, or adverse uses.
pub struct SecGpc;

impl SecGpc {
    /// Create a new [`SecGpc`] typed header.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl TypedHeader for SecGpc {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::SEC_GPC
    }
}

impl HeaderDecode for SecGpc {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(crate::Error::invalid)?;

        if value == "0" {
            tracing::debug!("unexpected Sec-Gpc header value of 0; only 1 is expected");
            Err(crate::Error::invalid())
        } else if value == "1" {
            Ok(Self)
        } else {
            Err(crate::Error::invalid())
        }
    }
}

impl HeaderEncode for SecGpc {
    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let value = HeaderValue::from_static("1");
        values.extend(std::iter::once(value));
    }
}
