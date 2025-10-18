use crate::{HeaderDecode, HeaderEncode, TypedHeader};
use rama_core::telemetry::tracing;
use rama_http_types::{HeaderName, HeaderValue};

#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
/// The HTTP DNT (Do Not Track) request header indicates the user's tracking preference.
///
/// It lets users indicate whether they would prefer privacy rather than personalized content.
///
/// [`Dnt`] in the wild is deprecated in favor of Global Privacy Control,
/// which is communicated to servers using the [`Sec-GPC`] header,
/// and accessible to clients from `navigator.globalPrivacyControl`.
///
/// [`Sec-GPC`]: super::SecGpc
pub struct Dnt;

impl Dnt {
    /// Create a new [`Dnt`] typed header.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl TypedHeader for Dnt {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::DNT
    }
}

impl HeaderDecode for Dnt {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(crate::Error::invalid)?;

        if value == "0" {
            tracing::debug!("unexpected Dnt header value of 0; only 1 is expected");
            Err(crate::Error::invalid())
        } else if value == "1" {
            Ok(Self)
        } else {
            Err(crate::Error::invalid())
        }
    }
}

impl HeaderEncode for Dnt {
    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let value = HeaderValue::from_static("1");
        values.extend(std::iter::once(value));
    }
}
