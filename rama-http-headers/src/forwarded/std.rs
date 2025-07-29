use std::ops::{Deref, DerefMut};

use rama_core::telemetry::tracing;
use rama_http_types::{HeaderName, HeaderValue, header::FORWARDED};
use rama_net::forwarded::ForwardedElement;

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

use super::ForwardHeader;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Typed header wrapper for [`rama_net::forwarded::Forwarded`];
pub struct Forwarded(rama_net::forwarded::Forwarded);

impl Deref for Forwarded {
    type Target = rama_net::forwarded::Forwarded;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Forwarded {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Forwarded {
    #[inline]
    /// Return the inner [`Forwarded`].
    ///
    /// [`Forwarded`]: rama_net::forwarded::Forwarded
    #[must_use]
    pub fn into_inner(self) -> rama_net::forwarded::Forwarded {
        self.0
    }
}

impl From<rama_net::forwarded::Forwarded> for Forwarded {
    fn from(value: rama_net::forwarded::Forwarded) -> Self {
        Self(value)
    }
}

impl From<Forwarded> for rama_net::forwarded::Forwarded {
    fn from(value: Forwarded) -> Self {
        value.0
    }
}

impl TypedHeader for Forwarded {
    fn name() -> &'static HeaderName {
        &FORWARDED
    }
}

impl HeaderDecode for Forwarded {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let first_header = values.next().ok_or_else(Error::invalid)?;

        let mut forwarded: rama_net::forwarded::Forwarded = match first_header.as_bytes().try_into()
        {
            Ok(f) => f,
            Err(err) => {
                tracing::trace!("failed to turn header into Forwarded extension: {err:?}");
                return Err(Error::invalid());
            }
        };

        for header in values {
            let other: rama_net::forwarded::Forwarded = match header.as_bytes().try_into() {
                Ok(f) => f,
                Err(err) => {
                    tracing::trace!("failed to turn header into Forwarded extension: {err:?}");
                    return Err(Error::invalid());
                }
            };
            forwarded.extend(other);
        }

        Ok(Self(forwarded))
    }
}

impl HeaderEncode for Forwarded {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = self.0.to_string();

        let value = HeaderValue::try_from(s)
            .expect("Forwarded extension should always result in a valid header value");

        values.extend(std::iter::once(value));
    }
}

impl IntoIterator for Forwarded {
    type Item = <rama_net::forwarded::Forwarded as IntoIterator>::Item;
    type IntoIter = <rama_net::forwarded::Forwarded as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl ForwardHeader for Forwarded {
    fn try_from_forwarded<'a, I>(input: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a ForwardedElement>,
    {
        let mut it = input.into_iter();
        let mut forwarded = rama_net::forwarded::Forwarded::new(it.next()?.clone());
        forwarded.extend(it.cloned());
        Some(Self(forwarded))
    }
}
