use rama_http_types::{HeaderName, HeaderValue};

use std::error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

/// Base trait for a typed header.
///
/// To be implemented as part of being able to
/// implement [`HeaderEncode`] and/or [`HeaderDecode`].
pub trait TypedHeader {
    /// The name of this header.
    fn name() -> &'static HeaderName;
}

impl<H: TypedHeader> TypedHeader for &H {
    #[inline]
    fn name() -> &'static HeaderName {
        H::name()
    }
}

impl<H: TypedHeader> TypedHeader for Arc<H> {
    #[inline]
    fn name() -> &'static HeaderName {
        H::name()
    }
}

/// A typed header which can be decoded from one or multiple headers.
pub trait HeaderDecode: TypedHeader {
    /// Decode this type from an iterator of [`HeaderValue`]s.
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>;
}

/// A typed header which can be encoded into one or multiple headers.
pub trait HeaderEncode: TypedHeader {
    /// Encode this type to a [`HeaderValue`], and add it to a container
    /// which has [`HeaderValue`] type as each element.
    ///
    /// This function should be infallible. Any errors converting to a
    /// `HeaderValue` should have been caught when parsing or constructing
    /// this value.
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E);

    /// Encode this header to [`HeaderValue`].
    fn encode_to_value(&self) -> HeaderValue {
        let mut container = ExtendOnce(None);
        self.encode(&mut container);
        container.0.unwrap()
    }
}

impl<H: HeaderEncode> HeaderEncode for &H {
    #[inline]
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        (*self).encode(values);
    }

    #[inline]
    fn encode_to_value(&self) -> HeaderValue {
        (*self).encode_to_value()
    }
}

impl<H: HeaderEncode> HeaderEncode for Arc<H> {
    #[inline]
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        self.as_ref().encode(values);
    }

    #[inline]
    fn encode_to_value(&self) -> HeaderValue {
        self.as_ref().encode_to_value()
    }
}

struct ExtendOnce(Option<HeaderValue>);

impl Extend<HeaderValue> for ExtendOnce {
    fn extend<T: IntoIterator<Item = HeaderValue>>(&mut self, iter: T) {
        self.0 = iter.into_iter().next();
    }
}

/// Errors trying to decode a header.
#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

#[derive(Debug)]
enum Kind {
    Invalid,
}

impl Error {
    /// Create an 'invalid' Error.
    #[must_use]
    pub fn invalid() -> Self {
        Self {
            kind: Kind::Invalid,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self.kind {
            Kind::Invalid => f.write_str("invalid HTTP header"),
        }
    }
}

impl error::Error for Error {}
