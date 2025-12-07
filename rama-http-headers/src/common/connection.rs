use rama_core::{combinators::Either, telemetry::tracing};
use rama_error::OpaqueError;
use rama_http_types::{
    HeaderName, HeaderValue,
    header::{KEEP_ALIVE, UPGRADE},
};
use rama_utils::collections::NonEmptyVec;

use crate::util::{
    FlatCsvSeparator, TryFromValues, try_decode_flat_csv_header_values_as_non_empty_vec,
    try_encode_non_empty_vec_as_flat_csv_header_value,
};

/// `Connection` header, defined in
/// [RFC7230](https://datatracker.ietf.org/doc/html/rfc7230#section-6.1)
///
/// The `Connection` header field allows the sender to indicate desired
/// control options for the current connection.  In order to avoid
/// confusing downstream recipients, a proxy or gateway MUST remove or
/// replace any received connection options before forwarding the
/// message.
///
/// # ABNF
///
/// ```text
/// Connection        = 1#connection-option
/// connection-option = token
///
/// # Example values
/// * `close`
/// * `keep-alive`
/// * `upgrade`
/// * `keep-alive, upgrade`
/// ```
///
/// # Examples
///
/// ```
/// use rama_http_headers::Connection;
///
/// let keep_alive = Connection::keep_alive();
/// ```
#[derive(Clone, Debug)]
pub struct Connection(Directive);

impl Connection {
    pub fn iter_headers(&self) -> impl Iterator<Item = &HeaderName> {
        match &self.0 {
            Directive::Close => Either::A(std::iter::empty()),
            Directive::Open(non_empty_vec) => Either::B(non_empty_vec.iter()),
        }
    }
}

#[derive(Clone, Debug)]
enum Directive {
    Close,
    Open(NonEmptyVec<HeaderName>),
}

impl TryFrom<&Directive> for HeaderValue {
    type Error = OpaqueError;

    fn try_from(value: &Directive) -> Result<Self, Self::Error> {
        match value {
            Directive::Close => Ok(DIRECTIVE_HEADER_VALUE_CLOSE),
            Directive::Open(values) => {
                try_encode_non_empty_vec_as_flat_csv_header_value(values, FlatCsvSeparator::Comma)
            }
        }
    }
}

impl TryFromValues for Directive {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        match try_decode_flat_csv_header_values_as_non_empty_vec(values, FlatCsvSeparator::Comma) {
            Ok(values) => {
                if values.len() == 1 && values.first() == "close" {
                    Ok(Self::Close)
                } else {
                    Ok(Self::Open(values))
                }
            }
            Err(err) => {
                tracing::trace!("invalid connection directive: {err}");
                Err(crate::Error::invalid())
            }
        }
    }
}

const DIRECTIVE_HEADER_VALUE_CLOSE: HeaderValue = HeaderValue::from_static("close");

impl crate::TypedHeader for Connection {
    fn name() -> &'static ::rama_http_types::header::HeaderName {
        &::rama_http_types::header::CONNECTION
    }
}

impl crate::HeaderDecode for Connection {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
    {
        Directive::try_from_values(values).map(Self)
    }
}

impl crate::HeaderEncode for Connection {
    fn encode<E: Extend<::rama_http_types::HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::try_from(&self.0) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                rama_core::telemetry::tracing::debug!(
                    "failed to encode connection directive {:?} as flat csv header: {err}",
                    self.0,
                );
            }
        }
    }
}

impl Connection {
    /// A constructor to easily create a `Connection` header,
    /// for the given header names.
    #[inline]
    #[must_use]
    pub fn open(headers: NonEmptyVec<HeaderName>) -> Self {
        Self(Directive::Open(headers))
    }

    /// A constructor to easily create a `Connection: close` header.
    #[inline]
    #[must_use]
    pub fn close() -> Self {
        Self(Directive::Close)
    }

    /// Returns true if this [`Connection`] header contains `close`.
    #[inline]
    pub fn is_close(&self) -> bool {
        matches!(self.0, Directive::Close)
    }

    /// A constructor to easily create a `Connection: keep-alive` header.
    #[inline]
    #[must_use]
    pub fn keep_alive() -> Self {
        Self(Directive::Open(NonEmptyVec::new(KEEP_ALIVE.clone())))
    }

    /// A constructor to easily create a `Connection: Upgrade` header.
    #[inline]
    #[must_use]
    pub fn upgrade() -> Self {
        Self(Directive::Open(NonEmptyVec::new(UPGRADE.clone())))
    }

    /// Returns true if this [`Connection`] header contains the given header.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http_types::header::UPGRADE;
    /// use rama_http_headers::Connection;
    ///
    /// let conn = Connection::keep_alive();
    ///
    /// assert!(!conn.contains_header(UPGRADE));
    /// assert!(conn.contains_header("keep-alive"));
    /// assert!(conn.contains_header("Keep-Alive"));
    /// ```
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn contains_header(&self, name: impl PartialEq<HeaderName>) -> bool {
        match &self.0 {
            Directive::Close => false,
            Directive::Open(values) => values.iter().any(|candidate| name.eq(candidate)),
        }
    }

    /// Returns true if this [`Connection`] header contains `Upgrade`.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http_headers::Connection;
    ///
    /// assert!(!Connection::keep_alive().contains_upgrade());
    /// assert!(Connection::upgrade().contains_upgrade());
    /// ```
    #[inline]
    pub fn contains_upgrade(&self) -> bool {
        self.contains_header(&UPGRADE)
    }

    /// Returns true if this [`Connection`] header contains `Keep-Alive`.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http_headers::Connection;
    ///
    /// assert!(Connection::keep_alive().contains_keep_alive());
    /// assert!(!Connection::upgrade().contains_keep_alive());
    /// ```
    #[inline]
    pub fn contains_keep_alive(&self) -> bool {
        self.contains_header(&KEEP_ALIVE)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_header_single_open() {
        let Connection(directive) = test_decode(&["foo, bar"]).unwrap();
        match directive {
            Directive::Close => panic!("unexpecte close directive"),
            Directive::Open(non_empty_vec) => {
                assert_eq!(2, non_empty_vec.len());
                assert_eq!(non_empty_vec[0], "foo");
                assert_eq!(non_empty_vec[1], "bar");
            }
        }
    }

    #[test]
    fn decode_header_single_close() {
        let Connection(directive) = test_decode(&["close"]).unwrap();
        match directive {
            Directive::Close => (),
            Directive::Open(non_empty_vec) => {
                panic!("unexpected open directive, headers: {non_empty_vec:?}")
            }
        }
    }

    #[test]
    fn encode_open() {
        let allow = Connection::open(non_empty_vec![
            ::rama_http_types::header::KEEP_ALIVE.clone(),
            ::rama_http_types::header::TRAILER,
        ]);

        let headers = test_encode(allow);
        assert_eq!(headers["connection"], "keep-alive, trailer");
    }

    #[test]
    fn decode_with_empty_header_value() {
        assert!(test_decode::<Connection>(&[""]).is_none());
    }

    #[test]
    fn decode_with_no_headers() {
        assert!(test_decode::<Connection>(&[]).is_none());
    }

    #[test]
    fn decode_with_invalid_value_str() {
        assert!(test_decode::<Connection>(&["foo foo, bar"]).is_none());
    }
}
