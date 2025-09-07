use std::iter::FromIterator;

use rama_http_types::{HeaderName, HeaderValue};

use self::sealed::AsConnectionOption;
use crate::util::FlatCsv;

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
/// ```
///
/// # Examples
///
/// ```
/// use rama_http_headers::Connection;
///
/// let keep_alive = Connection::keep_alive();
/// ```
// This is frequently just 1 or 2 values, so optimize for that case.
#[derive(Clone, Debug)]
pub struct Connection(FlatCsv);

derive_header! {
    Connection(_),
    name: CONNECTION
}

impl Connection {
    /// A constructor to easily create a `Connection: close` header.
    #[inline]
    #[must_use]
    pub fn close() -> Self {
        Self(HeaderValue::from_static("close").into())
    }

    /// Returns true if this [`Connection`] header contains `close`.
    #[inline]
    pub fn contains_close(&self) -> bool {
        self.contains("close")
    }

    /// A constructor to easily create a `Connection: keep-alive` header.
    #[inline]
    #[must_use]
    pub fn keep_alive() -> Self {
        Self(HeaderValue::from_static("keep-alive").into())
    }

    /// Returns true if this [`Connection`] header contains `keep-alive`.
    #[inline]
    pub fn contains_keep_alive(&self) -> bool {
        self.contains("keep-alive")
    }

    /// A constructor to easily create a `Connection: Upgrade` header.
    #[inline]
    #[must_use]
    pub fn upgrade() -> Self {
        Self(HeaderValue::from_static("upgrade").into())
    }

    /// Returns true if this [`Connection`] header contains `Upgrade`.
    #[inline]
    pub fn contains_upgrade(&self) -> bool {
        self.contains("upgrade")
    }

    /// Check if this header contains a given "connection option".
    ///
    /// This can be used with various argument types:
    ///
    /// - `&str`
    /// - `&HeaderName`
    /// - `HeaderName`
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http_types::header::UPGRADE;
    /// use rama_http_headers::Connection;
    ///
    /// let conn = Connection::keep_alive();
    ///
    /// assert!(!conn.contains("close"));
    /// assert!(!conn.contains(UPGRADE));
    /// assert!(conn.contains("keep-alive"));
    /// assert!(conn.contains("Keep-Alive"));
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn contains(&self, name: impl AsConnectionOption) -> bool {
        let s = name.as_connection_option();
        self.0.iter().any(|opt| opt.eq_ignore_ascii_case(s))
    }
}

impl FromIterator<HeaderName> for Connection {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        let flat = iter.into_iter().map(HeaderValue::from).collect();
        Self(flat)
    }
}

mod sealed {
    use rama_http_types::HeaderName;

    pub trait AsConnectionOption: Sealed {
        fn as_connection_option(&self) -> &str;
    }
    pub trait Sealed {}

    impl AsConnectionOption for &str {
        fn as_connection_option(&self) -> &str {
            self
        }
    }

    impl Sealed for &str {}

    impl AsConnectionOption for &HeaderName {
        fn as_connection_option(&self) -> &str {
            self.as_ref()
        }
    }

    impl Sealed for &HeaderName {}

    impl AsConnectionOption for HeaderName {
        fn as_connection_option(&self) -> &str {
            self.as_ref()
        }
    }

    impl Sealed for HeaderName {}
}
