use std::iter::FromIterator;

use rama_http_types::{HeaderValue, Method};

use crate::util::FlatCsv;

/// `Allow` header, defined in [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-7.4.1)
///
/// The `Allow` header field lists the set of methods advertised as
/// supported by the target resource.  The purpose of this field is
/// strictly to inform the recipient of valid request methods associated
/// with the resource.
///
/// # ABNF
///
/// ```text
/// Allow = #method
/// ```
///
/// # Example values
/// * `GET, HEAD, PUT`
/// * `OPTIONS, GET, PUT, POST, DELETE, HEAD, TRACE, CONNECT, PATCH, fOObAr`
/// * ``
///
/// # Examples
///
/// ```
/// use rama_http_headers::Allow;
/// use rama_http_types::Method;
///
/// let allow = vec![Method::GET, Method::POST]
///     .into_iter()
///     .collect::<Allow>();
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Allow(FlatCsv);

derive_header! {
    Allow(_),
    name: ALLOW
}

impl Allow {
    /// Returns an iterator over `Method`s contained within.
    pub fn iter(&self) -> impl Iterator<Item = Method> + '_ {
        self.0.iter().filter_map(|s| s.parse().ok())
    }
}

impl FromIterator<Method> for Allow {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Method>,
    {
        let flat = iter
            .into_iter()
            .map(|method| {
                method
                    .as_str()
                    .parse::<HeaderValue>()
                    .expect("Method is a valid HeaderValue")
            })
            .collect();
        Self(flat)
    }
}
