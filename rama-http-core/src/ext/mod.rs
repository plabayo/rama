//! HTTP extensions.

use bytes::Bytes;
use rama_http_types::header::HeaderName;
use rama_http_types::header::{HeaderMap, IntoHeaderName, ValueIter};
use std::collections::HashMap;
use std::fmt;

mod h1_reason_phrase;
pub use h1_reason_phrase::ReasonPhrase;

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    inner: crate::h2::ext::Protocol,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            inner: crate::h2::ext::Protocol::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    pub(crate) fn from_inner(inner: crate::h2::ext::Protocol) -> Self {
        Self { inner }
    }

    pub(crate) fn into_inner(self) -> crate::h2::ext::Protocol {
        self.inner
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            inner: crate::h2::ext::Protocol::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// A map from header names to their original casing as received in an HTTP message.
///
/// If an HTTP/1 response `res` is parsed on a connection whose option
/// [`preserve_header_case`] was set to true and the response included
/// the following headers:
///
/// ```text
/// x-Bread: Baguette
/// X-BREAD: Pain
/// x-bread: Ficelle
/// ```
///
/// Then `res.extensions().get::<HeaderCaseMap>()` will return a map with:
///
/// ```text
/// HeaderCaseMap({
///     "x-bread": ["x-Bread", "X-BREAD", "x-bread"],
/// })
/// ```
///
/// [`preserve_header_case`]: /client/struct.Client.html#method.preserve_header_case
#[derive(Clone, Debug)]
pub(crate) struct HeaderCaseMap(HeaderMap<Bytes>);

impl HeaderCaseMap {
    /// Returns a view of all spellings associated with that header name,
    /// in the order they were found.
    pub(crate) fn get_all<'a>(
        &'a self,
        name: &HeaderName,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        self.get_all_internal(name)
    }

    /// Returns a view of all spellings associated with that header name,
    /// in the order they were found.
    pub(crate) fn get_all_internal(&self, name: &HeaderName) -> ValueIter<'_, Bytes> {
        self.0.get_all(name).into_iter()
    }

    pub(crate) fn default() -> Self {
        Self(Default::default())
    }

    #[allow(dead_code)]
    pub(crate) fn insert(&mut self, name: HeaderName, orig: Bytes) {
        self.0.insert(name, orig);
    }

    pub(crate) fn append<N>(&mut self, name: N, orig: Bytes)
    where
        N: IntoHeaderName,
    {
        self.0.append(name, orig);
    }
}

#[derive(Clone, Debug, Default)]
/// Hashmap<Headername, numheaders with that name>
pub struct OriginalHeaderOrder {
    /// Stores how many entries a Headername maps to. This is used
    /// for accounting.
    num_entries: HashMap<HeaderName, usize>,
    /// Stores the ordering of the headers. ex: `vec[i] = (headerName, idx)`,
    /// The vector is ordered such that the ith element
    /// represents the ith header that came in off the line.
    /// The `HeaderName` and `idx` are then used elsewhere to index into
    /// the multi map that stores the header values.
    entry_order: Vec<(HeaderName, usize)>,
}

impl OriginalHeaderOrder {
    pub fn insert(&mut self, name: HeaderName) {
        if !self.num_entries.contains_key(&name) {
            let idx = 0;
            self.num_entries.insert(name.clone(), 1);
            self.entry_order.push((name, idx));
        }
        // Replacing an already existing element does not
        // change ordering, so we only care if its the first
        // header name encountered
    }

    pub fn append<N>(&mut self, name: N)
    where
        N: IntoHeaderName + Into<HeaderName> + Clone,
    {
        let name: HeaderName = name.into();
        let idx;
        if self.num_entries.contains_key(&name) {
            idx = self.num_entries[&name];
            *self.num_entries.get_mut(&name).unwrap() += 1;
        } else {
            idx = 0;
            self.num_entries.insert(name.clone(), 1);
        }
        self.entry_order.push((name, idx));
    }

    /// This returns an iterator that provides header names and indexes
    /// in the original order received.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_http_core::ext::OriginalHeaderOrder;
    /// use rama_http_types::header::{HeaderName, HeaderValue, HeaderMap};
    ///
    /// let mut h_order = OriginalHeaderOrder::default();
    /// let mut h_map = HeaderMap::new();
    ///
    /// let name1 = HeaderName::try_from("Set-CookiE").expect("valid Set-CookiE header name");
    /// let value1 = HeaderValue::from_static("a=b");
    /// h_map.append(name1.clone(), value1);
    /// h_order.append(name1);
    ///
    /// let name2 = HeaderName::try_from("Content-Encoding").expect("valid Content-Encoding header name");
    /// let value2 = HeaderValue::from_static("gzip");
    /// h_map.append(name2.clone(), value2);
    /// h_order.append(name2);
    ///
    /// let name3 = HeaderName::try_from("SET-COOKIE").expect("valid SET-COOKIE header name");
    /// let value3 = HeaderValue::from_static("c=d");
    /// h_map.append(name3.clone(), value3);
    /// h_order.append(name3);
    ///
    /// let mut iter = h_order.get_in_order();
    ///
    /// let (name, idx) = iter.next().unwrap();
    /// assert_eq!("a=b", h_map.get_all(name).iter().nth(*idx).expect("get set-cookie header value"));
    ///
    /// let (name, idx) = iter.next().unwrap();
    /// assert_eq!("gzip", h_map.get_all(name).iter().nth(*idx).expect("get content-encoding header value"));
    ///
    /// let (name, idx) = iter.next().unwrap();
    /// assert_eq!("c=d", h_map.get_all(name).iter().nth(*idx).expect("get SET-COOKIE header value"));
    /// ```
    pub fn get_in_order(&self) -> impl Iterator<Item = &(HeaderName, usize)> {
        self.entry_order.iter()
    }
}
