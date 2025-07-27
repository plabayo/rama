use std::{
    borrow::Cow,
    collections::{self, HashMap},
};

use crate::header::AsHeaderName;
use serde::{Deserialize, Serialize, de::Error as _, ser::Error as _};

use super::{
    Http1HeaderName,
    name::{IntoHttp1HeaderName, IntoSealed as _, TryIntoHttp1HeaderName},
    original::{self, OriginalHttp1Headers},
};

use crate::{
    HeaderMap, HeaderName, HeaderValue, Request,
    dep::http::Extensions,
    header::{self, InvalidHeaderName},
};

#[derive(Debug, Clone, Default)]
pub struct Http1HeaderMap {
    headers: HeaderMap,
    original_headers: OriginalHttp1Headers,
}

impl Http1HeaderMap {
    #[must_use]
    pub fn with_capacity(size: usize) -> Self {
        Self {
            headers: HeaderMap::with_capacity(size),
            original_headers: OriginalHttp1Headers::with_capacity(size),
        }
    }

    #[must_use]
    pub fn from_parts(headers: HeaderMap, original_headers: OriginalHttp1Headers) -> Self {
        Self {
            headers,
            original_headers,
        }
    }

    pub fn copy_from_req<B>(req: &Request<B>) -> Self {
        let headers = req.headers().clone();
        let original_headers = req.extensions().get().cloned().unwrap_or_default();
        Self {
            headers,
            original_headers,
        }
    }

    #[must_use]
    pub fn new(headers: HeaderMap, ext: Option<&mut Extensions>) -> Self {
        let original_headers = ext.and_then(|ext| ext.remove()).unwrap_or_default();
        Self {
            headers,
            original_headers,
        }
    }

    #[inline]
    pub fn get(&self, key: impl AsHeaderName) -> Option<&HeaderValue> {
        self.headers.get(key)
    }

    pub fn get_original_name(&self, key: &HeaderName) -> Option<&Http1HeaderName> {
        self.original_headers
            .iter()
            .find(|header| header.header_name() == key)
    }

    #[inline]
    pub fn contains_key(&self, key: impl AsHeaderName) -> bool {
        self.headers.contains_key(key)
    }

    #[must_use]
    pub fn into_headers(self) -> HeaderMap {
        self.headers
    }

    /// use [`Self::into_headers`] if you do not care about
    /// the original headers.
    pub fn consume(self, ext: &mut Extensions) -> HeaderMap {
        ext.insert(self.original_headers);
        self.headers
    }

    #[must_use]
    pub fn into_parts(self) -> (HeaderMap, OriginalHttp1Headers) {
        (self.headers, self.original_headers)
    }

    pub fn append(&mut self, name: impl IntoHttp1HeaderName, value: HeaderValue) {
        let original_header = name.into_http1_header_name();
        let header_name = original_header.header_name();
        self.headers.append(header_name, value);
        self.original_headers.push(original_header);
    }

    pub fn try_append(
        &mut self,
        name: impl TryIntoHttp1HeaderName,
        value: HeaderValue,
    ) -> Result<(), InvalidHeaderName> {
        let original_header = name.try_into_http1_header_name()?;
        let header_name = original_header.header_name();
        self.headers.append(header_name, value);
        self.original_headers.push(original_header);
        Ok(())
    }
}

impl From<HeaderMap> for Http1HeaderMap {
    fn from(value: HeaderMap) -> Self {
        Self {
            headers: value,
            ..Default::default()
        }
    }
}

impl From<Http1HeaderMap> for HeaderMap {
    fn from(value: Http1HeaderMap) -> Self {
        value.headers
    }
}

impl<N: IntoHttp1HeaderName> FromIterator<(N, HeaderValue)> for Http1HeaderMap {
    fn from_iter<T: IntoIterator<Item = (N, HeaderValue)>>(iter: T) -> Self {
        let mut map: Self = Default::default();
        for (name, value) in iter {
            map.append(name, value);
        }
        map
    }
}

impl IntoIterator for Http1HeaderMap {
    type Item = (Http1HeaderName, HeaderValue);
    type IntoIter = Http1HeaderMapIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        if self.original_headers.is_empty() {
            return Http1HeaderMapIntoIter {
                state: Http1HeaderMapIntoIterState::Rem(
                    HeaderMapValueRemover::from(self.headers).into_iter(),
                ),
            };
        }

        Http1HeaderMapIntoIter {
            state: Http1HeaderMapIntoIterState::Original {
                original_iter: self.original_headers.into_iter(),
                headers: self.headers.into(),
            },
        }
    }
}

impl Serialize for Http1HeaderMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let headers: Result<Vec<_>, _> = self
            .clone()
            .into_iter()
            .map(|(name, value)| {
                let value = value.to_str().map_err(S::Error::custom)?;
                Ok::<_, S::Error>((name, value.to_owned()))
            })
            .collect();
        headers?.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Http1HeaderMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let headers = <Vec<(Http1HeaderName, Cow<'de, str>)>>::deserialize(deserializer)?;
        headers
            .into_iter()
            .map(|(name, value)| {
                Ok::<_, D::Error>((
                    name,
                    HeaderValue::from_str(&value).map_err(D::Error::custom)?,
                ))
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct Http1HeaderMapIntoIter {
    state: Http1HeaderMapIntoIterState,
}

#[derive(Debug)]
enum Http1HeaderMapIntoIterState {
    Original {
        original_iter: original::IntoIter,
        headers: HeaderMapValueRemover,
    },
    Rem(HeaderMapValueRemoverIntoIter),
    Empty,
}

impl Iterator for Http1HeaderMapIntoIter {
    type Item = (Http1HeaderName, HeaderValue);

    fn next(&mut self) -> Option<Self::Item> {
        match std::mem::replace(&mut self.state, Http1HeaderMapIntoIterState::Empty) {
            Http1HeaderMapIntoIterState::Original {
                mut original_iter,
                mut headers,
            } => loop {
                if let Some(http1_header_name) = original_iter.next() {
                    if let Some(value) = headers.remove(http1_header_name.header_name()) {
                        let next = Some((http1_header_name, value));
                        self.state = Http1HeaderMapIntoIterState::Original {
                            original_iter,
                            headers,
                        };
                        return next;
                    }
                } else {
                    let mut it = headers.into_iter();
                    let next = it.next();
                    self.state = Http1HeaderMapIntoIterState::Rem(it);
                    return next;
                }
            },
            Http1HeaderMapIntoIterState::Rem(mut it) => {
                let next = it.next()?;
                self.state = Http1HeaderMapIntoIterState::Rem(it);
                Some(next)
            }
            Http1HeaderMapIntoIterState::Empty => None,
        }
    }
}

#[derive(Debug)]
/// Utility that can be used to be able to remove
/// headers from an [`HeaderMap`] in random order, one by one.
pub struct HeaderMapValueRemover {
    header_map: HeaderMap,
    removed_values: Option<HashMap<HeaderName, std::vec::IntoIter<HeaderValue>>>,
}

impl From<HeaderMap> for HeaderMapValueRemover {
    fn from(value: HeaderMap) -> Self {
        Self {
            header_map: value,
            removed_values: None,
        }
    }
}

impl HeaderMapValueRemover {
    pub fn remove(&mut self, header: &HeaderName) -> Option<HeaderValue> {
        match self.header_map.entry(header) {
            header::Entry::Occupied(occupied_entry) => {
                let (k, mut values) = occupied_entry.remove_entry_mult();
                match values.next() {
                    Some(v) => {
                        let values: Vec<_> = values.collect();
                        if !values.is_empty() {
                            self.removed_values
                                .get_or_insert_with(Default::default)
                                .insert(k, values.into_iter());
                        }
                        Some(v)
                    }
                    None => None,
                }
            }
            header::Entry::Vacant(_) => self
                .removed_values
                .as_mut()
                .and_then(|m| m.get_mut(header))
                .and_then(|i| i.next()),
        }
    }
}

impl IntoIterator for HeaderMapValueRemover {
    type Item = (Http1HeaderName, HeaderValue);
    type IntoIter = HeaderMapValueRemoverIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        let removed_headers = self.removed_values.map(|r| r.into_iter());
        let remaining_headers = self.header_map.into_iter().peekable();
        HeaderMapValueRemoverIntoIter {
            cached_header_name: None,
            cached_headers: None,
            removed_headers,
            remaining_headers,
        }
    }
}

#[derive(Debug)]
/// Porduced by the [`IntoIterator`] implementation for [`HeaderMapValueRemover`].
pub struct HeaderMapValueRemoverIntoIter {
    cached_header_name: Option<HeaderName>,
    cached_headers: Option<std::iter::Peekable<std::vec::IntoIter<HeaderValue>>>,
    removed_headers:
        Option<collections::hash_map::IntoIter<HeaderName, std::vec::IntoIter<HeaderValue>>>,
    remaining_headers: std::iter::Peekable<header::IntoIter<HeaderValue>>,
}

impl Iterator for HeaderMapValueRemoverIntoIter {
    type Item = (Http1HeaderName, HeaderValue);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut it) = self.cached_headers.take() {
            if let Some(value) = it.next() {
                match if it.peek().is_some() {
                    self.cached_headers = Some(it);
                    self.cached_header_name.clone()
                } else {
                    self.cached_header_name.take()
                } {
                    Some(name) => {
                        return Some((name.into_http1_header_name(), value));
                    }
                    None => {
                        if cfg!(debug_assertions) {
                            panic!("no http header name found for multi-value header");
                        }
                    }
                }
            }
        }

        if let Some(removed_headers) = self.removed_headers.as_mut() {
            for removed_header in removed_headers {
                let mut cached_headers = removed_header.1.peekable();
                if cached_headers.peek().is_some() {
                    self.cached_header_name = Some(removed_header.0);
                    self.cached_headers = Some(cached_headers);
                    return self.next();
                }
            }
        }

        loop {
            let header = self.remaining_headers.next()?;
            match (header.0, self.cached_header_name.take()) {
                (Some(name), _) | (None, Some(name)) => {
                    if self
                        .remaining_headers
                        .peek()
                        .map(|h| h.0.is_none())
                        .unwrap_or_default()
                    {
                        self.cached_header_name = Some(name.clone());
                    }
                    return Some((name.into_http1_header_name(), header.1));
                }
                (None, None) => {
                    if cfg!(debug_assertions) {
                        panic!("no http header name found for multi-value header");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let mut drain = Http1HeaderMap::default().into_iter();
        assert!(drain.next().is_none());
    }

    macro_rules! _add_extra_headers {
        (
            $map:expr,
            {}
        ) => {
            {
                let extra: Option<Vec<String>> = None;
                extra
            }
        };
        (
            $map:expr,
            {
                $($name:literal: $value:literal),*
                $(,)?
            }
        ) => {
            {
                let mut extra = vec![];
                $(
                    $map.append($name.to_lowercase().parse::<HeaderName>().unwrap(), $value.parse().unwrap());
                    extra.push(format!("{}: {}", $name.to_lowercase(), $value));
                )*
                Some(extra)
            }
        };
    }

    macro_rules! test_req {
            ({$(
                $name:literal: $value:literal
            ),* $(,)?}, $extra_headers:tt) => {
            {
                let mut map = Http1HeaderMap::default();

                $(
                    map.try_append(
                        $name,
                        HeaderValue::from_str($value).unwrap()
                    ).unwrap();
                )*

                let extra_headers = _add_extra_headers!(&mut map.headers, $extra_headers);

                let mut drain = map.into_iter();

                let mut next = || {
                    drain.next().map(|(name, value)| {
                        let s = format!(
                            "{}: {}",
                            name,
                            String::from_utf8_lossy(value.as_bytes()),
                        );
                        s
                    })
                };

                $(
                    assert_eq!(Some(format!("{}: {}", $name, $value)), next());
                )*

                if let Some(extra_headers) = extra_headers {
                    for extra in extra_headers {
                        assert_eq!(Some(extra), next())
                    }
                }

                assert_eq!(None, next())
            }
        };
    }

    #[test]
    fn test_only_extra_1() {
        test_req!({}, {
            "content-type": "application/json",
        })
    }

    #[test]
    fn test_only_extra_2() {
        test_req!({}, {
            "content-type": "application/json",
            "content-length": "9",
        })
    }

    #[test]
    fn test_only_extra_2_manual_core_type() {
        let mut map = HeaderMap::new();
        map.insert(header::CONTENT_LENGTH, "123".parse().unwrap());
        map.insert(header::CONTENT_TYPE, "json".parse().unwrap());

        let mut iter = map.into_iter().peekable();
        let _ = iter.peek();
        assert_eq!(
            iter.next(),
            Some((Some(header::CONTENT_LENGTH), "123".parse().unwrap()))
        );
        let _ = iter.peek();
        assert_eq!(
            iter.next(),
            Some((Some(header::CONTENT_TYPE), "json".parse().unwrap()))
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_only_extra_2_manual_dummy_wrapper() {
        let mut map = HeaderMap::new();
        map.insert(header::CONTENT_LENGTH, "123".parse().unwrap());
        map.insert(header::CONTENT_TYPE, "json".parse().unwrap());

        let map: Http1HeaderMap = map.into();

        let mut iter = map.into_iter();
        assert_eq!(
            iter.next(),
            Some((
                header::CONTENT_LENGTH.into_http1_header_name(),
                "123".parse().unwrap()
            ))
        );
        assert_eq!(
            iter.next(),
            Some((
                header::CONTENT_TYPE.into_http1_header_name(),
                "json".parse().unwrap()
            ))
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_happy_case_perfect() {
        test_req!({
            "User-Agent": "curl/7.16.3",
            "Host": "curl/7.16.3",
            "Accept-Language": "en-us",
            "Connection": "Keep-Alive",
            "Content-Type": "application/json",
            "X-FOO": "BaR",
        }, {})
    }

    #[test]
    fn test_happy_case_perfect_extra_headers() {
        test_req!({
            "User-Agent": "curl/7.16.3",
            "Host": "curl/7.16.3",
            "Accept-Language": "en-us",
            "Connection": "Keep-Alive",
            "Content-Type": "application/json",
            "X-FOO": "BaR",
        }, {
            "x-Hello": "world",
        })
    }

    #[test]
    fn test_happy_case_with_repetition() {
        test_req!({
            "User-Agent": "curl/7.16.3",
            "Host": "curl/7.16.3",
            "Accept-Language": "en-us",
            "Connection": "Keep-Alive",
            "Accept-LANGuage": "NL-be",
            "Content-Type": "application/json",
            "Cookie": "a=1",
            "Cookie": "b=2",
            "X-FOO": "BaR",
        }, {})
    }

    #[test]
    fn test_happy_case_with_repetition_and_extra() {
        test_req!({
            "User-Agent": "curl/7.16.3",
            "Host": "curl/7.16.3",
            "Accept-Language": "en-us",
            "Connection": "Keep-Alive",
            "Accept-LANGuage": "NL-be",
            "Content-Type": "application/json",
            "Cookie": "a=1",
            "Cookie": "b=2",
            "X-FOO": "BaR",
        }, {
            "x-Hello": "world",
        })
    }
}
