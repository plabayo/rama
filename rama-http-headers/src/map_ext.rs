use rama_http_types::{HeaderValue, header, header::AsHeaderName};

use crate::{HeaderDecode, HeaderEncode};

use super::Error;

/// An extension trait adding "typed" methods to `http::HeaderMap`.
pub trait HeaderMapExt: self::sealed::Sealed {
    /// Inserts the typed header into this `HeaderMap`.
    fn typed_insert<H>(&mut self, header: H)
    where
        H: HeaderEncode;

    /// Tries to find the header by name, and then decode it into `H`.
    fn typed_get<H>(&self) -> Option<H>
    where
        H: HeaderDecode;

    /// Tries to find the header by name, and then decode it into `H`.
    fn typed_try_get<H>(&self) -> Result<Option<H>, Error>
    where
        H: HeaderDecode;

    /// Remove every value associated with a header name and return how many
    /// were removed.
    ///
    /// Note: `HeaderMap::remove` already removes the whole entry (all
    /// values) for a header — it just *returns* only the first value as
    /// `Option<HeaderValue>`. This method gives callers an accurate count
    /// without needing to call `HeaderMap::get_all` manually beforehand.
    /// Use [`remove_all_values`](Self::remove_all_values) when the values
    /// themselves are needed.
    fn remove_all<K>(&mut self, name: K) -> usize
    where
        K: AsHeaderName + Clone;

    /// Remove every value associated with a header name and return them in
    /// iteration order.
    ///
    /// Useful when you need to inspect, log, or relocate the removed
    /// values — `HeaderMap::remove` only surfaces the first.
    fn remove_all_values<K>(&mut self, name: K) -> Vec<HeaderValue>
    where
        K: AsHeaderName + Clone;
}

impl HeaderMapExt for rama_http_types::HeaderMap {
    fn typed_insert<H>(&mut self, header: H)
    where
        H: HeaderEncode,
    {
        let entry = self.entry(H::name());
        let mut values = ToValues {
            state: State::First(entry),
        };
        header.encode(&mut values);
    }

    fn typed_get<H>(&self) -> Option<H>
    where
        H: HeaderDecode,
    {
        HeaderMapExt::typed_try_get(self).unwrap_or(None)
    }

    fn typed_try_get<H>(&self) -> Result<Option<H>, Error>
    where
        H: HeaderDecode,
    {
        let mut values = self.get_all(H::name()).iter();
        if values.size_hint() == (0, Some(0)) {
            Ok(None)
        } else {
            H::decode(&mut values).map(Some)
        }
    }

    fn remove_all<K>(&mut self, name: K) -> usize
    where
        K: AsHeaderName + Clone,
    {
        // `HeaderMap::remove` removes the whole entry; count separately
        // because it only surfaces the first value.
        let count = self.get_all(name.clone()).iter().count();
        self.remove(name);
        count
    }

    fn remove_all_values<K>(&mut self, name: K) -> Vec<HeaderValue>
    where
        K: AsHeaderName + Clone,
    {
        // Collect every value first, then drop the entry in one call.
        let values: Vec<HeaderValue> = self.get_all(name.clone()).iter().cloned().collect();
        self.remove(name);
        values
    }
}

struct ToValues<'a> {
    state: State<'a>,
}

#[derive(Debug)]
enum State<'a> {
    First(header::Entry<'a, HeaderValue>),
    Latter(header::OccupiedEntry<'a, HeaderValue>),
    Tmp,
}

impl Extend<HeaderValue> for ToValues<'_> {
    fn extend<T: IntoIterator<Item = HeaderValue>>(&mut self, iter: T) {
        for value in iter {
            let entry = match ::std::mem::replace(&mut self.state, State::Tmp) {
                State::First(header::Entry::Occupied(mut e)) => {
                    e.insert(value);
                    e
                }
                State::First(header::Entry::Vacant(e)) => e.insert_entry(value),
                State::Latter(mut e) => {
                    e.append(value);
                    e
                }
                State::Tmp => unreachable!("ToValues State::Tmp"),
            };
            self.state = State::Latter(entry);
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for ::rama_http_types::HeaderMap {}
}

#[cfg(test)]
mod test {
    use super::*;
    use rama_http_types::HeaderMap;

    #[test]
    fn test_remove_all_drops_every_value() {
        let mut map = HeaderMap::new();
        map.append(header::CONTENT_LENGTH, HeaderValue::from(42u64));
        map.append(header::CONTENT_LENGTH, HeaderValue::from(99u64));
        map.append(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

        let removed = map.remove_all(&header::CONTENT_LENGTH);
        assert_eq!(removed, 2);
        assert!(!map.contains_key(header::CONTENT_LENGTH));
        assert_eq!(
            map.get(header::CONTENT_TYPE).unwrap().as_bytes(),
            b"text/plain"
        );
    }

    #[test]
    fn test_remove_all_returns_zero_when_absent() {
        let mut map = HeaderMap::new();
        map.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(map.remove_all(&header::CONTENT_LENGTH), 0);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_remove_all_values_collects_in_order() {
        let mut map = HeaderMap::new();
        map.append(header::CONTENT_LENGTH, HeaderValue::from(1u64));
        map.append(header::CONTENT_LENGTH, HeaderValue::from(2u64));
        map.append(header::CONTENT_LENGTH, HeaderValue::from(3u64));

        let values = map.remove_all_values(&header::CONTENT_LENGTH);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0].to_str().unwrap(), "1");
        assert_eq!(values[1].to_str().unwrap(), "2");
        assert_eq!(values[2].to_str().unwrap(), "3");
        assert!(!map.contains_key(header::CONTENT_LENGTH));
    }
}
