use rama_http_types::{HeaderValue, header};

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
