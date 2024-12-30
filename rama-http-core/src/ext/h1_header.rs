use std::{borrow::Cow, collections::HashMap};

use bytes::Bytes;
use rama_http_types::{
    dep::http::{header::IntoIter, Extensions},
    header, HeaderMap, HeaderName, HeaderValue,
};

use super::{HeaderCaseMap, OriginalHeaderOrderNew};

pub struct H1HeaderDrainer {
    state: H1HeaderDrainerState,
}

struct HeaderMapValueRemover<T = HeaderValue> {
    header_map: HeaderMap<T>,
    removed_values: HashMap<HeaderName, Vec<T>>,
}

impl<T> From<HeaderMap<T>> for HeaderMapValueRemover<T> {
    fn from(value: HeaderMap<T>) -> Self {
        Self {
            header_map: value,
            removed_values: Default::default(),
        }
    }
}

impl<T> HeaderMapValueRemover<T> {
    fn remove(&mut self, header: &HeaderName) -> Option<T> {
        match self.header_map.entry(header) {
            header::Entry::Occupied(occupied_entry) => {
                let (k, mut values) = occupied_entry.remove_entry_mult();
                match values.next() {
                    Some(v) => {
                        let mut values: Vec<_> = values.collect();
                        if !values.is_empty() {
                            values.reverse();
                            self.removed_values.insert(k, values);
                        }
                        Some(v)
                    }
                    None => None,
                }
            }
            header::Entry::Vacant(_) => self.removed_values.get_mut(header).and_then(|v| v.pop()),
        }
    }

    fn into_iter(mut self) -> IntoIter<T> {
        for (k, mut values) in self.removed_values {
            match self.header_map.entry(k) {
                header::Entry::Occupied(mut occupied_entry) => {
                    values.reverse();
                    for value in values {
                        occupied_entry.append(value);
                    }
                }
                header::Entry::Vacant(vacant_entry) => {
                    if let Some(v) = values.pop() {
                        let mut occupied_entry = vacant_entry.insert_entry(v);
                        values.reverse();
                        for value in values {
                            occupied_entry.append(value);
                        }
                    }
                }
            }
        }
        self.header_map.into_iter()
    }
}

impl H1HeaderDrainer {
    pub fn new(header_map: HeaderMap, ext: &mut Extensions) -> H1HeaderDrainer {
        let header_casing = ext.remove().unwrap_or_else(HeaderCaseMap::default);
        let state = match ext.remove::<OriginalHeaderOrderNew>() {
            Some(header_order) => H1HeaderDrainerState::InOrder {
                header_map: header_map.into(),
                header_order_iter: header_order.0.into_iter(),
                header_casing: header_casing.0.into(),
            },
            None => H1HeaderDrainerState::Rem {
                header_iter: header_map.into_iter(),
                header_casing: header_casing.0.into(),
            },
        };
        H1HeaderDrainer { state }
    }
}

pub enum H1HeaderKey {
    Name(HeaderName),
    Raw(Bytes),
}

impl H1HeaderKey {
    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            H1HeaderKey::Name(header_name) => header_name.as_str().into(),
            H1HeaderKey::Raw(bytes) => String::from_utf8_lossy(bytes),
        }
    }
}

enum H1HeaderDrainerState {
    InOrder {
        header_map: HeaderMapValueRemover,
        header_order_iter: std::vec::IntoIter<HeaderName>,
        header_casing: HeaderMapValueRemover<Bytes>,
    },
    Rem {
        header_iter: IntoIter<HeaderValue>,
        header_casing: HeaderMapValueRemover<Bytes>,
    },
    Empty,
}

impl Iterator for H1HeaderDrainer {
    type Item = (Option<H1HeaderKey>, HeaderValue);

    fn next(&mut self) -> Option<Self::Item> {
        let (state, result) = match std::mem::replace(&mut self.state, H1HeaderDrainerState::Empty)
        {
            H1HeaderDrainerState::InOrder {
                header_map,
                header_order_iter,
                header_casing,
            } => h1_drain_next_in_order(header_map, header_order_iter, header_casing),
            H1HeaderDrainerState::Rem {
                header_iter,
                header_casing,
            } => h1_drain_next_from_rem(header_iter, header_casing),
            H1HeaderDrainerState::Empty => (H1HeaderDrainerState::Empty, None),
        };
        self.state = state;
        result
    }
}

fn h1_drain_next_in_order(
    mut header_map: HeaderMapValueRemover,
    mut header_order_iter: std::vec::IntoIter<HeaderName>,
    mut header_casing: HeaderMapValueRemover<Bytes>,
) -> (
    H1HeaderDrainerState,
    Option<(Option<H1HeaderKey>, HeaderValue)>,
) {
    loop {
        match header_order_iter.next() {
            Some(header) => match header_map.remove(&header) {
                Some(value) => {
                    let result = Some((
                        Some(
                            header_casing
                                .remove(&header)
                                .map(H1HeaderKey::Raw)
                                .unwrap_or(H1HeaderKey::Name(header)),
                        ),
                        value,
                    ));
                    return (
                        H1HeaderDrainerState::InOrder {
                            header_map,
                            header_order_iter,
                            header_casing,
                        },
                        result,
                    );
                }
                None => continue,
            },
            None => {
                let header_iter = header_map.into_iter();
                return h1_drain_next_from_rem(header_iter, header_casing);
            }
        }
    }
}

fn h1_drain_next_from_rem(
    mut header_iter: IntoIter<HeaderValue>,
    mut header_casing: HeaderMapValueRemover<Bytes>,
) -> (
    H1HeaderDrainerState,
    Option<(Option<H1HeaderKey>, HeaderValue)>,
) {
    let result = match header_iter.next() {
        Some((Some(header), value)) => Some((
            Some(
                header_casing
                    .remove(&header)
                    .map(H1HeaderKey::Raw)
                    .unwrap_or(H1HeaderKey::Name(header)),
            ),
            value,
        )),
        Some((None, value)) => Some((None, value)),
        None => return (H1HeaderDrainerState::Empty, None),
    };
    (
        H1HeaderDrainerState::Rem {
            header_iter,
            header_casing,
        },
        result,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let mut drain = H1HeaderDrainer::new(Default::default(), &mut Default::default());
        assert!(drain.next().is_none());
    }

    macro_rules! _add_extra_headers {
        (
            $map:ident,
            {}
        ) => {
            {
                let extra: Option<Vec<String>> = None;
                (extra, $map)
            }
        };
        (
            $map:ident,
            {
                $($name:literal: $value:literal),*
                $(,)?
            }
        ) => {
            {
                let mut $map = $map;
                let mut extra = vec![];
                $(
                    $map.append($name.to_lowercase().parse::<HeaderName>().unwrap(), $value.parse().unwrap());
                    extra.push(format!("{}: {}", $name.to_lowercase(), $value));
                )*
                (Some(extra), $map)
            }
        };
    }

    macro_rules! test_req {
            ({$(
                $name:literal: $value:literal
            ),+ $(,)?}, $extra_headers:tt) => {
            {
                let order = OriginalHeaderOrderNew(vec![$($name.to_lowercase().parse::<HeaderName>().unwrap()),+]);
                let mut header_casing = HeaderCaseMap::default();
                $(
                    header_casing.append($name.to_lowercase().parse::<HeaderName>().unwrap(), $name.into());
                )+

                let mut ext = Extensions::new();
                ext.insert(order);
                ext.insert(header_casing);

                let header_map = HeaderMap::from_iter([
                    $(
                        (
                            $name.to_lowercase().parse().unwrap(),
                            HeaderValue::from_str($value).unwrap(),
                        ),
                    )+
                ]);
                let (extra_headers, header_map ) = _add_extra_headers!(header_map, $extra_headers);

                let mut drain = H1HeaderDrainer::new(header_map, &mut ext);
                let mut last_header_name: Option<String> = None;

                let mut next = || {
                    drain.next().map(|(name, value)| {
                        let header_name = match name {
                            Some(name) => name.as_str().to_string(),
                            None => last_header_name.take().unwrap(),
                        };
                        let s = format!(
                            "{}: {}",
                            header_name,
                            String::from_utf8_lossy(value.as_bytes()),
                        );
                        last_header_name = Some(header_name);
                        s
                    })
                };

                $(
                    assert_eq!(Some(format!("{}: {}", $name, $value)), next());
                )+

                match extra_headers {
                    Some(extra_headers) => {
                        for extra in extra_headers {
                            assert_eq!(Some(extra), next())
                        }
                    },
                    None => assert_eq!(None, next()),
                }
            }
        };
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
