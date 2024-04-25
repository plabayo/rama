//! CSV utilities
//! lifted from <https://github.com/hyperium/headers/blob/1b4efe2e9faac3d96ddfb9347c2028477663f01d/src/util/csv.rs>
//! until relevant PRs get merged that rely on this internal utility.

use std::fmt;

use crate::http::headers::Error;
use crate::http::HeaderValue;

/// Reads a comma-delimited raw header into a Vec.
pub(crate) fn from_comma_delimited<'i, I, T, E>(values: &mut I) -> Result<E, Error>
where
    I: Iterator<Item = &'i HeaderValue>,
    T: ::std::str::FromStr,
    E: ::std::iter::FromIterator<T>,
{
    values
        .flat_map(|value| {
            value.to_str().into_iter().flat_map(|string| {
                string
                    .split(',')
                    .filter_map(|x| match x.trim() {
                        "" => None,
                        y => Some(y),
                    })
                    .map(|x| x.parse().map_err(|_| Error::invalid()))
            })
        })
        .collect()
}

/// Format an array into a comma-delimited string.
pub(crate) fn fmt_comma_delimited<T: fmt::Display>(
    f: &mut fmt::Formatter,
    mut iter: impl Iterator<Item = T>,
) -> fmt::Result {
    if let Some(part) = iter.next() {
        fmt::Display::fmt(&part, f)?;
    }
    for part in iter {
        f.write_str(", ")?;
        fmt::Display::fmt(&part, f)?;
    }
    Ok(())
}
