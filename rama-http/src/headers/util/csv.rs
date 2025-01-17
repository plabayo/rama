//! CSV utilities
//! lifted from <https://github.com/hyperium/headers/blob/1b4efe2e9faac3d96ddfb9347c2028477663f01d/src/util/csv.rs>
//! until relevant PRs get merged that rely on this internal utility.

use std::fmt;

use crate::headers::Error;
use crate::HeaderValue;

/// Reads a comma-delimited raw header into a Vec.
pub(crate) fn from_comma_delimited<'i, I, T, E>(values: &mut I) -> Result<E, Error>
where
    I: Iterator<Item = &'i HeaderValue>,
    T: std::str::FromStr,
    E: FromIterator<T>,
{
    values
        .flat_map(|value| {
            value.to_str().into_iter().flat_map(|string| {
                split_csv_str(string)
            })
        })
        .collect()
}

pub(crate) fn split_csv_str<T: std::str::FromStr>(
    string: &str,
) -> impl Iterator<Item = Result<T, Error>> + use<'_, T> {
    string.split(',').filter_map(|x| match x.trim() {
        "" => None,
        y => Some(y.parse().map_err(|_| Error::invalid())),
    })
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
