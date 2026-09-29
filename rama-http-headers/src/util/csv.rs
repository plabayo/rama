use std::{fmt, iter};

use rama_http_types::HeaderValue;

use crate::{Error, util::skip_quoted};

/// Reads a comma-delimited raw header into a Vec.
pub fn from_comma_delimited<'i, I, T, E>(values: &mut I) -> Result<E, Error>
where
    I: Iterator<Item = &'i HeaderValue>,
    T: std::str::FromStr,
    E: FromIterator<T>,
{
    values
        .flat_map(|value| {
            value
                .to_str()
                .into_iter()
                .flat_map(|string| split_csv_str(string))
        })
        .collect()
}

/// Split on `,` outside quoted-strings; an unterminated one runs to the end.
pub(crate) fn split_csv_str<T: std::str::FromStr>(
    string: &str,
) -> impl Iterator<Item = Result<T, Error>> + use<'_, T> {
    let bytes = string.as_bytes();
    let mut start = Some(0_usize);
    // `,` and `"` are ASCII, so every cut keeps a char boundary
    iter::from_fn(move || {
        let from = start.take()?;
        let mut cursor = from;
        loop {
            let found = bytes
                .get(cursor..)
                .unwrap_or_default()
                .iter()
                .position(|byte| matches!(byte, b',' | b'"'))
                .map(|offset| cursor.saturating_add(offset));
            match found {
                Some(end) if bytes.get(end) == Some(&b',') => {
                    start = Some(end.saturating_add(1));
                    return Some(string.get(from..end).unwrap_or_default());
                }
                // a quoted-pair never closes the quoted-string (RFC 9110 §5.6.4)
                Some(quote) => match skip_quoted(bytes, quote) {
                    Some(next) => cursor = next,
                    None => return Some(string.get(from..).unwrap_or_default()),
                },
                None => return Some(string.get(from..).unwrap_or_default()),
            }
        }
    })
    .filter_map(|x| match x.trim() {
        "" => None,
        y => Some(y.parse().map_err(|_e| Error::invalid())),
    })
}

/// Format an array into a comma-delimited string.
pub fn fmt_comma_delimited<T: fmt::Display>(
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
