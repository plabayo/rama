use std::fmt;

use rama_http_types::HeaderValue;

use crate::Error;

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
    let mut in_quotes = false;
    let mut escaped = false;
    string
        .split(move |c| {
            // a quoted-pair never closes the quoted-string (RFC 9110 §5.6.4)
            if escaped {
                escaped = false;
            } else if in_quotes {
                match c {
                    '\\' => escaped = true,
                    '"' => in_quotes = false,
                    _ => {}
                }
            } else if c == '"' {
                in_quotes = true;
            } else {
                return c == ',';
            }
            false
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
