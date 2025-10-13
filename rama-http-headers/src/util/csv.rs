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

pub(crate) fn split_csv_str<T: std::str::FromStr>(
    string: &str,
) -> impl Iterator<Item = Result<T, Error>> + use<'_, T> {
    let mut in_quotes = false;
    string
        .split(move |c| {
            #[allow(clippy::collapsible_else_if)]
            if in_quotes {
                if c == '"' {
                    in_quotes = false;
                }
                false // dont split
            } else {
                if c == ',' {
                    true // split
                } else {
                    if c == '"' {
                        in_quotes = true;
                    }
                    false // dont split
                }
            }
        })
        .filter_map(|x| match x.trim() {
            "" => None,
            y => Some(y.parse().map_err(|_| Error::invalid())),
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
