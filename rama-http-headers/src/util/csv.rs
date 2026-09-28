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
    split_quoted(string, ',').filter_map(|x| match x.trim() {
        "" => None,
        y => Some(y.parse().map_err(|_e| Error::invalid())),
    })
}

/// Split `s` on `sep`, ignoring any `sep` within double quotes.
pub(crate) fn split_quoted(s: &str, sep: char) -> impl Iterator<Item = &str> {
    let mut in_quotes = false;
    s.split(move |c| {
        if c == '"' {
            in_quotes = !in_quotes;
        }
        c == sep && !in_quotes
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_quoted_ignores_separators_within_quotes() {
        for (input, sep, expected) in [
            ("a, b,c", ',', vec!["a", " b", "c"]),
            (
                r#"foo="bar,baz", x=1"#,
                ',',
                vec![r#"foo="bar,baz""#, " x=1"],
            ),
            (
                r#"a="x;y"; b; "c""#,
                ';',
                vec![r#"a="x;y""#, " b", r#" "c""#],
            ),
            (
                r#""unterminated, still quoted"#,
                ',',
                vec![r#""unterminated, still quoted"#],
            ),
            ("", ',', vec![""]),
        ] {
            assert_eq!(split_quoted(input, sep).collect::<Vec<_>>(), expected);
        }
    }
}
