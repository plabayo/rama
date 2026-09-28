use std::fmt::Display;
use std::str::FromStr;

use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::HeaderValue;
use rama_utils::collections::{NonEmptySmallVec, NonEmptyVec};

use super::csv::split_quoted;

/// Header value which is either any `*` or
/// the given values separated by the defined separator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValuesOrAny<T> {
    /// The specific values as defined in order.
    Values(NonEmptyVec<T>),
    /// The any `*` value, also referred to as "wildcard".
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) enum FlatCsvSeparator {
    #[default]
    Comma,
    SemiColon,
}

impl FlatCsvSeparator {
    fn as_byte(self) -> u8 {
        match self {
            Self::Comma => b',',
            Self::SemiColon => b';',
        }
    }

    fn as_char(self) -> char {
        match self {
            Self::Comma => ',',
            Self::SemiColon => ';',
        }
    }
}

/// Parse each flat CSV value, skipping header values which are not valid utf-8.
fn parse_flat_csv<'a, T>(
    values: impl IntoIterator<Item = &'a HeaderValue>,
    sep: FlatCsvSeparator,
) -> impl Iterator<Item = Result<T, BoxError>>
where
    T: FromStr<Err: Into<BoxError>>,
{
    let sep = sep.as_char();
    values
        .into_iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(move |s| split_quoted(s, sep))
        .map(str::trim)
        .map(|s| s.parse().context("parse header value CSV colum from str"))
}

pub(crate) fn try_decode_flat_csv_header_values_as_non_empty_vec<'a, T>(
    values: impl IntoIterator<Item = &'a HeaderValue>,
    sep: FlatCsvSeparator,
) -> Result<NonEmptyVec<T>, BoxError>
where
    T: FromStr<Err: Into<BoxError>>,
{
    let mut iter = parse_flat_csv(values, sep);
    let mut vec = NonEmptyVec::new(iter.next().context("header value is an empty (CSV?)")??);
    for value in iter {
        vec.push(value?);
    }
    Ok(vec)
}

pub(crate) fn try_encode_non_empty_vec_as_flat_csv_header_value<T>(
    values: &NonEmptyVec<T>,
    sep: FlatCsvSeparator,
) -> Result<HeaderValue, BoxError>
where
    T: Display,
{
    use std::io::Write as _;

    let mut v = Vec::new();

    let sep_byte = sep.as_byte();

    _ = write!(&mut v, "{}", values.head);

    for value in values.tail.iter() {
        v.push(sep_byte);
        v.push(b' ');
        _ = write!(&mut v, "{value}");
    }

    HeaderValue::try_from(v).context("turn encoded bytes into HeaderValue")
}

pub(crate) fn try_encode_non_empty_vec_of_bytes_as_flat_csv_header_value<T>(
    values: &NonEmptyVec<T>,
    sep: FlatCsvSeparator,
) -> Result<HeaderValue, BoxError>
where
    T: AsRef<[u8]>,
{
    let mut v = Vec::with_capacity(
        values
            .iter()
            .map(|value| value.as_ref().len())
            .sum::<usize>()
            + 2 * values.len(),
    );

    let sep_byte = sep.as_byte();

    v.extend(values.head.as_ref());

    for value in values.tail.iter() {
        v.push(sep_byte);
        v.push(b' ');
        v.extend(value.as_ref());
    }

    HeaderValue::try_from(v).context("turn encoded bytes into HeaderValue")
}

pub(crate) fn try_decode_flat_csv_header_values_as_non_empty_smallvec<'a, const N: usize, T>(
    values: impl IntoIterator<Item = &'a HeaderValue>,
    sep: FlatCsvSeparator,
) -> Result<NonEmptySmallVec<N, T>, BoxError>
where
    T: FromStr<Err: Into<BoxError>>,
{
    let mut iter = parse_flat_csv(values, sep);
    let mut vec = NonEmptySmallVec::new(iter.next().context("header value is an empty (CSV?)")??);
    for value in iter {
        vec.push(value?);
    }
    Ok(vec)
}

pub(crate) fn try_encode_non_empty_smallvec_as_flat_csv_header_value<const N: usize, T>(
    values: &NonEmptySmallVec<N, T>,
    sep: FlatCsvSeparator,
) -> Result<HeaderValue, BoxError>
where
    T: Display,
{
    use std::io::Write as _;

    let mut v = Vec::new();

    let sep_byte = sep.as_byte();

    _ = write!(&mut v, "{}", values.head);

    for value in values.tail.iter() {
        v.push(sep_byte);
        v.push(b' ');
        _ = write!(&mut v, "{value}");
    }

    HeaderValue::try_from(v).context("turn encoded bytes into HeaderValue")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_flat_csv_into_non_empty_vec() {
        for (header_values, separator, expected) in [
            (
                vec![HeaderValue::from_static("aaa, b; bb, ccc")],
                FlatCsvSeparator::SemiColon,
                non_empty_vec![String::from("aaa, b"), String::from("bb, ccc")],
            ),
            (
                vec![HeaderValue::from_static("aaa; b, bb; ccc")],
                FlatCsvSeparator::Comma,
                non_empty_vec![String::from("aaa; b"), String::from("bb; ccc")],
            ),
            (
                vec![HeaderValue::from_static("foo=\"bar,baz\", sherlock=holmes")],
                FlatCsvSeparator::Comma,
                non_empty_vec![
                    String::from("foo=\"bar,baz\""),
                    String::from("sherlock=holmes")
                ],
            ),
            (
                vec![
                    HeaderValue::from_static("foo=\"bar,baz\", sherlock=holmes"),
                    HeaderValue::from_static("answer=42"),
                ],
                FlatCsvSeparator::Comma,
                non_empty_vec![
                    String::from("foo=\"bar,baz\""),
                    String::from("sherlock=holmes"),
                    String::from("answer=42")
                ],
            ),
        ] {
            let values =
                try_decode_flat_csv_header_values_as_non_empty_vec(header_values.iter(), separator)
                    .unwrap();
            assert_eq!(expected, values);
        }
    }

    #[test]
    fn encode_non_empty_vec_as_flat_csv() {
        for (values, separator, expected) in [
            (
                non_empty_vec![String::from("aaa, b"), String::from("bb, ccc")],
                FlatCsvSeparator::SemiColon,
                "aaa, b; bb, ccc",
            ),
            (
                non_empty_vec![String::from("aaa; b"), String::from("bb; ccc")],
                FlatCsvSeparator::Comma,
                "aaa; b, bb; ccc",
            ),
            (
                non_empty_vec![
                    String::from("foo=\"bar,baz\""),
                    String::from("sherlock=holmes")
                ],
                FlatCsvSeparator::Comma,
                "foo=\"bar,baz\", sherlock=holmes",
            ),
        ] {
            let header_value =
                try_encode_non_empty_vec_as_flat_csv_header_value(&values, separator).unwrap();
            assert_eq!(expected, header_value.to_str().unwrap());
        }
    }
}
