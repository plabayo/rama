use std::fmt::Display;
use std::str::{self, FromStr};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::HeaderValue;
use rama_utils::collections::{NonEmptySmallVec, NonEmptyVec};

use crate::util::{ListMembers, trim_ows};

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
}

/// Visit trimmed list members of all values, skipping empty ones (RFC 9110 §5.6.1.2).
fn for_each_flat_csv_member<'a, T>(
    values: impl IntoIterator<Item = &'a HeaderValue>,
    sep: FlatCsvSeparator,
    mut f: impl FnMut(T),
) -> Result<(), BoxError>
where
    T: FromStr<Err: Into<BoxError>>,
{
    for value in values {
        match sep {
            // quoted-strings may hold separators and quoted-pairs (RFC 9110 §5.6.4)
            FlatCsvSeparator::Comma => {
                let s = value
                    .to_str()
                    .context("header value is not a valid utf-8 str")?;
                for member in ListMembers::new(s.as_bytes()) {
                    visit_flat_csv_member(member?, &mut f)?;
                }
            }
            // split on every `;` (RFC 6265 §4.2.1), skipping only an unreadable cookie-pair
            FlatCsvSeparator::SemiColon => {
                for member in value.as_bytes().split(|byte| *byte == b';') {
                    if member
                        .iter()
                        .all(|byte| matches!(byte, b' '..=b'~' | b'\t'))
                    {
                        visit_flat_csv_member(member, &mut f)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn visit_flat_csv_member<T>(member: &[u8], f: &mut impl FnMut(T)) -> Result<(), BoxError>
where
    T: FromStr<Err: Into<BoxError>>,
{
    let member = trim_ows(member);
    if member.is_empty() {
        return Ok(());
    }
    let member = str::from_utf8(member).context("header value CSV colum is not utf-8")?;
    f(member
        .parse::<T>()
        .context("parse header value CSV colum from str")?);
    Ok(())
}

pub(crate) fn try_decode_flat_csv_header_values_as_non_empty_vec<'a, T>(
    values: impl IntoIterator<Item = &'a HeaderValue>,
    sep: FlatCsvSeparator,
) -> Result<NonEmptyVec<T>, BoxError>
where
    T: FromStr<Err: Into<BoxError>>,
{
    let mut vec: Option<NonEmptyVec<T>> = None;
    for_each_flat_csv_member(values, sep, |value| match &mut vec {
        Some(vec) => vec.push(value),
        None => vec = Some(NonEmptyVec::new(value)),
    })?;
    vec.context("header value is an empty (CSV?)")
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
    let mut v = Vec::with_capacity(values.iter().fold(0usize, |len, value| {
        len.saturating_add(value.as_ref().len()).saturating_add(2)
    }));

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
    let mut vec: Option<NonEmptySmallVec<N, T>> = None;
    for_each_flat_csv_member(values, sep, |value| match &mut vec {
        Some(vec) => vec.push(value),
        None => vec = Some(NonEmptySmallVec::new(value)),
    })?;
    vec.context("header value is an empty (CSV?)")
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
    use crate::util::for_each_small_input;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_flat_csv_rejects_non_utf8_value() {
        let values = [
            HeaderValue::from_static("a"),
            HeaderValue::from_bytes(b"b\xff").unwrap(),
        ];
        try_decode_flat_csv_header_values_as_non_empty_vec::<String>(
            &values,
            FlatCsvSeparator::Comma,
        )
        .unwrap_err();
    }

    #[test]
    fn decode_flat_csv_skips_empty_members() {
        let values = [
            HeaderValue::from_static(", a,, b ,"),
            HeaderValue::from_static(""),
        ];
        let result: NonEmptyVec<String> =
            try_decode_flat_csv_header_values_as_non_empty_vec(&values, FlatCsvSeparator::Comma)
                .unwrap();
        assert_eq!(result, non_empty_vec![String::from("a"), String::from("b")]);

        for values in [&[""][..], &[" , "], &["", ","]] {
            let values: Vec<_> = values.iter().map(|v| HeaderValue::from_static(v)).collect();
            try_decode_flat_csv_header_values_as_non_empty_vec::<String>(
                &values,
                FlatCsvSeparator::Comma,
            )
            .unwrap_err();
        }
    }

    #[test]
    fn decode_flat_csv_comma_honours_quoted_pairs() {
        let values = [HeaderValue::from_static(r#"a;p="x\",y", b"#)];
        let result: NonEmptyVec<String> =
            try_decode_flat_csv_header_values_as_non_empty_vec(&values, FlatCsvSeparator::Comma)
                .unwrap();
        assert_eq!(
            result,
            non_empty_vec![String::from(r#"a;p="x\",y""#), String::from("b")]
        );

        let values = [HeaderValue::from_static(r#"a;p="x, b"#)];
        try_decode_flat_csv_header_values_as_non_empty_vec::<String>(
            &values,
            FlatCsvSeparator::Comma,
        )
        .unwrap_err();
    }

    #[test]
    fn decode_flat_csv_semicolon_ignores_quotes() {
        let values = [HeaderValue::from_static(r#"a="x; b=y"; c=1"#)];
        let result: NonEmptyVec<String> = try_decode_flat_csv_header_values_as_non_empty_vec(
            &values,
            FlatCsvSeparator::SemiColon,
        )
        .unwrap();
        assert_eq!(
            result,
            non_empty_vec![
                String::from(r#"a="x"#),
                String::from(r#"b=y""#),
                String::from("c=1")
            ]
        );
    }

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
    fn decode_small_inputs_never_panic() {
        for_each_small_input(b"\",; a\x80", 6, |input| {
            let Ok(value) = HeaderValue::from_bytes(input) else {
                return;
            };
            for sep in [FlatCsvSeparator::Comma, FlatCsvSeparator::SemiColon] {
                if let Ok(values) = try_decode_flat_csv_header_values_as_non_empty_vec::<String>(
                    [&value, &value],
                    sep,
                ) {
                    _ = try_encode_non_empty_vec_as_flat_csv_header_value(&values, sep);
                    _ = try_encode_non_empty_vec_of_bytes_as_flat_csv_header_value(&values, sep);
                }
                if let Ok(values) = try_decode_flat_csv_header_values_as_non_empty_smallvec::<
                    2,
                    String,
                >([&value], sep)
                {
                    _ = try_encode_non_empty_smallvec_as_flat_csv_header_value(&values, sep);
                }
            }
        });
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
