//! `Content-Disposition: form-data` parameters of a part (RFC 7578 §4.2).

use rama_http_types::{HeaderMap, header::CONTENT_DISPOSITION};
use std::fmt;

/// The parameters of a `form-data` disposition that name a part.
#[derive(Debug, Default)]
pub struct FormData {
    name: Option<Box<str>>,
    file_name: Option<Box<str>>,
}

/// The value is not a well-formed `form-data` disposition.
#[derive(Debug)]
#[non_exhaustive]
pub struct InvalidContentDisposition;

impl fmt::Display for InvalidContentDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid `form-data` content disposition")
    }
}

impl std::error::Error for InvalidContentDisposition {}

impl FormData {
    /// Parse a `Content-Disposition` value of a `multipart/form-data` part.
    ///
    /// Values are tokens or quoted strings holding UTF-8. Within quotes `\"` and
    /// `\\` are unescaped and any other backslash is literal, so a legacy full
    /// path survives; percent-encoding is left as sent, a file can carry `%22` in
    /// its name. `filename*` is ignored (RFC 7578 §4.2), it never overrides
    /// `filename`. A repeated `name` or `filename` is rejected (RFC 6266 §4.1).
    pub fn parse(value: &[u8]) -> Result<Self, InvalidContentDisposition> {
        parse(value)
    }

    /// Read the disposition of a part from its headers.
    ///
    /// A part without the header has neither a name nor a file name; one with
    /// the header repeated is rejected.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, InvalidContentDisposition> {
        let mut values = headers.get_all(CONTENT_DISPOSITION).iter();
        match (values.next(), values.next()) {
            (None, _) => Ok(Self::default()),
            (Some(value), None) => parse(value.as_bytes()),
            (Some(_), Some(_)) => Err(InvalidContentDisposition),
        }
    }

    /// The `name` parameter.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The `filename` parameter as the client sent it: it can be a full path
    /// or hold `..` segments.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.file_name.as_deref()
    }

    /// Split into the `name` and `filename` parameters.
    #[must_use]
    pub fn into_parts(self) -> (Option<Box<str>>, Option<Box<str>>) {
        (self.name, self.file_name)
    }
}

fn parse(value: &[u8]) -> Result<FormData, InvalidContentDisposition> {
    let (kind, mut rest) = split_token(value);
    if !kind.eq_ignore_ascii_case(b"form-data") {
        return Err(InvalidContentDisposition);
    }

    let mut form_data = FormData::default();
    loop {
        rest = rest.trim_ascii_start();
        let Some(after) = rest.strip_prefix(b";") else {
            return if rest.is_empty() {
                Ok(form_data)
            } else {
                Err(InvalidContentDisposition)
            };
        };
        rest = after.trim_ascii_start();
        if rest.is_empty() {
            return Ok(form_data);
        }

        let (param, after) = split_token(rest);
        let after = after.strip_prefix(b"=").ok_or(InvalidContentDisposition)?;
        if param.is_empty() {
            return Err(InvalidContentDisposition);
        }
        let (value, after) = if let Some(quoted) = after.strip_prefix(b"\"") {
            split_quoted(quoted)?
        } else {
            let (token, after) = split_token(after);
            (token.to_vec(), after)
        };
        rest = after;

        let slot = if param.eq_ignore_ascii_case(b"name") {
            &mut form_data.name
        } else if param.eq_ignore_ascii_case(b"filename") {
            &mut form_data.file_name
        } else {
            continue;
        };
        if slot.is_some() {
            return Err(InvalidContentDisposition);
        }
        let value = String::from_utf8(value).map_err(|_e| InvalidContentDisposition)?;
        *slot = Some(value.into_boxed_str());
    }
}

/// Split at the first byte that ends a token: whitespace, `;`, `=` or `"`.
fn split_token(input: &[u8]) -> (&[u8], &[u8]) {
    let end = input
        .iter()
        .position(|b| matches!(b, b' ' | b'\t' | b';' | b'=' | b'"'))
        .unwrap_or(input.len());
    input.split_at(end)
}

/// Read a quoted string past its opening quote; returns its content and what follows the
/// closing quote.
fn split_quoted(input: &[u8]) -> Result<(Vec<u8>, &[u8]), InvalidContentDisposition> {
    let mut value = Vec::with_capacity(input.len().min(64));
    let mut bytes = input.iter().enumerate();
    while let Some((at, &byte)) = bytes.next() {
        match byte {
            b'"' => return Ok((value, &input[at + 1..])),
            b'\\' => match input.get(at + 1) {
                Some(&escaped @ (b'"' | b'\\')) => {
                    value.push(escaped);
                    bytes.next();
                }
                _ => value.push(byte),
            },
            _ => value.push(byte),
        }
    }
    Err(InvalidContentDisposition)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(value: &str) -> Option<(Option<String>, Option<String>)> {
        parse(value.as_bytes()).ok().map(|form_data| {
            (
                form_data.name.map(Into::into),
                form_data.file_name.map(Into::into),
            )
        })
    }

    fn some(
        name: Option<&str>,
        file_name: Option<&str>,
    ) -> Option<(Option<String>, Option<String>)> {
        Some((name.map(Into::into), file_name.map(Into::into)))
    }

    #[test]
    fn name_and_file_name() {
        for (value, name, file_name) in [
            ("form-data", None, None),
            ("form-data;", None, None),
            ("form-data; name=\"a\"", Some("a"), None),
            ("form-data; name=a", Some("a"), None),
            ("form-data;name=a;filename=b.txt", Some("a"), Some("b.txt")),
            (
                "FORM-DATA; NAME=\"a\"; FileName=\"b\"",
                Some("a"),
                Some("b"),
            ),
            (
                "form-data ; name=\"a\" ; filename=\"b\" ;",
                Some("a"),
                Some("b"),
            ),
            (
                "form-data; filename=\"b\"; name=\"a\"",
                Some("a"),
                Some("b"),
            ),
            ("form-data; name=\"\"; filename=\"\"", Some(""), Some("")),
            ("form-data; name=; filename=b", Some(""), Some("b")),
            ("form-data; name=\"a b; c=d\"", Some("a b; c=d"), None),
            (
                "form-data; name=\"r\u{e9}sum\u{e9}\"",
                Some("r\u{e9}sum\u{e9}"),
                None,
            ),
            ("form-data; name=a; other=x; x-y=\"z\"", Some("a"), None),
        ] {
            assert_eq!(names(value), some(name, file_name), "{value:?}");
        }
    }

    #[test]
    fn quoting() {
        for (value, file_name) in [
            (r#"form-data; filename="we\"ird.txt""#, r#"we"ird.txt"#),
            (r#"form-data; filename="back\\slash""#, r"back\slash"),
            (r#"form-data; filename="C:\dir\x.txt""#, r"C:\dir\x.txt"),
            (r#"form-data; filename="trailing\\""#, r"trailing\"),
            (r#"form-data; filename="a%22b%0D%0Ac""#, "a%22b%0D%0Ac"),
            (r#"form-data; filename="../../x""#, "../../x"),
            (
                r#"form-data; filename="=?UTF-8?B?w6k=?=""#,
                "=?UTF-8?B?w6k=?=",
            ),
        ] {
            assert_eq!(names(value), some(None, Some(file_name)), "{value:?}");
        }
    }

    #[test]
    fn extended_file_name_never_wins() {
        for (value, file_name) in [
            ("form-data; filename*=UTF-8''b.php", None),
            (
                "form-data; filename=\"a.txt\"; filename*=UTF-8''b.php",
                Some("a.txt"),
            ),
            (
                "form-data; filename*=UTF-8''b.php; filename=\"a.txt\"",
                Some("a.txt"),
            ),
            ("form-data; name*=UTF-8''b; filename=a.txt", Some("a.txt")),
        ] {
            assert_eq!(names(value), some(None, file_name), "{value:?}");
        }
    }

    #[test]
    fn malformed_values_are_rejected() {
        for value in [
            "",
            "attachment; name=\"a\"",
            "form-datax; name=\"a\"",
            "name=\"a\"",
            "form-data name=\"a\"",
            "form-data; name",
            "form-data; name; filename=b",
            "form-data; =a",
            "form-data; name =a",
            "form-data; name= a",
            "form-data; name=\"a",
            "form-data; name=\"a\\\"",
            "form-data; name=\"a\"b",
            "form-data; name=a\"b\"",
            "form-data; name=a=b",
            "form-data; name=\"a\"; name=\"b\"",
            "form-data; name=a; NAME=a",
            "form-data; filename=a; filename=\"b\"",
            "form-data, name=a",
        ] {
            assert_eq!(names(value), None, "{value:?}");
        }
        parse(b"form-data; name=\"\xff\"").unwrap_err();
        parse(b"form-data; filename=\xc3").unwrap_err();
        // bytes of a parameter that is not read need not be UTF-8
        parse(b"form-data; name=a; other=\"\xff\"").unwrap();
    }
}
