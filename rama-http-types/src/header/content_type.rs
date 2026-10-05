//! The `Content-Type` a recipient acts on, read as browsers do, so a proxy or server agrees
//! with them:
//!
//! - [`extract_mime_type`] and [`extract_essence`] read a response as browsers do: WHATWG Fetch's
//!   lenient "extract a MIME type" (§3.5) over every field line.
//! - [`parse_essence`] and [`parse_mime_type`] judge a request as the CORS safelist does: MIME
//!   Sniffing's "parse a MIME type" (§4.4) over the whole value. A decision that gates a request uses it, as the lenient
//!   reading finds `application/json` in a `text/plain;,application/json` sent without preflight.

use std::borrow::Cow;

use rama_utils::collections::smallvec::SmallVec;

use crate::{HeaderValue, header::is_token, mime::Mime};

/// The extracted type with its parameters, `None` when no line holds a valid one.
///
/// A parameter is left out unless it re-encodes to the octets it came from: printable ASCII
/// without a quote or backslash, and not empty.
pub fn extract_mime_type<'i>(lines: impl IntoIterator<Item = &'i HeaderValue>) -> Option<Mime> {
    let value = combined(lines)?;
    let (winner, inherited_charset) = extract(&value)?;
    let mut parameters = winner.parameters();
    if let Some(charset) = inherited_charset {
        parameters.push(("charset", charset));
    }
    to_mime(winner.essence, &parameters)
}

/// The `type/subtype` of the extracted type, as sent: all a decision on the media type needs,
/// without allocating for one line.
pub fn extract_essence<'i>(
    lines: impl IntoIterator<Item = &'i HeaderValue>,
) -> Option<Cow<'i, str>> {
    match combined(lines)? {
        Cow::Borrowed(value) => last_valid(value).map(|winner| Cow::Borrowed(winner.essence)),
        Cow::Owned(value) => last_valid(&value).map(|winner| Cow::Owned(winner.essence.to_owned())),
    }
}

/// The `type/subtype` of the whole value as one media type, as sent: what the CORS safelist
/// judges, so a request is gated on the type its sender was allowed to send.
pub fn parse_essence<'i>(lines: impl IntoIterator<Item = &'i HeaderValue>) -> Option<Cow<'i, str>> {
    match combined(lines)? {
        Cow::Borrowed(value) => Candidate::parse(value).map(|parsed| Cow::Borrowed(parsed.essence)),
        Cow::Owned(value) => {
            Candidate::parse(&value).map(|parsed| Cow::Owned(parsed.essence.to_owned()))
        }
    }
}

/// The whole value as one media type with the parameters the `mime` crate can hold, see
/// [`parse_essence`].
pub fn parse_mime_type<'i>(lines: impl IntoIterator<Item = &'i HeaderValue>) -> Option<Mime> {
    let value = combined(lines)?;
    let parsed = Candidate::parse(&value)?;
    to_mime(parsed.essence, &parsed.parameters())
}

/// The lines as the one value they combine to (Fetch's "get"), isomorphic decoded.
fn combined<'i>(lines: impl IntoIterator<Item = &'i HeaderValue>) -> Option<Cow<'i, str>> {
    let mut lines = lines.into_iter();
    let first = isomorphic_decode(lines.next()?.as_bytes());
    let Some(second) = lines.next() else {
        return Some(first);
    };
    let mut combined = first.into_owned();
    for line in std::iter::once(second).chain(lines) {
        combined.push_str(", ");
        combined.push_str(&isomorphic_decode(line.as_bytes()));
    }
    Some(Cow::Owned(combined))
}

/// Each byte as the code point of the same value, as Fetch decodes field values.
fn isomorphic_decode(bytes: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(bytes) {
        Ok(ascii) if bytes.is_ascii() => Cow::Borrowed(ascii),
        _ => Cow::Owned(bytes.iter().copied().map(char::from).collect()),
    }
}

fn last_valid(value: &str) -> Option<Candidate<'_>> {
    split_outside_quotes(value)
        .filter_map(Candidate::parse)
        .filter(|candidate| candidate.essence != "*/*")
        .last()
}

/// The last valid type and the charset it inherits from an earlier one of the same essence.
fn extract(value: &str) -> Option<(Candidate<'_>, Option<Cow<'_, str>>)> {
    let mut winner: Option<Candidate<'_>> = None;
    let mut essence_from: Option<Candidate<'_>> = None;
    let mut inherits = false;
    for candidate in split_outside_quotes(value).filter_map(Candidate::parse) {
        if candidate.essence == "*/*" {
            continue;
        }
        let same_essence =
            winner.is_some_and(|winner| winner.essence.eq_ignore_ascii_case(candidate.essence));
        if same_essence {
            inherits = candidate.charset().is_none();
        } else {
            essence_from = Some(candidate);
            inherits = false;
        }
        winner = Some(candidate);
    }
    let winner = winner?;
    let charset = inherits
        .then(|| essence_from.and_then(Candidate::charset))
        .flatten();
    Some((winner, charset))
}

/// A type MIME Sniffing accepts: a token type and subtype; its parameters never fail it.
#[derive(Clone, Copy)]
struct Candidate<'a> {
    /// `type/subtype` as sent.
    essence: &'a str,
    /// What follows the subtype, from its first `;`.
    parameters: &'a str,
}

impl<'a> Candidate<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        let value = value.trim_matches(HTTP_WHITESPACE);
        let (kind, rest) = value.split_once('/')?;
        let (subtype, parameters) = rest.split_at(rest.find(';').unwrap_or(rest.len()));
        let subtype = subtype.trim_end_matches(HTTP_WHITESPACE);
        if !is_token(kind.as_bytes()) || !is_token(subtype.as_bytes()) {
            return None;
        }
        Some(Self {
            essence: &value[..kind.len() + 1 + subtype.len()],
            parameters,
        })
    }

    fn charset(self) -> Option<Cow<'a, str>> {
        self.parameters()
            .into_iter()
            .find_map(|(name, value)| name.eq_ignore_ascii_case("charset").then_some(value))
    }

    /// The parameters MIME Sniffing keeps: a token name, a value of quoted-string token code
    /// points, the first of a repeated name.
    fn parameters(self) -> SmallVec<[(&'a str, Cow<'a, str>); 4]> {
        let input = self.parameters;
        let bytes = input.as_bytes();
        let mut parameters: SmallVec<[(&'a str, Cow<'a, str>); 4]> = SmallVec::new();
        let mut position = 0;
        while position < bytes.len() {
            // At a `;`.
            position += 1;
            while bytes
                .get(position)
                .is_some_and(|b| HTTP_WHITESPACE_BYTES.contains(b))
            {
                position += 1;
            }
            let name_start = position;
            while bytes
                .get(position)
                .is_some_and(|b| *b != b';' && *b != b'=')
            {
                position += 1;
            }
            let name = &input[name_start..position];
            match bytes.get(position) {
                Some(b';') => continue,
                Some(_) => position += 1,
                None => break,
            }
            if position >= bytes.len() {
                break;
            }
            let value = if bytes[position] == b'"' {
                let (value, end) = collect_quoted_string(input, position);
                position = end;
                while bytes.get(position).is_some_and(|b| *b != b';') {
                    position += 1;
                }
                value
            } else {
                let value_start = position;
                while bytes.get(position).is_some_and(|b| *b != b';') {
                    position += 1;
                }
                let value = input[value_start..position].trim_end_matches(HTTP_WHITESPACE);
                if value.is_empty() {
                    continue;
                }
                Cow::Borrowed(value)
            };
            if is_token(name.as_bytes())
                && value.chars().all(is_quoted_string_token_code_point)
                && !parameters
                    .iter()
                    .any(|(known, _)| known.eq_ignore_ascii_case(name))
            {
                parameters.push((name, value));
            }
        }
        parameters
    }
}

/// HTTP whitespace as MIME Sniffing and Fetch use it.
const HTTP_WHITESPACE: [char; 4] = [' ', '\t', '\n', '\r'];
const HTTP_WHITESPACE_BYTES: [u8; 4] = [b' ', b'\t', b'\n', b'\r'];

fn is_quoted_string_token_code_point(c: char) -> bool {
    matches!(c, '\t' | ' '..='~' | '\u{80}'..='\u{ff}')
}

/// Fetch's "collect an HTTP quoted string" with the extract-value flag set, from the `"` at
/// `position`: its value and the position after it.
fn collect_quoted_string(input: &str, mut position: usize) -> (Cow<'_, str>, usize) {
    position += 1;
    let mut value: Cow<'_, str> = Cow::Borrowed("");
    loop {
        let start = position;
        while input
            .as_bytes()
            .get(position)
            .is_some_and(|b| *b != b'"' && *b != b'\\')
        {
            position += 1;
        }
        append(&mut value, &input[start..position]);
        let Some(&quote_or_backslash) = input.as_bytes().get(position) else {
            break;
        };
        position += 1;
        if quote_or_backslash == b'"' {
            break;
        }
        match input[position..].chars().next() {
            Some(escaped) => {
                value.to_mut().push(escaped);
                position += escaped.len_utf8();
            }
            None => {
                value.to_mut().push('\\');
                break;
            }
        }
    }
    (value, position)
}

fn append<'a>(value: &mut Cow<'a, str>, part: &'a str) {
    if value.is_empty() {
        *value = Cow::Borrowed(part);
    } else if !part.is_empty() {
        value.to_mut().push_str(part);
    }
}

/// `essence` with the `parameters` the `mime` crate can hold, quoted where they need it.
fn to_mime(essence: &str, parameters: &[(&str, Cow<'_, str>)]) -> Option<Mime> {
    if parameters.is_empty() {
        return essence.parse().ok();
    }
    let mut serialized = String::with_capacity(essence.len() + 16 * parameters.len());
    serialized.push_str(essence);
    for (name, value) in parameters {
        let quoted = !is_token(value.as_bytes());
        // `mime` holds a quoted value raw: UTF-8 or a backslash would not re-encode as sent.
        if quoted
            && (value.is_empty()
                || !value
                    .bytes()
                    .all(|b| (b' '..=b'~').contains(&b) && b != b'"' && b != b'\\'))
        {
            continue;
        }
        serialized.push_str("; ");
        serialized.push_str(name);
        serialized.push('=');
        if quoted {
            serialized.push('"');
            serialized.push_str(value);
            serialized.push('"');
        } else {
            serialized.push_str(value);
        }
    }
    serialized.parse().ok().or_else(|| essence.parse().ok())
}

/// Fetch's "split" of a field value: on commas outside quoted strings, trimming HTTP tab or
/// space around each part.
fn split_outside_quotes(value: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(value);
    std::iter::from_fn(move || {
        let input = rest?;
        let bytes = input.as_bytes();
        let (mut quoted, mut escaped) = (false, false);
        let mut end = bytes.len();
        for (index, byte) in bytes.iter().enumerate() {
            match (quoted, escaped, byte) {
                (true, true, _) => escaped = false,
                (true, false, b'\\') => escaped = true,
                (_, _, b'"') => quoted = !quoted,
                (false, _, b',') => {
                    end = index;
                    break;
                }
                _ => {}
            }
        }
        rest = input.get(end + 1..).filter(|_| end < bytes.len());
        Some(input[..end].trim_matches([' ', '\t']))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mime;

    fn values(lines: &[&str]) -> Vec<HeaderValue> {
        lines
            .iter()
            .map(|line| HeaderValue::from_str(line).unwrap())
            .collect()
    }

    /// The examples of Fetch's "extract a MIME type" (§3.5), one field line per entry.
    #[test]
    fn several_lines_extract_the_mime_type_as_fetch_does() {
        for (lines, essence, charset, x) in [
            (
                &["text/plain;charset=gbk, text/html"][..],
                "text/html",
                None,
                None,
            ),
            (
                &["text/html;charset=gbk;a=b, text/html;x=y"],
                "text/html",
                Some("gbk"),
                Some("y"),
            ),
            (
                &["text/html;charset=gbk;a=b", "text/html;x=y"],
                "text/html",
                Some("gbk"),
                Some("y"),
            ),
            (
                &["text/html;charset=gbk", "x/x", "text/html;x=y"],
                "text/html",
                None,
                Some("y"),
            ),
            (&["text/html", "cannot-parse"], "text/html", None, None),
            (&["text/html", "*/*"], "text/html", None, None),
            (&["text/html", ""], "text/html", None, None),
            (&["text/html", "x/"], "text/html", None, None),
            // A comma inside a quoted parameter value does not split.
            (
                &[r#"text/html;x=",text/plain""#],
                "text/html",
                None,
                Some(",text/plain"),
            ),
            // The inherited charset is set as a parameter, after a trailing `;` too.
            (
                &["text/html;charset=gbk", "text/html;x=y;"],
                "text/html",
                Some("gbk"),
                Some("y"),
            ),
            // A same-essence type with its own charset keeps it and does not pass it on.
            (
                &[
                    "text/html;charset=gbk",
                    "text/html;charset=utf-8",
                    "text/html",
                ],
                "text/html",
                Some("gbk"),
                None,
            ),
        ] {
            let mime = extract_mime_type(&values(lines)).unwrap();
            assert_eq!(mime.essence_str(), essence, "{lines:?}");
            assert_eq!(
                mime.get_param(mime::CHARSET).map(|value| value.as_str()),
                charset,
                "{lines:?}"
            );
            assert_eq!(
                mime.get_param("x").map(|value| value.as_str()),
                x,
                "{lines:?}"
            );
            assert_eq!(
                extract_essence(&values(lines)).as_deref(),
                Some(essence),
                "{lines:?}"
            );
        }
        for lines in [
            &[][..],
            &["cannot-parse"],
            &["*/*"],
            &[""],
            &["x/"],
            &["/x"],
        ] {
            assert!(extract_mime_type(&values(lines)).is_none(), "{lines:?}");
            assert!(extract_essence(&values(lines)).is_none(), "{lines:?}");
        }
    }

    /// MIME Sniffing's "parse a MIME type" (§4.4): only the type and subtype can fail it.
    #[test]
    fn parameters_never_fail_a_type() {
        for (line, essence, parameters) in [
            (
                "application/x-www-form-urlencoded ; charset=UTF-8",
                "application/x-www-form-urlencoded",
                &[("charset", "utf-8")][..],
            ),
            ("text/html;;x=1", "text/html", &[("x", "1")]),
            ("text/html;\tx=1", "text/html", &[("x", "1")]),
            ("text/html;charset", "text/html", &[]),
            ("text/html;charset=", "text/html", &[]),
            ("text/html;x=a@b", "text/html", &[("x", "a@b")]),
            ("text/html;x=\"a b\"", "text/html", &[("x", "a b")]),
            // The `mime` crate holds no escaped quote: left out.
            ("text/html;x=\"a\\\"b\";y=2", "text/html", &[("y", "2")]),
            // Nor a backslash, which a re-encoded value would turn into an escape.
            ("text/html;x=\"a\\\\b\";y=2", "text/html", &[("y", "2")]),
            (
                "text/html;x=\"unterminated",
                "text/html",
                &[("x", "unterminated")],
            ),
            ("TEXT/HTML;X=1;x=2", "text/html", &[("x", "1")]),
            // Nor a tab or an empty quoted value: only that parameter is left out.
            (
                "multipart/form-data; boundary=abc; x=\"\"",
                "multipart/form-data",
                &[("boundary", "abc")],
            ),
            (
                "multipart/form-data; x=\"a\tb\"; boundary=abc",
                "multipart/form-data",
                &[("boundary", "abc")],
            ),
            (
                "multipart/form-data; boundary=AaB03x",
                "multipart/form-data",
                &[("boundary", "AaB03x")],
            ),
        ] {
            let mime = extract_mime_type(&values(&[line])).unwrap();
            assert_eq!(mime.essence_str(), essence, "{line}");
            let kept: Vec<_> = mime
                .params()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            assert_eq!(kept, parameters, "{line}");
        }
    }

    #[test]
    fn one_line_essence_borrows() {
        let values = values(&["Text/HTML; charset=utf-8"]);
        assert!(matches!(
            extract_essence(&values),
            Some(Cow::Borrowed("Text/HTML"))
        ));
    }

    #[test]
    fn values_are_isomorphic_decoded() {
        let values = [
            HeaderValue::from_static("text/html"),
            HeaderValue::from_bytes(b"text/\xffplain").unwrap(),
        ];
        assert_eq!(
            extract_mime_type(&values).unwrap().essence_str(),
            "text/html"
        );
        // `\xff` is a valid code point, so nothing is inherited; as UTF-8 it would not re-encode.
        let values = [
            HeaderValue::from_static("text/html;charset=gbk"),
            HeaderValue::from_bytes(b"text/html;charset=\xff").unwrap(),
        ];
        let mime = extract_mime_type(&values).unwrap();
        assert_eq!(mime.essence_str(), "text/html");
        assert_eq!(mime.get_param(mime::CHARSET), None);
        let values = [HeaderValue::from_bytes(b"text/plain; name=\"caf\xe9.txt\"; x=1").unwrap()];
        let mime = extract_mime_type(&values).unwrap();
        assert_eq!(mime.get_param("name"), None);
        assert_eq!(mime.get_param("x").map(|value| value.as_str()), Some("1"));
    }

    /// A request is judged as the CORS safelist judges it: the whole value as one type.
    #[test]
    fn parsing_judges_the_whole_value_as_one_type() {
        for (lines, essence) in [
            (&["application/json"][..], Some("application/json")),
            (
                &["Application/JSON ; charset=utf-8"],
                Some("Application/JSON"),
            ),
            // Safelisted as `text/plain`, so never JSON.
            (&["text/plain;,application/json"], Some("text/plain")),
            (&["text/plain;a=b", "application/json"], Some("text/plain")),
            (&["application/json", "application/json"], None),
            (&["text/plain, application/json"], None),
            (&["x/"], None),
            (&[], None),
        ] {
            assert_eq!(
                parse_essence(&values(lines)).as_deref(),
                essence,
                "{lines:?}"
            );
        }
        let mime = parse_mime_type(&values(&["Text/Plain; charset=utf-8;,application/json"]));
        assert_eq!(mime.as_ref().map(Mime::essence_str), Some("text/plain"));
        assert_eq!(
            mime.as_ref()
                .and_then(|mime| mime.get_param(mime::CHARSET))
                .map(|value| value.as_str()),
            Some("utf-8")
        );
        assert_eq!(
            extract_essence(&values(&["text/plain;,application/json"])).as_deref(),
            Some("application/json"),
            "a response is read leniently"
        );
    }
}
