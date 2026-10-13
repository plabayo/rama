//! Character-reference decoding of attribute values, as browsers apply it
//! before the tree builder or a selector sees the value.
//!
//! Numeric references are decoded fully. Named references are decoded when
//! their text holds ASCII: only those can decide whether an ASCII value (an
//! `encoding` or `type` check, an ASCII selector) matches. Any other named
//! reference stays literal; where browsers see non-ASCII text, an ASCII needle
//! cannot match either way.

use std::borrow::Cow;

use memchr::memchr;

/// Named references with ASCII in their text, terminating `;` included.
const NAMED: &[(&[u8], &[u8])] = &[
    (b"Tab;", b"\t"),
    (b"NewLine;", b"\n"),
    (b"excl;", b"!"),
    (b"quot;", b"\""),
    (b"QUOT;", b"\""),
    (b"num;", b"#"),
    (b"dollar;", b"$"),
    (b"percnt;", b"%"),
    (b"amp;", b"&"),
    (b"AMP;", b"&"),
    (b"apos;", b"'"),
    (b"lpar;", b"("),
    (b"rpar;", b")"),
    (b"ast;", b"*"),
    (b"midast;", b"*"),
    (b"plus;", b"+"),
    (b"comma;", b","),
    (b"period;", b"."),
    (b"sol;", b"/"),
    (b"colon;", b":"),
    (b"semi;", b";"),
    (b"lt;", b"<"),
    (b"LT;", b"<"),
    (b"equals;", b"="),
    (b"gt;", b">"),
    (b"GT;", b">"),
    (b"quest;", b"?"),
    (b"commat;", b"@"),
    (b"lsqb;", b"["),
    (b"lbrack;", b"["),
    (b"bsol;", b"\\"),
    (b"rsqb;", b"]"),
    (b"rbrack;", b"]"),
    (b"Hat;", b"^"),
    (b"lowbar;", b"_"),
    (b"UnderBar;", b"_"),
    (b"grave;", b"`"),
    (b"DiacriticalGrave;", b"`"),
    (b"lcub;", b"{"),
    (b"lbrace;", b"{"),
    (b"verbar;", b"|"),
    (b"vert;", b"|"),
    (b"VerticalLine;", b"|"),
    (b"rcub;", b"}"),
    (b"rbrace;", b"}"),
    (b"fjlig;", b"fj"),
    (b"nvlt;", "<\u{20D2}".as_bytes()),
    (b"nvgt;", ">\u{20D2}".as_bytes()),
    (b"bne;", "=\u{20E5}".as_bytes()),
];

/// The ASCII legacy references browsers also accept without the `;`.
const LEGACY: &[(&[u8], u8)] = &[
    (b"amp", b'&'),
    (b"AMP", b'&'),
    (b"lt", b'<'),
    (b"LT", b'<'),
    (b"gt", b'>'),
    (b"GT", b'>'),
    (b"quot", b'"'),
    (b"QUOT", b'"'),
];

/// Code points browsers substitute for numeric references to `0x80..=0x9F`
/// (`0` keeps the number).
const WINDOWS_1252: [u32; 32] = [
    0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0, 0x017D, 0, 0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC,
    0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178,
];

/// The attribute value browsers see for `raw`, borrowing when there is
/// nothing to decode.
pub(crate) fn decode_attribute_value(raw: &[u8]) -> Cow<'_, [u8]> {
    if memchr(b'&', raw).is_none() {
        Cow::Borrowed(raw)
    } else {
        let mut out = Vec::with_capacity(raw.len());
        decode_attribute_value_into(raw, &mut out);
        Cow::Owned(out)
    }
}

/// Appends the attribute value browsers see for `raw` to `out`.
pub(crate) fn decode_attribute_value_into(raw: &[u8], out: &mut Vec<u8>) {
    let mut rest = raw;
    while let Some(amp) = memchr(b'&', rest) {
        out.extend_from_slice(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(consumed) = reference(after, out) {
            rest = &after[consumed..];
        } else {
            out.push(b'&');
            rest = after;
        }
    }
    out.extend_from_slice(rest);
}

/// Whether the decoded value of `raw` equals one of `candidates` (ASCII case
/// insensitive), the way browsers compare enumerated attribute values.
pub(crate) fn attribute_value_is(raw: &[u8], candidates: &[&[u8]]) -> bool {
    let value = decode_attribute_value(raw);
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

/// Decodes the reference after an `&` into `out`, returning how many bytes it
/// consumed, or `None` when browsers keep the `&` literal.
fn reference(after: &[u8], out: &mut Vec<u8>) -> Option<usize> {
    match after.first()? {
        b'#' => numeric(after, out),
        b if b.is_ascii_alphanumeric() => named(after, out),
        _ => None,
    }
}

fn named(after: &[u8], out: &mut Vec<u8>) -> Option<usize> {
    if let Some(&(name, text)) = NAMED.iter().find(|(name, _)| after.starts_with(name)) {
        out.extend_from_slice(text);
        return Some(name.len());
    }
    let &(name, byte) = LEGACY.iter().find(|(name, _)| after.starts_with(name))?;
    // In attribute values a legacy reference followed by `=` or an
    // alphanumeric stays literal.
    if after
        .get(name.len())
        .is_some_and(|&next| next == b'=' || next.is_ascii_alphanumeric())
    {
        return None;
    }
    out.push(byte);
    Some(name.len())
}

fn numeric(after: &[u8], out: &mut Vec<u8>) -> Option<usize> {
    let hex = matches!(after.get(1), Some(b'x' | b'X'));
    let start = if hex { 2 } else { 1 };
    let radix = if hex { 16 } else { 10 };
    let mut end = start;
    let mut value: u32 = 0;
    while let Some(digit) = after.get(end).and_then(|&b| char::from(b).to_digit(radix)) {
        // Saturate past the Unicode range: browsers map it to U+FFFD anyway.
        value = value
            .saturating_mul(radix)
            .saturating_add(digit)
            .min(0x11_0000);
        end += 1;
    }
    if end == start {
        return None;
    }
    if after.get(end) == Some(&b';') {
        end += 1;
    }
    let code = match value {
        0x80..=0x9F => match WINDOWS_1252[(value - 0x80) as usize] {
            0 => value,
            mapped => mapped,
        },
        other => other,
    };
    let ch = match code {
        0 => char::REPLACEMENT_CHARACTER,
        code => char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER),
    };
    let mut buf = [0; 4];
    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    Some(end)
}

#[cfg(test)]
mod tests {
    use super::{attribute_value_is, decode_attribute_value};

    fn decoded(raw: &str) -> String {
        String::from_utf8(decode_attribute_value(raw.as_bytes()).into_owned()).unwrap()
    }

    #[test]
    fn decodes_like_browsers_in_attribute_values() {
        for (raw, expected) in [
            ("plain", "plain"),
            ("text&#47html", "text/html"),
            ("text&#47;html", "text/html"),
            ("text&#x2F;html", "text/html"),
            ("text&#X2f html", "text/ html"),
            ("text&sol;html", "text/html"),
            ("application/xhtml&plus;xml", "application/xhtml+xml"),
            ("a&amp;b", "a&b"),
            ("a&ampb", "a&ampb"),
            ("a&amp=b", "a&amp=b"),
            ("a&amp b", "a& b"),
            ("&lt", "<"),
            ("&LT;&GT;&QUOT", "<>\""),
            ("&solb;", "&solb;"),
            ("&ltimes;", "&ltimes;"),
            ("&eacute;", "&eacute;"),
            ("&#", "&#"),
            ("&#x;", "&#x;"),
            ("&#0;", "\u{FFFD}"),
            ("&#x110000;", "\u{FFFD}"),
            ("&#xD800;", "\u{FFFD}"),
            ("&#99999999999999999999;", "\u{FFFD}"),
            ("&#x80;", "\u{20AC}"),
            ("&#x81;", "\u{81}"),
            ("&#120;&#x41;", "xA"),
            ("&fjlig;", "fj"),
            ("&Tab;&NewLine;", "\t\n"),
            ("&nvlt;", "<\u{20D2}"),
            ("&", "&"),
            ("a&", "a&"),
            ("&&amp;", "&&"),
        ] {
            assert_eq!(decoded(raw), expected, "{raw}");
        }
    }

    #[test]
    fn enumerated_values_compare_decoded_and_case_insensitively() {
        assert!(attribute_value_is(b"TEXT&sol;HTML", &[b"text/html"]));
        assert!(attribute_value_is(b"h&#105;dden", &[b"hidden"]));
        assert!(!attribute_value_is(b"text/htm", &[b"text/html"]));
        assert!(!attribute_value_is(b"text&sol html", &[b"text/html"]));
    }
}
