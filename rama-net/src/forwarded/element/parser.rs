use super::ExtensionValue;
use super::{ForwardedElement, NodeId};
use crate::forwarded::ForwardedProtocol;
use rama_core::error::extra::OpaqueError;
use rama_core::error::{BoxError, ErrorContext, ErrorExt};
use rama_utils::macros::match_ignore_ascii_case_str;

pub(crate) fn parse_single_forwarded_element(bytes: &[u8]) -> Result<ForwardedElement, BoxError> {
    if bytes.len() > 512 {
        // custom max length, to keep things sane here...
        return Err(
            OpaqueError::from_static_str("forwarded element bytes length is too big")
                .context_field("length", bytes.len()),
        );
    }

    let (element, bytes) = parse_next_forwarded_element(bytes)?;
    if bytes.is_empty() {
        Ok(element)
    } else {
        Err(OpaqueError::from_static_str(
            "trailing characters found following the forwarded element",
        )
        .context_field("count", bytes.len()))
    }
}

pub(crate) fn parse_one_plus_forwarded_elements(
    bytes: &[u8],
) -> Result<(ForwardedElement, Vec<ForwardedElement>), BoxError> {
    if bytes.len() > 8096 {
        // custom max length, to keep things sane here...
        return Err(OpaqueError::from_static_str(
            "forwarded elements list bytes length is too big",
        )
        .context_field("length", bytes.len()));
    }

    let mut others = Vec::new();
    let (first, mut bytes) = parse_next_forwarded_element(bytes)?;
    if bytes.is_empty() {
        // early return, just a single element found :)
        return Ok((first, others));
    }

    // parse as many as possibly found
    loop {
        // skip comma first
        if bytes[0] != b',' {
            return Err(OpaqueError::from_static_str(
                "unexpected char in forward element list: expected comma",
            )
            .context_field("char", bytes[0]));
        }
        bytes = &bytes[1..];

        let (next, b) = parse_next_forwarded_element(bytes)?;
        others.push(next);
        bytes = b;

        //return if we are finished
        if bytes.is_empty() {
            // early return, just a single element found :)
            return Ok((first, others));
        }
    }
}

fn parse_next_forwarded_element(mut bytes: &[u8]) -> Result<(ForwardedElement, &[u8]), BoxError> {
    if bytes.is_empty() {
        return Err(
            OpaqueError::from_static_str("empty str is not a valid Forwarded Element")
                .into_box_error(),
        );
    }

    let mut el = ForwardedElement {
        by_node: None,
        for_node: None,
        authority: None,
        proto: None,
        proto_version: None,
        extensions: None,
    };

    loop {
        let Some(separator_index) = bytes.iter().position(|b| *b == b'=') else {
            bytes = trim_left(bytes);
            // finished parsing
            break;
        };

        let key = parse_value(trim(&bytes[..separator_index]))?;
        bytes = trim_left(&bytes[separator_index + 1..]);

        // `unescaped` holds the decoded value only when the quoted form
        // actually contained a `\`-escape (RFC 7230 §3.2.6 `quoted-pair`);
        // otherwise we stay zero-copy and borrow straight from the input.
        // `Option<Vec<u8>>::None` is a tag and does not allocate — the
        // `Vec` is only materialized inside `scan_quoted_string` if it
        // actually sees a backslash.
        let mut unescaped: Option<Vec<u8>> = None;
        let value_slice: &[u8];
        let quoted: bool;

        if let Some(index) = bytes
            .iter()
            .position(|b| *b == b'"' || *b == b';' || *b == b',')
        {
            match bytes[index] {
                b'"' => {
                    if index != 0 {
                        return Err(OpaqueError::from_static_str("dangling quote string quote")
                            .context_field("quote_pos", index));
                    }
                    bytes = &bytes[1..];
                    let scan = scan_quoted_string(bytes)?;
                    value_slice = &bytes[..scan.raw_len];
                    bytes = &bytes[scan.consumed..];
                    unescaped = scan.decoded;
                    quoted = true;
                }
                b';' | b',' => {
                    value_slice = &bytes[..index];
                    bytes = &bytes[index..];
                    quoted = false;
                }
                _ => {
                    #[expect(
                        clippy::unreachable,
                        reason = "the iter::position above only returns indices for `\"`, `;`, or `,`"
                    )]
                    {
                        unreachable!("we should only ever find a quote or semicolon at this point")
                    }
                }
            }
        } else {
            value_slice = bytes;
            bytes = &bytes[bytes.len()..];
            quoted = false;
        }

        let value_bytes: &[u8] = unescaped.as_deref().unwrap_or(value_slice);
        let value = if quoted {
            parse_quoted_value(value_bytes)?
        } else {
            parse_value(value_bytes)?
        };

        // as defined in <https://datatracker.ietf.org/doc/html/rfc7239#section-4>:
        //
        // > Note that as ":" and "[]" are not valid characters in "token", IPv6
        // > addresses are written as "quoted-string"
        // >
        // > cfr: <https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6>
        // >
        // > remark: we do not apply any validation here
        if !quoted && value.contains(['[', ']', ':']) {
            return Err(OpaqueError::from_static_str(
                "Forwarded Element pair's value was expected to be a quoted string due to the chars it contains"
            ).context_str_field("value", value));
        }

        match_ignore_ascii_case_str! {
            match(key) {
                "for" => if el.for_node.is_some() {
                    return Err(OpaqueError::from_static_str("Forwarded Element can only contain one 'for' property").into_box_error());
                } else {
                    el.for_node = Some(NodeId::try_from(value).context("parse Forwarded Element 'for' node")?);
                },
                "host" => if el.authority.is_some() {
                    return Err(OpaqueError::from_static_str("Forwarded Element can only contain one 'host' property").into_box_error());
                } else {
                    el.authority = Some(value.parse().context("parse Forwarded Element 'host' authority")?);
                },
                "by" => if el.by_node.is_some() {
                    return Err(OpaqueError::from_static_str("Forwarded Element can only contain one 'by' property").into_box_error());
                } else {
                    el.by_node = Some(NodeId::try_from(value).context("parse Forwarded Element 'by' node")?);
                },
                "proto" => if el.proto.is_some() {
                    return Err(OpaqueError::from_static_str("Forwarded Element can only contain one 'proto' property").into_box_error());
                } else {
                    el.proto = Some(ForwardedProtocol::try_from(value).context("parse Forwarded Element 'proto' protocol")?);
                },
                _ => {
                    el.extensions.get_or_insert_with(Default::default)
                        .insert(key.to_owned(), ExtensionValue{
                            value: value.to_owned(),
                            quoted,
                        });
                }
            }
        }

        // look for (semi) colon, otherwise we are finished...
        bytes = trim_left(bytes);
        if bytes.is_empty() || bytes[0] != b';' {
            // finished parsing
            break;
        }

        // remove semi column, and try next pair :)
        bytes = &bytes[1..];
    }

    if el.for_node.is_none() && el.by_node.is_none() && el.authority.is_none() && el.proto.is_none()
    {
        return Err(OpaqueError::from_static_str(
            "invalid forwarded element: none of required properties are set",
        )
        .into_box_error());
    }

    bytes = trim_left(bytes);
    Ok((el, bytes))
}

/// Output of [`scan_quoted_string`].
struct QuotedScan {
    /// Number of bytes consumed up to and including the closing `"`.
    consumed: usize,
    /// Length of the raw slice (excluding the closing `"`).
    raw_len: usize,
    /// Decoded bytes — only populated when one or more `\`-escapes were
    /// resolved. When `None` the raw slice (`&bytes[..raw_len]`) is the
    /// already-correct value.
    decoded: Option<Vec<u8>>,
}

/// Scan an RFC 7230 §3.2.6 `quoted-string` body (the bytes *after* the
/// opening `"`), honoring `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )`.
///
/// We are graceful: a trailing `\` before EOF is reported as a missing
/// trailer quote rather than silently swallowed.
//
// Regression: `tests::regression_forwarded_quoted_pair_rfc7230`.
fn scan_quoted_string(bytes: &[u8]) -> Result<QuotedScan, BoxError> {
    let mut i = 0;
    let mut decoded: Option<Vec<u8>> = None;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                return Ok(QuotedScan {
                    consumed: i + 1,
                    raw_len: i,
                    decoded,
                });
            }
            b'\\' => {
                // quoted-pair: `\` followed by one byte.
                if i + 1 >= bytes.len() {
                    break;
                }
                let buf = decoded.get_or_insert_with(|| bytes[..i].to_vec());
                buf.push(bytes[i + 1]);
                i += 2;
            }
            other => {
                if let Some(buf) = decoded.as_mut() {
                    buf.push(other);
                }
                i += 1;
            }
        }
    }
    Err(OpaqueError::from_static_str("quote string missing trailer quote").into_box_error())
}

fn trim_left(b: &[u8]) -> &[u8] {
    let mut offset = 0;
    while offset < b.len() && matches!(b[offset], b' ' | b'\t') {
        offset += 1;
    }
    &b[offset..]
}

fn trim_right(b: &[u8]) -> &[u8] {
    if b.is_empty() {
        return b;
    }

    let mut offset = b.len();
    while offset > 0 && matches!(b[offset - 1], b' ' | b'\t') {
        offset -= 1;
    }
    &b[..offset]
}

fn trim(b: &[u8]) -> &[u8] {
    trim_right(trim_left(b))
}

/// Parse a `token`-form value: visible ASCII (`0x21..=0x7E`) only, no `"`.
fn parse_value(slice: &[u8]) -> Result<&str, BoxError> {
    if slice.iter().any(|b| !(32..127).contains(b) || *b == b'"') {
        return Err(
            OpaqueError::from_static_str("value contains invalid characters").into_box_error(),
        );
    }
    std::str::from_utf8(slice).context("parse value as utf-8")
}

/// Parse a `quoted-string` body (post-unescape). RFC 7230 §3.2.6 defines
/// `qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text` and
/// `obs-text = %x80-FF`. We allow:
///
/// * HTAB (`0x09`) and SP (`0x20`)
/// * VCHAR except `"` and `\` (those would have ended / opened a quoted-pair
///   already, so seeing them post-decode would be a bug)
/// * obs-text (`0x80..=0xFF`) — accepted gracefully, with the actual
///   UTF-8 well-formedness check delegated to [`std::str::from_utf8`].
//
// Regression: `tests::regression_forwarded_obs_text_in_qdtext`.
fn parse_quoted_value(slice: &[u8]) -> Result<&str, BoxError> {
    // The slice here is either:
    //   * the raw bytes between the surrounding `"`s (no quoted-pair was
    //     present); in that case `"` cannot appear because the scan would
    //     have terminated, and `\` cannot appear because the scan would
    //     have started a quoted-pair branch — but we still validate for
    //     defensive symmetry; or
    //   * the post-unescape buffer, which legitimately may contain `"` and
    //     `\` derived from `\"`/`\\` and must be passed through verbatim.
    //
    // We only reject CTL bytes other than HTAB (0x09), plus DEL (0x7F).
    // obs-text (0x80–0xFF) is allowed per RFC 7230 §3.2.6; UTF-8
    // well-formedness is enforced by `from_utf8`.
    if let Some(idx) = slice
        .iter()
        .position(|b| matches!(*b, 0..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(
            OpaqueError::from_static_str("quoted value contains invalid control byte")
                .context_field("byte_index", idx),
        );
    }
    std::str::from_utf8(slice).context("parse quoted value as utf-8")
}
