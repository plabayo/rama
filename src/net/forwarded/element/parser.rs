use super::ExtensionValue;
use super::{ForwardedElement, NodeId};
use crate::error::{ErrorContext, OpaqueError};
use crate::net::forwarded::ForwardedProtocol;

pub(crate) fn parse_single_forwarded_element(
    bytes: &[u8],
) -> Result<ForwardedElement, OpaqueError> {
    if bytes.len() > 512 {
        // custom max length, to keep things sane here...
        return Err(OpaqueError::from_display(
            "forwarded element bytes length is too big",
        ));
    }

    let (element, bytes) = parse_next_forwarded_element(bytes)?;
    if bytes.is_empty() {
        Ok(element)
    } else {
        Err(OpaqueError::from_display(
            "trailing characters found following the forwarded element",
        ))
    }
}

pub(crate) fn parse_one_plus_forwarded_elements(
    bytes: &[u8],
) -> Result<(ForwardedElement, Vec<ForwardedElement>), OpaqueError> {
    if bytes.len() > 8096 {
        // custom max length, to keep things sane here...
        return Err(OpaqueError::from_display(
            "forwarded elements list bytes length is too big",
        ));
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
            return Err(OpaqueError::from_display(
                "unexpected char in forward element list: expected comma",
            ));
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

fn parse_next_forwarded_element(
    mut bytes: &[u8],
) -> Result<(ForwardedElement, &[u8]), OpaqueError> {
    if bytes.is_empty() {
        return Err(OpaqueError::from_display(
            "empty str is not a valid Forwarded Element",
        ));
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
        let separator_index = match bytes.iter().position(|b| *b == b'=') {
            Some(index) => index,
            None => {
                bytes = trim_left(bytes);
                // finished parsing
                break;
            }
        };

        let key = parse_value(trim(&bytes[..separator_index]))?;
        bytes = trim_left(&bytes[separator_index + 1..]);

        let (value, quoted) = match bytes
            .iter()
            .position(|b| *b == b'"' || *b == b';' || *b == b',')
        {
            Some(index) => match bytes[index] {
                b'"' => {
                    if index != 0 {
                        return Err(OpaqueError::from_display("dangling quote string quote"));
                    } else {
                        bytes = &bytes[1..];
                        let trailer_quote_index =
                            bytes.iter().position(|b| *b == b'"').ok_or_else(|| {
                                OpaqueError::from_display("quote string missing trailer quote")
                            })?;
                        let value = &bytes[..trailer_quote_index];
                        bytes = &bytes[trailer_quote_index + 1..];
                        (value, true)
                    }
                }
                b';' | b',' => {
                    let value = &bytes[..index];
                    bytes = &bytes[index..];
                    (value, false)
                }
                _ => {
                    unreachable!("we should only ever find a quote or semicolon at this point")
                }
            },
            None => {
                let value = bytes;
                bytes = &bytes[bytes.len()..];
                (value, false)
            }
        };

        let value = parse_value(value)?;

        // as defined in <https://datatracker.ietf.org/doc/html/rfc7239#section-4>:
        //
        // > Note that as ":" and "[]" are not valid characters in "token", IPv6
        // > addresses are written as "quoted-string"
        // >
        // > cfr: <https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6>
        // >
        // > remark: we do not apply any validation here
        if !quoted && value.contains(['[', ']', ':']) {
            return Err(OpaqueError::from_display(format!("Forwarded Element pair's value was expected to be a quoted string due to the chars it contains: {value}")));
        }

        match_ignore_ascii_case_str! {
            match(key) {
                "for" => if el.for_node.is_some() {
                    return Err(OpaqueError::from_display("Forwarded Element can only contain one 'for' property"));
                } else {
                    el.for_node = Some(NodeId::try_from(value).context("parse Forwarded Element 'for' node")?);
                },
                "host" => if el.authority.is_some() {
                    return Err(OpaqueError::from_display("Forwarded Element can only contain one 'host' property"));
                } else {
                    el.authority = Some(value.parse().context("parse Forwarded Element 'host' authority")?);
                },
                "by" => if el.by_node.is_some() {
                    return Err(OpaqueError::from_display("Forwarded Element can only contain one 'by' property"));
                } else {
                    el.by_node = Some(NodeId::try_from(value).context("parse Forwarded Element 'by' node")?);
                },
                "proto" => if el.proto.is_some() {
                    return Err(OpaqueError::from_display("Forwarded Element can only contain one 'proto' property"));
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
        return Err(OpaqueError::from_display(
            "invalid forwarded element: none of required properties are set",
        ));
    }

    bytes = trim_left(bytes);
    Ok((el, bytes))
}

fn trim_left(b: &[u8]) -> &[u8] {
    let mut offset = 0;
    while offset < b.len() && b[offset] == b' ' {
        offset += 1;
    }
    &b[offset..]
}

fn trim_right(b: &[u8]) -> &[u8] {
    if b.is_empty() {
        return b;
    }

    let mut offset = b.len();
    while offset > 0 && b[offset - 1] == b' ' {
        offset -= 1;
    }
    &b[..offset]
}

fn trim(b: &[u8]) -> &[u8] {
    trim_right(trim_left(b))
}

fn parse_value(slice: &[u8]) -> Result<&str, OpaqueError> {
    if slice.iter().any(|b| !(32..127).contains(b) || *b == b'"') {
        return Err(OpaqueError::from_display(
            "value contains invalid characters",
        ));
    }
    std::str::from_utf8(slice).context("parse value as utf-8")
}
