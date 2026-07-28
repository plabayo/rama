//! Structured Fields serializer (RFC 9651 subset).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use super::types::{
    BareItem, Dictionary, DictionaryMember, InnerList, Item, List, ListMember, ParameterValue,
    Parameters,
};

/// Serialize a Dictionary to a Structured Fields header value string.
pub fn serialize_dictionary(dict: &Dictionary) -> String {
    let mut out = String::new();
    for (i, (key, member)) in dict.members.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(key);
        match member {
            DictionaryMember::Item(item) => {
                // Boolean-true shorthand without parameters: just the key
                if matches!(item.bare, BareItem::Boolean(true)) && item.parameters.is_empty() {
                    continue;
                }
                out.push('=');
                serialize_item(&mut out, item);
            }
            DictionaryMember::InnerList(list) => {
                out.push('=');
                serialize_inner_list(&mut out, list);
            }
        }
    }
    out
}

/// Serialize a List to a Structured Fields header value string.
pub fn serialize_list(list: &List) -> String {
    let mut out = String::new();
    for (i, member) in list.members.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match member {
            ListMember::Item(item) => serialize_item(&mut out, item),
            ListMember::InnerList(inner) => serialize_inner_list(&mut out, inner),
        }
    }
    out
}

/// Serialize a single Item (bare item + parameters).
pub fn serialize_item_value(item: &Item) -> String {
    let mut out = String::new();
    serialize_item(&mut out, item);
    out
}

fn serialize_inner_list(out: &mut String, list: &InnerList) {
    out.push('(');
    for (i, item) in list.items.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        serialize_item(out, item);
    }
    out.push(')');
    serialize_parameters(out, &list.parameters);
}

fn serialize_item(out: &mut String, item: &Item) {
    serialize_bare_item(out, &item.bare);
    serialize_parameters(out, &item.parameters);
}

fn serialize_bare_item(out: &mut String, bare: &BareItem) {
    match bare {
        BareItem::String(s) => {
            out.push('"');
            for c in s.chars() {
                if c == '"' || c == '\\' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        }
        BareItem::Token(t) => out.push_str(t),
        BareItem::Integer(n) => {
            out.push_str(&n.to_string());
        }
        BareItem::Decimal {
            negative,
            integer,
            fraction,
            fraction_digits,
        } => {
            if *negative {
                out.push('-');
            }
            out.push_str(&integer.to_string());
            out.push('.');
            let width = usize::from(*fraction_digits);
            out.push_str(&format!("{fraction:0width$}"));
        }
        BareItem::Boolean(true) => out.push_str("?1"),
        BareItem::Boolean(false) => out.push_str("?0"),
        BareItem::ByteSequence(bytes) => {
            out.push(':');
            out.push_str(&B64.encode(bytes));
            out.push(':');
        }
        BareItem::Date(n) => {
            out.push('@');
            out.push_str(&n.to_string());
        }
        BareItem::DisplayString(s) => {
            out.push('%');
            out.push('"');
            // RFC 9651 §3.3.8 / §4.1.11: encode %x00-1f / %x22 / %x25 / %x7f-ff
            // with lowercase hex; allow ldash-char otherwise.
            for b in s.as_bytes() {
                match *b {
                    0x20..=0x21 | 0x23..=0x24 | 0x26..=0x5b | 0x5d..=0x7e => {
                        out.push(*b as char);
                    }
                    _ => {
                        out.push('%');
                        out.push(char::from(LC_HEX[(b >> 4) as usize]));
                        out.push(char::from(LC_HEX[(b & 0xf) as usize]));
                    }
                }
            }
            out.push('"');
        }
    }
}

const LC_HEX: &[u8; 16] = b"0123456789abcdef";

fn serialize_parameters(out: &mut String, params: &Parameters) {
    for p in &params.params {
        out.push(';');
        out.push_str(&p.name);
        match &p.value {
            ParameterValue::Boolean(true) => {}
            ParameterValue::Boolean(false) => {
                out.push('=');
                out.push_str("?0");
            }
            ParameterValue::String(s) => {
                out.push('=');
                serialize_bare_item(out, &BareItem::String(s.clone()));
            }
            ParameterValue::Token(t) => {
                out.push('=');
                out.push_str(t);
            }
            ParameterValue::Integer(n) => {
                out.push('=');
                out.push_str(&n.to_string());
            }
            ParameterValue::Decimal {
                negative,
                integer,
                fraction,
                fraction_digits,
            } => {
                out.push('=');
                serialize_bare_item(
                    out,
                    &BareItem::Decimal {
                        negative: *negative,
                        integer: *integer,
                        fraction: *fraction,
                        fraction_digits: *fraction_digits,
                    },
                );
            }
            ParameterValue::ByteSequence(bytes) => {
                out.push('=');
                serialize_bare_item(out, &BareItem::ByteSequence(bytes.clone()));
            }
            ParameterValue::Date(n) => {
                out.push('=');
                serialize_bare_item(out, &BareItem::Date(*n));
            }
            ParameterValue::DisplayString(s) => {
                out.push('=');
                serialize_bare_item(out, &BareItem::DisplayString(s.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::structured_fields::{BareItem, Item, parse_dictionary, parse_item};

    #[test]
    fn round_trip_signature_input() {
        let input =
            r#"sig1=("@method" "@authority" "@path");created=1618884475;keyid="test-key-ecc-p256""#;
        let dict = parse_dictionary(input).unwrap();
        let encoded = serialize_dictionary(&dict);
        let again = parse_dictionary(&encoded).unwrap();
        assert_eq!(dict, again);
    }

    #[test]
    fn round_trip_byte_sequence() {
        let input = "sig1=:dGVzdA==:";
        let dict = parse_dictionary(input).unwrap();
        let encoded = serialize_dictionary(&dict);
        assert_eq!(parse_dictionary(&encoded).unwrap(), dict);
    }

    #[test]
    fn display_string_encodes_percent_and_uses_lowercase_hex() {
        let item = Item::new(BareItem::DisplayString("100% café".into()));
        let encoded = serialize_item_value(&item);
        assert_eq!(encoded, "%\"100%25 caf%c3%a9\"");
        assert_eq!(parse_item(&encoded).unwrap(), item);
    }
}
