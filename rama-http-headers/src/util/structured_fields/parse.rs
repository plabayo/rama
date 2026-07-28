//! Structured Fields parser (RFC 9651 subset).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use super::types::{
    BareItem, Dictionary, DictionaryMember, InnerList, Item, List, ListMember, Parameter,
    ParameterValue, Parameters,
};

/// Parse error for Structured Fields input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: &'static str,
    pub position: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "structured fields parse error at {}: {}",
            self.position, self.message
        )
    }
}

impl std::error::Error for ParseError {}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn err(&self, message: &'static str) -> ParseError {
        ParseError {
            message,
            position: self.pos,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8, msg: &'static str) -> Result<(), ParseError> {
        match self.bump() {
            Some(c) if c == b => Ok(()),
            _ => Err(self.err(msg)),
        }
    }

    fn parse_dictionary(mut self) -> Result<Dictionary, ParseError> {
        self.skip_ows();
        let mut dict = Dictionary::new();
        if self.pos >= self.input.len() {
            return Ok(dict);
        }

        loop {
            self.skip_ows();
            let key = self.parse_key()?;
            self.skip_ows();

            let member = if self.peek() == Some(b'=') {
                self.bump();
                self.skip_ows();
                if self.peek() == Some(b'(') {
                    DictionaryMember::InnerList(self.parse_inner_list()?)
                } else {
                    DictionaryMember::Item(self.parse_item()?)
                }
            } else {
                // Boolean true shorthand: `key` alone
                DictionaryMember::Item(
                    Item::boolean(true).with_parameters(self.parse_parameters()?),
                )
            };

            if dict.get(&key).is_some() {
                return Err(self.err("duplicate dictionary key"));
            }
            dict.members.push((key, member));

            self.skip_ows();
            if self.pos >= self.input.len() {
                break;
            }
            self.expect(b',', "expected ',' between dictionary members")?;
            self.skip_ows();
            if self.pos >= self.input.len() {
                return Err(self.err("trailing comma in dictionary"));
            }
        }

        Ok(dict)
    }

    fn parse_key(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        let first = self.bump().ok_or_else(|| self.err("expected key"))?;
        if !(first.is_ascii_lowercase() || first == b'*') {
            return Err(self.err("key must start with lcalpha or '*'"));
        }
        while matches!(
            self.peek(),
            Some(b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')
        ) {
            self.pos += 1;
        }
        Ok(std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_err| self.err("invalid utf-8 in key"))?
            .to_owned())
    }

    fn parse_inner_list(&mut self) -> Result<InnerList, ParseError> {
        self.expect(b'(', "expected '('")?;
        self.skip_ows();
        let mut items = Vec::new();
        while self.peek() != Some(b')') {
            if self.pos >= self.input.len() {
                return Err(self.err("unterminated inner list"));
            }
            items.push(self.parse_item()?);
            let had_ws = matches!(self.peek(), Some(b' ' | b'\t'));
            self.skip_ows();
            if self.peek() == Some(b')') {
                break;
            }
            if !had_ws {
                return Err(self.err("expected whitespace between inner-list items"));
            }
        }
        self.expect(b')', "expected ')'")?;
        let parameters = self.parse_parameters()?;
        Ok(InnerList { items, parameters })
    }

    fn parse_item(&mut self) -> Result<Item, ParseError> {
        let bare = self.parse_bare_item()?;
        let parameters = self.parse_parameters()?;
        Ok(Item { bare, parameters })
    }

    fn parse_bare_item(&mut self) -> Result<BareItem, ParseError> {
        match self.peek() {
            Some(b'"') => Ok(BareItem::String(self.parse_string()?)),
            Some(b':') => Ok(BareItem::ByteSequence(self.parse_byte_sequence()?)),
            Some(b'?') => Ok(BareItem::Boolean(self.parse_boolean()?)),
            Some(b'@') => Ok(BareItem::Date(self.parse_date()?)),
            Some(b'%') => Ok(BareItem::DisplayString(self.parse_display_string()?)),
            Some(b'-' | b'0'..=b'9') => self.parse_integer_or_decimal(),
            Some(b'a'..=b'z' | b'A'..=b'Z' | b'*') => Ok(BareItem::Token(self.parse_token()?)),
            _ => Err(self.err("expected bare item")),
        }
    }

    fn parse_date(&mut self) -> Result<i64, ParseError> {
        self.expect(b'@', "expected '@'")?;
        match self.parse_integer_or_decimal()? {
            BareItem::Integer(n) => Ok(n),
            _ => Err(self.err("date requires an integer")),
        }
    }

    fn parse_display_string(&mut self) -> Result<String, ParseError> {
        self.expect(b'%', "expected '%'")?;
        self.expect(b'"', "expected '\"' after %")?;
        let mut bytes = Vec::new();
        loop {
            match self.bump() {
                Some(b'"') => {
                    return String::from_utf8(bytes)
                        .map_err(|_err| self.err("invalid utf-8 in display string"));
                }
                Some(b'%') => {
                    let hi = self.bump().ok_or_else(|| self.err("truncated percent"))?;
                    let lo = self.bump().ok_or_else(|| self.err("truncated percent"))?;
                    let h =
                        hex_nibble(hi).ok_or_else(|| self.err("invalid hex in display string"))?;
                    let l =
                        hex_nibble(lo).ok_or_else(|| self.err("invalid hex in display string"))?;
                    bytes.push((h << 4) | l);
                }
                Some(c)
                    if (0x20..=0x21).contains(&c)
                        || (0x23..=0x5b).contains(&c)
                        || (0x5d..=0x7e).contains(&c) =>
                {
                    bytes.push(c);
                }
                Some(_) => return Err(self.err("invalid byte in display string")),
                None => return Err(self.err("unterminated display string")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"', "expected '\"'")?;
        let mut out = String::new();
        loop {
            match self.bump() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => match self.bump() {
                    Some(c @ (b'\\' | b'"')) => out.push(c as char),
                    Some(_) => return Err(self.err("invalid escape in string")),
                    None => return Err(self.err("unterminated escape")),
                },
                Some(b'\n' | b'\r') => return Err(self.err("newline in string")),
                Some(c) if c <= 0x7f => out.push(c as char),
                Some(_) => return Err(self.err("non-ASCII in string")),
                None => return Err(self.err("unterminated string")),
            }
        }
    }

    fn parse_byte_sequence(&mut self) -> Result<Vec<u8>, ParseError> {
        self.expect(b':', "expected ':'")?;
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == b':' {
                break;
            }
            self.pos += 1;
        }
        let encoded = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_err| self.err("invalid utf-8 in byte sequence"))?;
        self.expect(b':', "expected closing ':'")?;
        B64.decode(encoded)
            .map_err(|_err| self.err("invalid base64 in byte sequence"))
    }

    fn parse_boolean(&mut self) -> Result<bool, ParseError> {
        self.expect(b'?', "expected '?'")?;
        match self.bump() {
            Some(b'1') => Ok(true),
            Some(b'0') => Ok(false),
            _ => Err(self.err("expected ?0 or ?1")),
        }
    }

    fn parse_integer_or_decimal(&mut self) -> Result<BareItem, ParseError> {
        let negative = if self.peek() == Some(b'-') {
            self.pos += 1;
            true
        } else {
            false
        };
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.err("expected digit"));
        }
        let int_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos - int_start > 12 {
            return Err(self.err("integer too long"));
        }
        let int_str = std::str::from_utf8(&self.input[int_start..self.pos])
            .map_err(|_err| self.err("invalid integer"))?;

        if self.peek() != Some(b'.') {
            let mut n: i64 = int_str
                .parse()
                .map_err(|_err| self.err("integer out of range"))?;
            if negative {
                n = -n;
            }
            return Ok(BareItem::Integer(n));
        }

        self.bump(); // '.'
        let frac_start = self.pos;
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.err("expected fractional digit"));
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let frac_len = self.pos - frac_start;
        if !(1..=3).contains(&frac_len) {
            return Err(self.err("decimal fraction must be 1 to 3 digits"));
        }
        let frac_str = std::str::from_utf8(&self.input[frac_start..self.pos])
            .map_err(|_err| self.err("invalid fraction"))?;

        // Strip trailing zeros but keep at least one fractional digit.
        let mut digits = frac_len as u8;
        let mut fraction: u16 = frac_str
            .parse()
            .map_err(|_err| self.err("invalid fraction"))?;
        while digits > 1 && fraction.is_multiple_of(10) {
            fraction /= 10;
            digits -= 1;
        }
        let integer: u64 = int_str
            .parse()
            .map_err(|_err| self.err("integer out of range"))?;
        Ok(BareItem::Decimal {
            negative,
            integer,
            fraction,
            fraction_digits: digits,
        })
    }

    fn parse_token(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        let first = self.bump().ok_or_else(|| self.err("expected token"))?;
        if !(first.is_ascii_alphabetic() || first == b'*') {
            return Err(self.err("invalid token start"));
        }
        while let Some(c) = self.peek() {
            if is_tchar(c) || c == b':' || c == b'/' {
                self.pos += 1;
            } else {
                break;
            }
        }
        Ok(std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_err| self.err("invalid utf-8 in token"))?
            .to_owned())
    }

    fn parse_parameters(&mut self) -> Result<Parameters, ParseError> {
        let mut params = Parameters::new();
        while self.peek() == Some(b';') {
            self.bump();
            let name = self.parse_key()?;
            let value = if self.peek() == Some(b'=') {
                self.bump();
                bare_to_parameter_value(self.parse_bare_item()?)
            } else {
                ParameterValue::Boolean(true)
            };
            if params.get(&name).is_some() {
                return Err(self.err("duplicate parameter"));
            }
            params.params.push(Parameter { name, value });
        }
        Ok(params)
    }
}

fn bare_to_parameter_value(bare: BareItem) -> ParameterValue {
    match bare {
        BareItem::String(s) => ParameterValue::String(s),
        BareItem::Token(t) => ParameterValue::Token(t),
        BareItem::Integer(n) => ParameterValue::Integer(n),
        BareItem::Boolean(b) => ParameterValue::Boolean(b),
        BareItem::ByteSequence(b) => ParameterValue::ByteSequence(b),
        BareItem::Decimal {
            negative,
            integer,
            fraction,
            fraction_digits,
        } => ParameterValue::Decimal {
            negative,
            integer,
            fraction,
            fraction_digits,
        },
        BareItem::Date(n) => ParameterValue::Date(n),
        BareItem::DisplayString(s) => ParameterValue::DisplayString(s),
    }
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn is_tchar(c: u8) -> bool {
    matches!(
        c,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
    )
}

/// Parse a Structured Fields Dictionary from a header field value.
pub fn parse_dictionary(input: &str) -> Result<Dictionary, ParseError> {
    Parser::new(input).parse_dictionary()
}

/// Parse a Structured Fields List from a header field value.
pub fn parse_list(input: &str) -> Result<List, ParseError> {
    Parser::new(input).parse_list()
}

/// Parse a Structured Fields Item from a header field value.
pub fn parse_item(input: &str) -> Result<Item, ParseError> {
    let mut p = Parser::new(input);
    p.skip_ows();
    let item = p.parse_item()?;
    p.skip_ows();
    if p.pos < p.input.len() {
        return Err(p.err("trailing data after item"));
    }
    Ok(item)
}

impl Parser<'_> {
    fn parse_list(mut self) -> Result<List, ParseError> {
        self.skip_ows();
        let mut members = Vec::new();
        if self.pos >= self.input.len() {
            return Ok(List::new(members));
        }
        loop {
            self.skip_ows();
            let member = if self.peek() == Some(b'(') {
                ListMember::InnerList(self.parse_inner_list()?)
            } else {
                ListMember::Item(self.parse_item()?)
            };
            members.push(member);
            self.skip_ows();
            if self.pos >= self.input.len() {
                break;
            }
            self.expect(b',', "expected ',' between list members")?;
            self.skip_ows();
            if self.pos >= self.input.len() {
                return Err(self.err("trailing comma in list"));
            }
        }
        Ok(List::new(members))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signature_input_example() {
        let input =
            r#"sig1=("@method" "@authority" "@path");created=1618884475;keyid="test-key-ecc-p256""#;
        let dict = parse_dictionary(input).unwrap();
        let member = dict.get("sig1").unwrap();
        let DictionaryMember::InnerList(list) = member else {
            panic!("expected inner list");
        };
        assert_eq!(list.items.len(), 3);
        assert_eq!(list.items[0].bare, BareItem::String("@method".into()));
        assert_eq!(
            list.parameters.get("created"),
            Some(&ParameterValue::Integer(1618884475))
        );
        assert_eq!(
            list.parameters.get("keyid"),
            Some(&ParameterValue::String("test-key-ecc-p256".into()))
        );
    }

    #[test]
    fn parse_signature_byte_sequence() {
        let input = "sig1=:dGVzdA==:";
        let dict = parse_dictionary(input).unwrap();
        let DictionaryMember::Item(item) = dict.get("sig1").unwrap() else {
            panic!("expected item");
        };
        assert_eq!(item.bare, BareItem::ByteSequence(b"test".to_vec()));
    }

    #[test]
    fn parse_multi_label() {
        let input = r#"sig1=("@method");created=1, proxy_sig=("@method" "forwarded");keyid="p""#;
        let dict = parse_dictionary(input).unwrap();
        assert_eq!(dict.members.len(), 2);
        assert!(dict.get("sig1").is_some());
        assert!(dict.get("proxy_sig").is_some());
    }
}
