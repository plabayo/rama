//! Structured Fields parser (RFC 9651 subset).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use super::types::{
    BareItem, Dictionary, DictionaryMember, InnerList, Item, Parameter, ParameterValue, Parameters,
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
            Some(b'-' | b'0'..=b'9') => Ok(BareItem::Integer(self.parse_integer()?)),
            Some(b'a'..=b'z' | b'A'..=b'Z' | b'*') => Ok(BareItem::Token(self.parse_token()?)),
            _ => Err(self.err("expected bare item")),
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

    fn parse_integer(&mut self) -> Result<i64, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.err("expected digit"));
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        // Reject decimals for this subset (RFC allows Decimal; we only need Integer)
        if self.peek() == Some(b'.') {
            return Err(self.err("decimals not supported in this subset"));
        }
        let s = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_err| self.err("invalid integer"))?;
        s.parse().map_err(|_err| self.err("integer out of range"))
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
                match self.parse_bare_item()? {
                    BareItem::String(s) => ParameterValue::String(s),
                    BareItem::Token(t) => ParameterValue::Token(t),
                    BareItem::Integer(n) => ParameterValue::Integer(n),
                    BareItem::Boolean(b) => ParameterValue::Boolean(b),
                    BareItem::ByteSequence(b) => ParameterValue::ByteSequence(b),
                }
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
