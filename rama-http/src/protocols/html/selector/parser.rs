//! Hand-rolled recursive-descent parser for the supported CSS selector
//! subset (see the [module docs](super) for the grammar).
//!
//! The parser operates over `&str` with a byte cursor that always rests on
//! a UTF-8 boundary (it only advances by whole `char`s). It returns a
//! typed [`SelectorError`] for any malformed or unsupported input and
//! never panics.

use std::str::FromStr;

use super::SelectorError;
use super::ast::{
    AttributeOperator, AttributeSelector, CaseSensitivity, Combinator, ComplexSelector, Compound,
    LocalName, Nth, NthType, Selector, SelectorPart,
};

impl FromStr for Selector {
    type Err = SelectorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Parser::new(s).parse_selector()
    }
}

struct Parser<'i> {
    input: &'i str,
    pos: usize,
}

impl<'i> Parser<'i> {
    fn new(input: &'i str) -> Self {
        Self { input, pos: 0 }
    }

    fn rest(&self) -> &'i str {
        // `pos` is always a char boundary, so this slice never panics.
        self.input.get(self.pos..).unwrap_or("")
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next().map(preprocess)
    }

    fn peek_nth(&self, n: usize) -> Option<char> {
        self.rest().chars().nth(n).map(preprocess)
    }

    fn bump(&mut self) -> Option<char> {
        let raw = self.rest().chars().next()?;
        self.pos += raw.len_utf8();
        Some(preprocess(raw))
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.pos += expected.len_utf8();
            true
        } else {
            false
        }
    }

    fn eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Skips CSS whitespace, returning whether any was consumed.
    fn skip_ws(&mut self) -> bool {
        let mut any = false;
        while self.peek().is_some_and(is_css_whitespace) {
            self.pos += 1;
            any = true;
        }
        any
    }

    fn parse_selector(&mut self) -> Result<Selector, SelectorError> {
        self.skip_ws();
        if self.eof() {
            return Err(SelectorError::EmptySelector);
        }

        let mut selectors = Vec::new();
        loop {
            selectors.push(self.parse_complex()?);
            self.skip_ws();
            match self.peek() {
                None => break,
                Some(',') => {
                    self.bump();
                    self.skip_ws();
                    if self.peek().is_none() {
                        return Err(SelectorError::UnexpectedEnd);
                    }
                }
                Some('+') => return Err(SelectorError::UnsupportedCombinator('+')),
                Some('~') => return Err(SelectorError::UnsupportedCombinator('~')),
                Some(_) => return Err(SelectorError::UnexpectedToken),
            }
        }
        Ok(Selector { selectors })
    }

    fn parse_complex(&mut self) -> Result<ComplexSelector, SelectorError> {
        let mut parts = vec![SelectorPart {
            combinator: None,
            compound: self.parse_compound()?,
        }];

        loop {
            let saw_ws = self.skip_ws();
            match self.peek() {
                None | Some(',') => break,
                Some('>') => {
                    self.bump();
                    self.skip_ws();
                    if matches!(self.peek(), None | Some(',')) {
                        return Err(SelectorError::DanglingCombinator);
                    }
                    parts.push(SelectorPart {
                        combinator: Some(Combinator::Child),
                        compound: self.parse_compound()?,
                    });
                }
                Some('+') => return Err(SelectorError::UnsupportedCombinator('+')),
                Some('~') => return Err(SelectorError::UnsupportedCombinator('~')),
                Some(_) => {
                    if !saw_ws {
                        return Err(SelectorError::UnexpectedToken);
                    }
                    parts.push(SelectorPart {
                        combinator: Some(Combinator::Descendant),
                        compound: self.parse_compound()?,
                    });
                }
            }
        }

        Ok(ComplexSelector { parts })
    }

    fn parse_compound(&mut self) -> Result<Compound, SelectorError> {
        let mut compound = Compound::default();
        let mut has_any = false;

        // Optional type / universal selector.
        match self.peek() {
            Some('*') => {
                self.bump();
                compound.explicit_universal = true;
                has_any = true;
                if self.peek() == Some('|') {
                    return Err(SelectorError::NamespacedSelector);
                }
            }
            Some('|') => return Err(SelectorError::NamespacedSelector),
            Some(c) if is_ident_start(c) || c == '\\' || c == '-' => {
                let name = self.parse_ident()?;
                if self.peek() == Some('|') {
                    return Err(SelectorError::NamespacedSelector);
                }
                compound.name = Some(LocalName::new(&name));
                has_any = true;
            }
            _ => {}
        }

        // Subclass selectors.
        loop {
            match self.peek() {
                Some('#') => {
                    self.bump();
                    compound.id = Some(self.parse_ident()?.into());
                }
                Some('.') => {
                    self.bump();
                    compound.classes.push(self.parse_ident()?.into());
                }
                Some('[') => compound.attributes.push(self.parse_attribute()?),
                Some(':') => self.parse_pseudo(&mut compound)?,
                _ => break,
            }
            has_any = true;
        }

        if !has_any {
            return Err(if self.eof() {
                SelectorError::UnexpectedEnd
            } else {
                SelectorError::UnexpectedToken
            });
        }
        Ok(compound)
    }

    fn parse_attribute(&mut self) -> Result<AttributeSelector, SelectorError> {
        self.bump(); // consume '['
        self.skip_ws();

        let name = match self.peek() {
            Some('=' | ']') => return Err(SelectorError::MissingAttributeName),
            Some('*' | '|') => return Err(SelectorError::NamespacedSelector),
            None => return Err(SelectorError::UnexpectedEnd),
            _ => self
                .parse_ident()
                .map_err(|_err| SelectorError::UnexpectedTokenInAttribute)?,
        };
        // A `|` immediately after the name is a namespace separator
        // (`ns|attr`) — unless it is the start of the `|=` operator.
        if self.peek() == Some('|') && self.peek_nth(1) != Some('=') {
            return Err(SelectorError::NamespacedSelector);
        }
        self.skip_ws();

        let operator = match self.peek() {
            Some(']') => None,
            Some('=') => {
                self.bump();
                Some(AttributeOperator::Equals)
            }
            Some('~') => Some(self.parse_attr_operator(AttributeOperator::Includes)?),
            Some('|') => Some(self.parse_attr_operator(AttributeOperator::DashMatch)?),
            Some('^') => Some(self.parse_attr_operator(AttributeOperator::Prefix)?),
            Some('$') => Some(self.parse_attr_operator(AttributeOperator::Suffix)?),
            Some('*') => Some(self.parse_attr_operator(AttributeOperator::Substring)?),
            None => return Err(SelectorError::UnexpectedEnd),
            Some(_) => return Err(SelectorError::UnexpectedTokenInAttribute),
        };

        let (value, case) = if operator.is_some() {
            self.skip_ws();
            let value = match self.peek() {
                Some('"' | '\'') => self.parse_string()?,
                Some(']') | None => return Err(SelectorError::UnexpectedTokenInAttribute),
                _ => self
                    .parse_ident()
                    .map_err(|_err| SelectorError::UnexpectedTokenInAttribute)?,
            };
            self.skip_ws();
            let case = match self.peek() {
                Some('i' | 'I') => {
                    self.bump();
                    self.skip_ws();
                    CaseSensitivity::AsciiCaseInsensitive
                }
                Some('s' | 'S') => {
                    self.bump();
                    self.skip_ws();
                    CaseSensitivity::CaseSensitive
                }
                _ => CaseSensitivity::CaseSensitive,
            };
            (value, case)
        } else {
            (String::new(), CaseSensitivity::CaseSensitive)
        };

        if !self.eat(']') {
            return Err(if self.eof() {
                SelectorError::UnexpectedEnd
            } else {
                SelectorError::UnexpectedTokenInAttribute
            });
        }

        Ok(AttributeSelector {
            name: name.to_ascii_lowercase().into(),
            operator,
            value: value.into(),
            case,
        })
    }

    /// Consumes the trailing `=` of a two-character attribute operator
    /// (e.g. the `=` in `~=`), returning the given operator.
    fn parse_attr_operator(
        &mut self,
        operator: AttributeOperator,
    ) -> Result<AttributeOperator, SelectorError> {
        self.bump(); // the operator's first char (`~`, `|`, `^`, `$`, `*`)
        if self.eat('=') {
            Ok(operator)
        } else {
            Err(SelectorError::UnexpectedTokenInAttribute)
        }
    }

    fn parse_pseudo(&mut self, compound: &mut Compound) -> Result<(), SelectorError> {
        self.bump(); // consume ':'
        if self.eat(':') {
            // Pseudo-element — unsupported. The cursor position no longer
            // matters once we return an error.
            return Err(SelectorError::UnsupportedPseudoClass);
        }

        let name = self.parse_ident()?.to_ascii_lowercase();

        if self.eat('(') {
            match name.as_str() {
                "nth-child" => {
                    let (a, b) = self.parse_nth_args()?;
                    compound.nth.push(Nth {
                        ty: NthType::Child,
                        a,
                        b,
                    });
                }
                "nth-of-type" => {
                    let (a, b) = self.parse_nth_args()?;
                    compound.nth.push(Nth {
                        ty: NthType::OfType,
                        a,
                        b,
                    });
                }
                "not" => self.parse_negation(compound)?,
                _ => {
                    self.skip_to_close_paren();
                    return Err(SelectorError::UnsupportedPseudoClass);
                }
            }
            Ok(())
        } else {
            match name.as_str() {
                "first-child" => {
                    compound.nth.push(Nth {
                        ty: NthType::Child,
                        a: 0,
                        b: 1,
                    });
                    Ok(())
                }
                "first-of-type" => {
                    compound.nth.push(Nth {
                        ty: NthType::OfType,
                        a: 0,
                        b: 1,
                    });
                    Ok(())
                }
                _ => Err(SelectorError::UnsupportedPseudoClass),
            }
        }
    }

    fn parse_negation(&mut self, compound: &mut Compound) -> Result<(), SelectorError> {
        // The opening '(' has already been consumed.
        self.skip_ws();
        if self.peek() == Some(')') {
            self.bump();
            return Err(SelectorError::EmptyNegation);
        }
        loop {
            compound.negations.push(self.parse_compound()?);
            self.skip_ws();
            match self.peek() {
                Some(')') => {
                    self.bump();
                    return Ok(());
                }
                Some(',') => {
                    self.bump();
                    self.skip_ws();
                    if self.peek() == Some(')') {
                        return Err(SelectorError::EmptyNegation);
                    }
                }
                None => return Err(SelectorError::UnexpectedEnd),
                // A combinator (or any other content) inside `:not()` means
                // the argument is not a bare compound — unsupported.
                Some(_) => return Err(SelectorError::UnsupportedPseudoClass),
            }
        }
    }

    /// Parses the `An+B` argument of an `:nth-*()` and the closing `)`.
    fn parse_nth_args(&mut self) -> Result<(i32, i32), SelectorError> {
        self.skip_ws();
        let anb = self.parse_anb()?;
        self.skip_ws();
        if !self.eat(')') {
            return Err(SelectorError::UnexpectedToken);
        }
        Ok(anb)
    }

    /// Parses the `An+B` micro-syntax (CSS Syntax §"The An+B microsyntax").
    fn parse_anb(&mut self) -> Result<(i32, i32), SelectorError> {
        if self.match_keyword_ci("even") {
            return Ok((2, 0));
        }
        if self.match_keyword_ci("odd") {
            return Ok((2, 1));
        }

        // Optional leading sign. No whitespace may follow it.
        let mut sign = 1i64;
        let has_sign = match self.peek() {
            Some('+') => {
                self.bump();
                true
            }
            Some('-') => {
                self.bump();
                sign = -1;
                true
            }
            _ => false,
        };
        if has_sign && self.peek().is_some_and(is_css_whitespace) {
            return Err(SelectorError::InvalidNth);
        }

        let digits = self.read_digits();

        if matches!(self.peek(), Some('n' | 'N')) {
            self.bump();
            let a = sign * digits.unwrap_or(1);
            let b = self.parse_anb_b()?;
            Ok((clamp_i32(a)?, clamp_i32(b)?))
        } else {
            let value = digits.ok_or(SelectorError::InvalidNth)?;
            Ok((0, clamp_i32(sign * value)?))
        }
    }

    /// Parses the optional `± B` tail of an `An+B` value (after `n`).
    fn parse_anb_b(&mut self) -> Result<i64, SelectorError> {
        let save = self.pos;
        self.skip_ws();
        let sign = match self.peek() {
            Some('+') => {
                self.bump();
                1
            }
            Some('-') => {
                self.bump();
                -1
            }
            _ => {
                self.pos = save;
                return Ok(0);
            }
        };
        self.skip_ws();
        if matches!(self.peek(), Some('+' | '-')) {
            return Err(SelectorError::InvalidNth);
        }
        let digits = self.read_digits().ok_or(SelectorError::InvalidNth)?;
        Ok(sign * digits)
    }

    fn read_digits(&mut self) -> Option<i64> {
        let mut value: i64 = 0;
        let mut any = false;
        while let Some(c) = self.peek() {
            let Some(d) = c.to_digit(10) else { break };
            value = value.saturating_mul(10).saturating_add(i64::from(d));
            any = true;
            self.bump();
        }
        any.then_some(value)
    }

    /// Consumes `keyword` (ASCII case-insensitive) if it is next and is
    /// not immediately followed by an identifier character.
    fn match_keyword_ci(&mut self, keyword: &str) -> bool {
        let rest = self.rest();
        if rest.len() < keyword.len() {
            return false;
        }
        let Some(head) = rest.get(..keyword.len()) else {
            return false;
        };
        if !head.eq_ignore_ascii_case(keyword) {
            return false;
        }
        if let Some(next) = rest[keyword.len()..].chars().next()
            && is_ident_char(next)
        {
            return false;
        }
        self.pos += keyword.len();
        true
    }

    fn parse_ident(&mut self) -> Result<String, SelectorError> {
        let mut out = String::new();
        match self.peek() {
            Some('\\') => out.push(self.parse_escape()?),
            Some('-') => {
                self.bump();
                out.push('-');
            }
            Some(c) if is_ident_start(c) => {
                self.bump();
                out.push(c);
            }
            _ => {
                return Err(if self.eof() {
                    SelectorError::UnexpectedEnd
                } else {
                    SelectorError::UnexpectedToken
                });
            }
        }

        loop {
            match self.peek() {
                Some('\\') => out.push(self.parse_escape()?),
                Some(c) if is_ident_char(c) => {
                    self.bump();
                    out.push(c);
                }
                _ => break,
            }
        }

        if out == "-" {
            return Err(SelectorError::UnexpectedToken);
        }
        Ok(out)
    }

    fn parse_string(&mut self) -> Result<String, SelectorError> {
        let quote = self.bump().unwrap_or('"');
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(SelectorError::UnexpectedEnd),
                Some(c) if c == quote => {
                    self.bump();
                    break;
                }
                Some('\n') => return Err(SelectorError::UnexpectedToken),
                Some('\\') => {
                    self.bump();
                    match self.peek() {
                        None => return Err(SelectorError::UnexpectedEnd),
                        // Escaped newline is a line continuation: emit nothing.
                        Some('\n') => {
                            self.bump();
                        }
                        Some(c) if c.is_ascii_hexdigit() => out.push(self.parse_hex_escape()),
                        Some(c) => {
                            self.bump();
                            out.push(c);
                        }
                    }
                }
                Some(c) => {
                    self.bump();
                    out.push(c);
                }
            }
        }
        Ok(out)
    }

    /// Parses a CSS escape sequence; the leading `\` is the current char.
    fn parse_escape(&mut self) -> Result<char, SelectorError> {
        self.bump(); // consume '\'
        match self.peek() {
            None | Some('\n') => Err(SelectorError::UnexpectedToken),
            Some(c) if c.is_ascii_hexdigit() => Ok(self.parse_hex_escape()),
            Some(c) => {
                self.bump();
                Ok(c)
            }
        }
    }

    /// Parses 1-6 hex digits (the current char is the first one) plus an
    /// optional single trailing whitespace, returning the code point.
    fn parse_hex_escape(&mut self) -> char {
        let mut value: u32 = 0;
        let mut count = 0;
        while count < 6 {
            match self.peek().and_then(|c| c.to_digit(16)) {
                Some(d) => {
                    value = value * 16 + d;
                    self.bump();
                    count += 1;
                }
                None => break,
            }
        }
        if self.peek().is_some_and(is_css_whitespace) {
            self.bump();
        }
        if value == 0 || (0xD800..=0xDFFF).contains(&value) || value > 0x0010_FFFF {
            '\u{FFFD}'
        } else {
            char::from_u32(value).unwrap_or('\u{FFFD}')
        }
    }

    /// Skips input up to and including the matching `)` (the opening `(`
    /// having been consumed). Used to recover after an unsupported
    /// functional pseudo-class.
    fn skip_to_close_paren(&mut self) {
        let mut depth = 1usize;
        while let Some(c) = self.bump() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
    }
}

fn clamp_i32(value: i64) -> Result<i32, SelectorError> {
    i32::try_from(value).map_err(|_err| SelectorError::InvalidNth)
}

/// CSS input preprocessing (CSS Syntax §3.3): a U+0000 NULL input code
/// point is treated as U+FFFD REPLACEMENT CHARACTER. Applying this at the
/// cursor keeps the parser and the CSSOM serializer in agreement, so
/// parsing always round-trips.
fn preprocess(c: char) -> char {
    if c == '\0' { '\u{FFFD}' } else { c }
}

/// CSS whitespace (CSS Syntax §"Whitespace"): space, tab, LF, FF, CR.
fn is_css_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{0c}')
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || !c.is_ascii()
}

fn is_ident_char(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit() || c == '-'
}
