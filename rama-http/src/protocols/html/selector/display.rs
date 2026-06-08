//! Serialization of parsed selectors back to canonical CSS text.
//!
//! Output follows the CSSOM "serialize a selector" rules closely enough to
//! round-trip: parsing the [`Display`] output yields an equal AST. The
//! canonical form is not byte-identical to arbitrary input (whitespace,
//! component order and quoting are normalized).

use std::fmt::{self, Write as _};

use super::ast::{
    AttributeOperator, AttributeSelector, CaseSensitivity, Combinator, ComplexSelector, Compound,
    Nth, Selector,
};

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, complex) in self.selectors.iter().enumerate() {
            if i != 0 {
                f.write_str(", ")?;
            }
            write_complex(f, complex)?;
        }
        Ok(())
    }
}

fn write_complex(f: &mut fmt::Formatter<'_>, complex: &ComplexSelector) -> fmt::Result {
    for part in &complex.parts {
        match part.combinator {
            None => {}
            Some(Combinator::Descendant) => f.write_str(" ")?,
            Some(Combinator::Child) => f.write_str(" > ")?,
        }
        write_compound(f, &part.compound)?;
    }
    Ok(())
}

fn write_compound(f: &mut fmt::Formatter<'_>, compound: &Compound) -> fmt::Result {
    if let Some(name) = &compound.name {
        write_ident(f, name.as_str())?;
    } else if compound.explicit_universal {
        f.write_str("*")?;
    }
    if let Some(id) = &compound.id {
        f.write_str("#")?;
        write_ident(f, id)?;
    }
    for class in &compound.classes {
        f.write_str(".")?;
        write_ident(f, class)?;
    }
    for attr in &compound.attributes {
        write_attribute(f, attr)?;
    }
    for nth in &compound.nth {
        write_nth(f, *nth)?;
    }
    for negation in &compound.negations {
        f.write_str(":not(")?;
        write_compound(f, negation)?;
        f.write_str(")")?;
    }
    Ok(())
}

fn write_attribute(f: &mut fmt::Formatter<'_>, attr: &AttributeSelector) -> fmt::Result {
    f.write_str("[")?;
    write_ident(f, &attr.name)?;
    if let Some(operator) = attr.operator {
        f.write_str(match operator {
            AttributeOperator::Equals => "=",
            AttributeOperator::Includes => "~=",
            AttributeOperator::DashMatch => "|=",
            AttributeOperator::Prefix => "^=",
            AttributeOperator::Suffix => "$=",
            AttributeOperator::Substring => "*=",
        })?;
        write_string(f, &attr.value)?;
        if matches!(attr.case, CaseSensitivity::AsciiCaseInsensitive) {
            f.write_str(" i")?;
        }
    }
    f.write_str("]")
}

fn write_nth(f: &mut fmt::Formatter<'_>, nth: Nth) -> fmt::Result {
    let pseudo = match nth.ty {
        super::ast::NthType::Child => "nth-child",
        super::ast::NthType::OfType => "nth-of-type",
    };
    write!(f, ":{pseudo}(")?;
    if nth.a == 0 {
        write!(f, "{}", nth.b)?;
    } else {
        match nth.a {
            1 => f.write_str("n")?,
            -1 => f.write_str("-n")?,
            a => write!(f, "{a}n")?,
        }
        match nth.b {
            0 => {}
            b if b > 0 => write!(f, "+{b}")?,
            b => write!(f, "{b}")?,
        }
    }
    f.write_str(")")
}

/// Serializes a CSS identifier (CSSOM "serialize an identifier").
fn write_ident(f: &mut fmt::Formatter<'_>, ident: &str) -> fmt::Result {
    for (i, c) in ident.chars().enumerate() {
        match c {
            '\0' => f.write_str("\u{FFFD}")?,
            c if is_control(c) => write_codepoint_escape(f, c)?,
            c if c.is_ascii_digit() && i == 0 => write_codepoint_escape(f, c)?,
            c if c.is_ascii_digit() && i == 1 && ident.starts_with('-') => {
                write_codepoint_escape(f, c)?;
            }
            '-' if i == 0 && ident.len() == 1 => f.write_str("\\-")?,
            c if c == '-' || c == '_' || c.is_ascii_alphanumeric() || !c.is_ascii() => {
                f.write_char(c)?;
            }
            c => write!(f, "\\{c}")?,
        }
    }
    Ok(())
}

/// Serializes a CSS string (CSSOM "serialize a string").
fn write_string(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    f.write_str("\"")?;
    for c in value.chars() {
        match c {
            '\0' => f.write_str("\u{FFFD}")?,
            c if is_control(c) => write_codepoint_escape(f, c)?,
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            c => f.write_char(c)?,
        }
    }
    f.write_str("\"")
}

fn write_codepoint_escape(f: &mut fmt::Formatter<'_>, c: char) -> fmt::Result {
    write!(f, "\\{:x} ", c as u32)
}

fn is_control(c: char) -> bool {
    let n = c as u32;
    (0x1..=0x1F).contains(&n) || n == 0x7F
}
