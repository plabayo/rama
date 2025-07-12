//! SSE Parser (for clients)
//!
//! Adapted from original parser implementation
//! <https://github.com/jpopesculian/eventsource-stream/blob/3d46f1c758f9ee4681e9da0427556d24c53f9c01/src/parser.rs>:
//! - by Julian Popescu (hi@julian.dev); License: MIT or Apache 2.0

use nom::branch::alt;
use nom::bytes::streaming::{take_while, take_while_m_n, take_while1};
use nom::character::complete::char;
use nom::combinator::opt;
use nom::sequence::{preceded, terminated};
use nom::{IResult, Parser};

/// ; ABNF definition from HTML spec
///
/// stream        = [ bom ] *event
/// event         = *( comment / field ) end-of-line
/// comment       = colon *any-char end-of-line
/// field         = 1*name-char [ colon [ space ] *any-char ] end-of-line
/// end-of-line   = ( cr lf / cr / lf )
///
/// ; characters
/// lf            = %x000A ; U+000A LINE FEED (LF)
/// cr            = %x000D ; U+000D CARRIAGE RETURN (CR)
/// space         = %x0020 ; U+0020 SPACE
/// colon         = %x003A ; U+003A COLON (:)
/// bom           = %xFEFF ; U+FEFF BYTE ORDER MARK
/// name-char     = %x0000-0009 / %x000B-000C / %x000E-0039 / %x003B-10FFFF
///                 ; a scalar value other than U+000A LINE FEED (LF), U+000D CARRIAGE RETURN (CR), or U+003A COLON (:)
/// any-char      = %x0000-0009 / %x000B-000C / %x000E-10FFFF
///                 ; a scalar value other than U+000A LINE FEED (LF) or U+000D CARRIAGE RETURN (CR)

#[derive(Debug, PartialEq)]
pub(super) enum RawEventLine<'a> {
    Comment(&'a str),
    Field(&'a str, Option<&'a str>),
    Empty,
}

#[inline]
pub(super) fn is_lf(c: char) -> bool {
    c == '\u{000A}'
}

#[inline]
pub(super) fn is_space(c: char) -> bool {
    c == '\u{0020}'
}

#[inline]
pub(super) fn is_colon(c: char) -> bool {
    c == '\u{003A}'
}

#[inline]
pub(super) fn is_bom(c: char) -> bool {
    c == '\u{feff}'
}

#[inline]
pub(super) fn is_name_char(c: char) -> bool {
    matches!(c, '\u{0000}'..='\u{0009}'
        | '\u{000B}'..='\u{000C}'
        | '\u{000E}'..='\u{0039}'
        | '\u{003B}'..='\u{10FFFF}')
}

#[inline]
pub(super) fn is_any_char(c: char) -> bool {
    matches!(c, '\u{0000}'..='\u{0009}'
        | '\u{000B}'..='\u{000C}'
        | '\u{000E}'..='\u{10FFFF}')
}

#[inline]
fn end_of_line(input: &str) -> IResult<&str, ()> {
    let (mut rem, c) = alt((char('\n'), char('\r'))).parse(input)?;
    if c == '\r' {
        rem = opt(char('\n')).parse(rem)?.0;
    }
    Ok((rem, ()))
}

#[inline]
fn comment(input: &str) -> IResult<&str, RawEventLine<'_>> {
    preceded(
        take_while_m_n(1, 1, is_colon),
        terminated(take_while(is_any_char), end_of_line),
    )
    .parse(input)
    .map(|(input, comment)| {
        (
            input,
            RawEventLine::Comment(comment.strip_prefix(' ').unwrap_or(comment)),
        )
    })
}

#[inline]
fn field(input: &str) -> IResult<&str, RawEventLine<'_>> {
    terminated(
        (
            take_while1(is_name_char),
            opt(preceded(
                take_while_m_n(1, 1, is_colon),
                preceded(opt(take_while_m_n(1, 1, is_space)), take_while(is_any_char)),
            )),
        ),
        end_of_line,
    )
    .parse(input)
    .map(|(input, (field, data))| (input, RawEventLine::Field(field, data)))
}

#[inline]
fn empty(input: &str) -> IResult<&str, RawEventLine<'_>> {
    end_of_line(input).map(|(i, _)| (i, RawEventLine::Empty))
}

pub(super) fn line(input: &str) -> IResult<&str, RawEventLine<'_>> {
    alt((comment, field, empty)).parse(input)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_end_of_line() {
        assert_eq!(Ok(("", ())), end_of_line("\u{000A}"));
        assert_eq!(Ok(("", ())), end_of_line("\n"));
        assert_eq!(Ok(("", ())), end_of_line("\r"));
        assert_eq!(Ok(("", ())), end_of_line("\r\n"));
        assert_eq!(Ok(("\n", ())), end_of_line("\n\n"));
    }

    #[test]
    fn test_empty() {
        assert_eq!(Ok(("", RawEventLine::Empty)), empty("\u{000A}"));
        assert_eq!(Ok(("", RawEventLine::Empty)), empty("\n"));
        assert_eq!(Ok(("", RawEventLine::Empty)), empty("\r"));
        assert_eq!(Ok(("", RawEventLine::Empty)), empty("\r\n"));
        assert_eq!(Ok(("\n", RawEventLine::Empty)), empty("\n\n"));
    }
}
