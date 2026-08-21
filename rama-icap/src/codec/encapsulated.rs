use crate::{
    byte_sets::is_horizontal_whitespace_byte,
    proto::{EncapsulatedKind, EncapsulatedSection, InvalidEncapsulated},
};

use super::EncodeError;
use super::head::Output;

/// A structurally valid, borrowed `Encapsulated` header value.
#[derive(Clone, Copy, Debug)]
pub struct Encapsulated<'a> {
    raw: &'a [u8],
    section_count: usize,
}

impl PartialEq for Encapsulated<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for Encapsulated<'_> {}

impl<'a> Encapsulated<'a> {
    /// Return the number of encapsulated sections.
    #[must_use]
    pub const fn section_count(self) -> usize {
        self.section_count
    }

    /// Iterate over the encapsulated sections.
    pub const fn iter(self) -> EncapsulatedIter<'a> {
        EncapsulatedIter {
            remaining: self.raw,
        }
    }

    /// Find the offset for an encapsulated entity kind.
    #[must_use]
    pub fn offset(self, kind: EncapsulatedKind) -> Option<u64> {
        self.iter()
            .find(|section| section.kind() == kind)
            .map(EncapsulatedSection::offset)
    }

    /// Validate this composition for an ICAP method and message direction.
    pub fn validate(self, context: EncapsulatedContext) -> Result<(), InvalidEncapsulated> {
        validate_context(self.iter(), context)
    }
}

/// Method and direction used for `Encapsulated` composition validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncapsulatedContext {
    /// A REQMOD request.
    ReqmodRequest,
    /// A body-bearing response to REQMOD.
    ReqmodResponse,
    /// A RESPMOD request.
    RespmodRequest,
    /// A body-bearing response to RESPMOD.
    RespmodResponse,
    /// An OPTIONS request.
    OptionsRequest,
    /// A body-bearing response to OPTIONS.
    OptionsResponse,
}

impl<'a> IntoIterator for Encapsulated<'a> {
    type Item = EncapsulatedSection;
    type IntoIter = EncapsulatedIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &Encapsulated<'a> {
    type Item = EncapsulatedSection;
    type IntoIter = EncapsulatedIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator returned by [`Encapsulated::iter`].
#[derive(Clone, Debug)]
pub struct EncapsulatedIter<'a> {
    remaining: &'a [u8],
}

impl Iterator for EncapsulatedIter<'_> {
    type Item = EncapsulatedSection;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let (section, consumed) = parse_section(self.remaining).ok()?;
        self.remaining = consume_separator(&self.remaining[consumed..]).ok()?;
        Some(section)
    }
}

/// Parse and structurally validate an `Encapsulated` header value.
///
/// Call [`Encapsulated::validate`] once the ICAP method and message direction
/// are known.
pub fn parse_encapsulated(value: &[u8]) -> Result<Encapsulated<'_>, InvalidEncapsulated> {
    let mut remaining = trim_whitespace(value);
    if remaining.is_empty() {
        return Err(InvalidEncapsulated);
    }

    let raw = remaining;
    let mut count = 0;
    let mut sections = [
        EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
        EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
        EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
    ];
    while !remaining.is_empty() {
        let (section, consumed) = parse_section(remaining)?;
        if count == sections.len() {
            return Err(InvalidEncapsulated);
        }
        sections[count] = section;
        count += 1;
        remaining = consume_separator(&remaining[consumed..])?;
    }
    validate_sections(&sections[..count])?;

    Ok(Encapsulated {
        raw,
        section_count: count,
    })
}

impl<'a> TryFrom<&'a [u8]> for Encapsulated<'a> {
    type Error = InvalidEncapsulated;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        parse_encapsulated(value)
    }
}

impl<'a> TryFrom<&'a str> for Encapsulated<'a> {
    type Error = InvalidEncapsulated;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        parse_encapsulated(value.as_bytes())
    }
}

/// Encode a structurally valid sequence for an `Encapsulated` header value.
pub fn encode_encapsulated(
    sections: &[EncapsulatedSection],
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    validate_sections(sections).map_err(|_invalid_sections| EncodeError::InvalidInput)?;
    let mut dst = Output::new(dst);
    for (index, section) in sections.iter().copied().enumerate() {
        if index != 0 {
            dst.put(b", ")?;
        }
        dst.put(section.kind().as_str().as_bytes())?;
        dst.put(b"=")?;
        put_decimal(section.offset(), &mut dst)?;
    }
    Ok(dst.len())
}

fn validate_sections(sections: &[EncapsulatedSection]) -> Result<(), InvalidEncapsulated> {
    if sections.is_empty() {
        return Err(InvalidEncapsulated);
    }
    if sections.len() > 3 {
        return Err(InvalidEncapsulated);
    }
    let mut previous_offset = None;
    for (index, section) in sections.iter().copied().enumerate() {
        if index == 0 && section.offset() != 0 {
            return Err(InvalidEncapsulated);
        }
        if previous_offset.is_some_and(|offset| section.offset() <= offset) {
            return Err(InvalidEncapsulated);
        }
        previous_offset = Some(section.offset());
    }
    if valid_shape(sections) {
        Ok(())
    } else {
        Err(InvalidEncapsulated)
    }
}

fn valid_shape(sections: &[EncapsulatedSection]) -> bool {
    use EncapsulatedKind::{
        NullBody, OptionsBody, RequestBody, RequestHeader, ResponseBody, ResponseHeader,
    };

    let kind = |index: usize| sections.get(index).map(|section| section.kind());
    match sections.len() {
        1 => matches!(
            kind(0),
            Some(RequestBody | ResponseBody | OptionsBody | NullBody)
        ),
        2 => matches!(
            (kind(0), kind(1)),
            (
                Some(RequestHeader),
                Some(RequestBody | ResponseBody | NullBody)
            ) | (Some(ResponseHeader), Some(ResponseBody | NullBody))
        ),
        3 => matches!(
            (kind(0), kind(1), kind(2)),
            (
                Some(RequestHeader),
                Some(ResponseHeader),
                Some(ResponseBody | NullBody)
            )
        ),
        _ => false,
    }
}

fn validate_context(
    sections: impl Iterator<Item = EncapsulatedSection>,
    context: EncapsulatedContext,
) -> Result<(), InvalidEncapsulated> {
    use EncapsulatedKind::{
        NullBody, OptionsBody, RequestBody, RequestHeader, ResponseBody, ResponseHeader,
    };

    let mut kinds = [NullBody; 3];
    let mut count = 0;
    for section in sections {
        if count == kinds.len() {
            return Err(InvalidEncapsulated);
        }
        kinds[count] = section.kind();
        count += 1;
    }
    let kinds = &kinds[..count];
    let reqmod_request = matches!(
        kinds,
        [RequestBody] | [RequestHeader, RequestBody | NullBody]
    );
    let reqmod_response = matches!(
        kinds,
        [RequestBody | NullBody] | [RequestHeader, RequestBody | NullBody]
    );
    let respmod_response = matches!(
        kinds,
        [ResponseBody | NullBody] | [ResponseHeader, ResponseBody | NullBody]
    );
    let respmod_request = matches!(
        kinds,
        [ResponseBody]
            | [ResponseHeader, ResponseBody | NullBody]
            | [RequestHeader, ResponseBody]
            | [RequestHeader, ResponseHeader, ResponseBody | NullBody]
    );
    let options = matches!(kinds, [OptionsBody | NullBody]);
    let valid = match context {
        EncapsulatedContext::ReqmodRequest => reqmod_request,
        EncapsulatedContext::ReqmodResponse => reqmod_response || respmod_response,
        EncapsulatedContext::RespmodRequest => respmod_request,
        EncapsulatedContext::RespmodResponse => respmod_response,
        EncapsulatedContext::OptionsRequest | EncapsulatedContext::OptionsResponse => options,
    };
    if valid {
        Ok(())
    } else {
        Err(InvalidEncapsulated)
    }
}

fn parse_section(value: &[u8]) -> Result<(EncapsulatedSection, usize), InvalidEncapsulated> {
    let name_end = value
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(InvalidEncapsulated)?;
    let name = trim_end(&value[..name_end]);
    let kind = EncapsulatedKind::from_bytes(name)?;
    let offset_start = name_end
        + 1
        + value[name_end + 1..]
            .iter()
            .take_while(|byte| is_horizontal_whitespace_byte(**byte))
            .count();
    let mut offset_end = offset_start;
    while value
        .get(offset_end)
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        offset_end += 1;
    }
    if offset_end == offset_start {
        return Err(InvalidEncapsulated);
    }
    let offset = parse_decimal(&value[offset_start..offset_end])?;
    let consumed = offset_end;
    let tail = &value[consumed..];
    if !trim_start(tail).is_empty() && !trim_start(tail).starts_with(b",") {
        return Err(InvalidEncapsulated);
    }
    Ok((EncapsulatedSection::new(kind, offset), consumed))
}

fn consume_separator(value: &[u8]) -> Result<&[u8], InvalidEncapsulated> {
    let value = trim_start(value);
    if value.is_empty() {
        return Ok(value);
    }
    let value = value.strip_prefix(b",").ok_or(InvalidEncapsulated)?;
    let value = trim_start(value);
    if value.is_empty() {
        Err(InvalidEncapsulated)
    } else {
        Ok(value)
    }
}

fn parse_decimal(value: &[u8]) -> Result<u64, InvalidEncapsulated> {
    value.iter().try_fold(0_u64, |result, byte| {
        if !byte.is_ascii_digit() {
            return Err(InvalidEncapsulated);
        }
        let digit = u64::from(byte - b'0');
        result
            .checked_mul(10)
            .and_then(|result| result.checked_add(digit))
            .ok_or(InvalidEncapsulated)
    })
}

fn put_decimal(mut value: u64, dst: &mut Output<'_>) -> Result<(), EncodeError> {
    // Twenty decimal digits are sufficient for every `u64` value.
    let mut digits = [0; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        let digit =
            u8::try_from(value % 10).map_err(|_conversion_error| EncodeError::InvalidInput)?;
        digits[start] = b'0' + digit;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    dst.put(&digits[start..])
}

fn trim_whitespace(value: &[u8]) -> &[u8] {
    trim_end(trim_start(value))
}

fn trim_start(mut value: &[u8]) -> &[u8] {
    while let Some((byte, rest)) = value.split_first() {
        if !is_horizontal_whitespace_byte(*byte) {
            break;
        }
        value = rest;
    }
    value
}

fn trim_end(mut value: &[u8]) -> &[u8] {
    while let Some((byte, rest)) = value.split_last() {
        if !is_horizontal_whitespace_byte(*byte) {
            break;
        }
        value = rest;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc_examples() {
        let value = parse_encapsulated(b"req-hdr=0, res-hdr=822, res-body=1655").unwrap();
        assert_eq!(value.section_count(), 3);
        assert_eq!(value.offset(EncapsulatedKind::RequestHeader), Some(0));
        assert_eq!(value.offset(EncapsulatedKind::ResponseHeader), Some(822));
        assert_eq!(value.offset(EncapsulatedKind::ResponseBody), Some(1655));
        assert_eq!(
            parse_encapsulated(b"null-body=0").unwrap().section_count(),
            1
        );
    }

    #[test]
    fn rejects_invalid_section_layouts() {
        for value in [
            b"".as_slice(),
            b"   ".as_slice(),
            b"req-hdr=1, null-body=2".as_slice(),
            b"req-hdr=0, res-hdr=10".as_slice(),
            b"req-hdr=0, req-body=10, res-body=20".as_slice(),
            b"req-hdr=0, req-hdr=10, null-body=20".as_slice(),
            b"res-hdr=0, res-hdr=10, null-body=20".as_slice(),
            b"req-hdr=0, res-hdr=1, req-hdr=2".as_slice(),
            b"req-hdr=0, res-hdr=10, res-body=5".as_slice(),
            b"res-hdr=10, res-body=0".as_slice(),
            b"res-hdr=0, req-hdr=1, null-body=2".as_slice(),
            b"req-hdr=0, res-hdr=1, req-body=2".as_slice(),
            b"req-hdr=0, opt-body=1".as_slice(),
            b"req-hdr=0, null-body=0".as_slice(),
            b"req-hdr=0, res-hdr=1, opt-body=2, null-body=3".as_slice(),
            b"null-body=".as_slice(),
            b"null-body=x".as_slice(),
            b"null-body=0x".as_slice(),
            b"null-body=0,".as_slice(),
        ] {
            assert_eq!(parse_encapsulated(value), Err(InvalidEncapsulated));
        }
    }

    #[test]
    fn validates_rfc_method_and_direction_compositions() {
        let cases: &[(&[u8], EncapsulatedContext)] = &[
            (
                b"req-hdr=0, req-body=12",
                EncapsulatedContext::ReqmodRequest,
            ),
            (b"req-body=0", EncapsulatedContext::ReqmodRequest),
            (
                b"res-hdr=0, res-body=12",
                EncapsulatedContext::ReqmodResponse,
            ),
            (
                b"req-hdr=0, res-hdr=12, res-body=24",
                EncapsulatedContext::RespmodRequest,
            ),
            (
                b"req-hdr=0, res-body=12",
                EncapsulatedContext::RespmodRequest,
            ),
            (b"res-body=0", EncapsulatedContext::RespmodRequest),
            (
                b"res-hdr=0, null-body=12",
                EncapsulatedContext::RespmodResponse,
            ),
            (b"opt-body=0", EncapsulatedContext::OptionsRequest),
            (b"null-body=0", EncapsulatedContext::OptionsResponse),
        ];
        for (wire, context) in cases {
            parse_encapsulated(wire)
                .unwrap()
                .validate(*context)
                .unwrap();
        }

        let request = parse_encapsulated(b"req-hdr=0, req-body=12").unwrap();
        assert_eq!(
            request.validate(EncapsulatedContext::RespmodResponse),
            Err(InvalidEncapsulated)
        );
        let options = parse_encapsulated(b"opt-body=0").unwrap();
        assert_eq!(
            options.validate(EncapsulatedContext::ReqmodRequest),
            Err(InvalidEncapsulated)
        );
        let response = parse_encapsulated(b"res-hdr=0, res-body=12").unwrap();
        assert_eq!(
            response.validate(EncapsulatedContext::ReqmodRequest),
            Err(InvalidEncapsulated)
        );
        let null = parse_encapsulated(b"null-body=0").unwrap();
        assert_eq!(
            null.validate(EncapsulatedContext::ReqmodRequest),
            Err(InvalidEncapsulated)
        );
        assert_eq!(
            null.validate(EncapsulatedContext::RespmodRequest),
            Err(InvalidEncapsulated)
        );
        let request_only = parse_encapsulated(b"req-hdr=0, null-body=12").unwrap();
        assert_eq!(
            request_only.validate(EncapsulatedContext::RespmodRequest),
            Err(InvalidEncapsulated)
        );
    }

    #[test]
    fn rejects_decimal_overflow() {
        assert_eq!(
            parse_encapsulated(b"null-body=999999999999999999999999999999999999"),
            Err(InvalidEncapsulated)
        );
    }

    #[test]
    fn encapsulated_round_trip() {
        let sections = [
            EncapsulatedSection::new(EncapsulatedKind::RequestHeader, 0),
            EncapsulatedSection::new(EncapsulatedKind::RequestBody, 412),
        ];
        let mut dst = [0; 64];
        let len = encode_encapsulated(&sections, &mut dst).unwrap();
        let parsed = parse_encapsulated(&dst[..len]).unwrap();
        assert_eq!(parsed.iter().collect::<std::vec::Vec<_>>(), sections);
        assert_eq!(
            parsed,
            parse_encapsulated(b"req-hdr = 0 , req-body = 412").unwrap()
        );
    }

    #[test]
    fn encapsulated_equality_is_semantic() {
        let compact = parse_encapsulated(b"req-hdr=0,null-body=5").unwrap();
        let spaced = parse_encapsulated(b" req-hdr = 0, null-body = 5 ").unwrap();
        assert_eq!(compact, spaced);
        assert_ne!(
            compact,
            parse_encapsulated(b"req-hdr=0,null-body=6").unwrap()
        );

        let sections = compact.iter().collect::<std::vec::Vec<_>>();
        let mut encoded = [0; 64];
        let len = encode_encapsulated(&sections, &mut encoded).unwrap();
        assert_eq!(compact, parse_encapsulated(&encoded[..len]).unwrap());
    }

    #[test]
    fn accepts_three_sections_and_surrounding_whitespace() {
        let value = parse_encapsulated(b"  req-hdr=0, res-hdr=17, res-body=123  ").unwrap();
        assert_eq!(value.section_count(), 3);
        assert_eq!(value.into_iter().count(), 3);

        assert_eq!(
            parse_encapsulated(b"req-hdr=0, null-body=0"),
            Err(InvalidEncapsulated)
        );
    }

    #[test]
    fn encoder_rejects_every_invalid_layout_class() {
        let request_header = EncapsulatedSection::new(EncapsulatedKind::RequestHeader, 0);
        let response_header = EncapsulatedSection::new(EncapsulatedKind::ResponseHeader, 10);
        let request_body = EncapsulatedSection::new(EncapsulatedKind::RequestBody, 20);
        let null_body = EncapsulatedSection::new(EncapsulatedKind::NullBody, 20);
        let mut dst = [0; 128];

        let invalid: &[&[EncapsulatedSection]] = &[
            &[],
            &[request_header, response_header, request_body, null_body],
            &[EncapsulatedSection::new(EncapsulatedKind::NullBody, 1)],
            &[null_body, request_header],
            &[
                request_header,
                response_header,
                EncapsulatedSection::new(EncapsulatedKind::NullBody, 9),
            ],
            &[request_header, request_header, null_body],
            &[request_header, response_header],
            &[
                request_header,
                response_header,
                request_body,
                null_body,
                null_body,
            ],
        ];
        for sections in invalid {
            assert_eq!(
                encode_encapsulated(sections, &mut dst),
                Err(EncodeError::InvalidInput)
            );
        }

        let valid = [
            request_header,
            response_header,
            EncapsulatedSection::new(EncapsulatedKind::ResponseBody, 20),
        ];
        encode_encapsulated(&valid, &mut dst).unwrap();
    }

    #[test]
    fn encoder_handles_decimal_boundaries_and_exact_buffers() {
        for offset in [1, 9, 10, u64::MAX] {
            let expected = std::format!("req-hdr=0, null-body={offset}");
            let header = EncapsulatedSection::new(EncapsulatedKind::RequestHeader, 0);
            let section = EncapsulatedSection::new(EncapsulatedKind::NullBody, offset);
            let mut dst = [0; 64];
            let len = encode_encapsulated(&[header, section], &mut dst).unwrap();
            assert_eq!(&dst[..len], expected.as_bytes());
            assert_eq!(
                encode_encapsulated(&[header, section], &mut dst[..len - 1]),
                Err(EncodeError::BufferTooSmall)
            );
        }

        let section = EncapsulatedSection::new(EncapsulatedKind::NullBody, 0);
        let mut dst = [0; 64];
        let len = encode_encapsulated(&[section], &mut dst).unwrap();
        assert_eq!(&dst[..len], b"null-body=0");
    }
}
