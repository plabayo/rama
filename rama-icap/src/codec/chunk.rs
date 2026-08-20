use core::fmt;

use crate::proto::is_token;

use super::head::Output;
use super::{EncodeError, ParseStatus};

/// Default maximum encoded size of an ICAP chunk-size line.
pub const DEFAULT_MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;

/// A borrowed chunk extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkExtension<'a> {
    name: &'a str,
    value: Option<&'a [u8]>,
}

impl<'a> ChunkExtension<'a> {
    /// Construct a chunk extension.
    ///
    /// A quoted value includes its surrounding double quotes.
    pub fn new(name: &'a str, value: Option<&'a [u8]>) -> Result<Self, InvalidChunkLine> {
        if !is_token(name.as_bytes()) || value.is_some_and(|value| !valid_extension_value(value)) {
            return Err(InvalidChunkLine);
        }
        let extension = Self { name, value };
        validate_reserved_extension(extension)?;
        Ok(extension)
    }

    /// Return the case-preserving extension name.
    #[must_use]
    pub const fn name(self) -> &'a str {
        self.name
    }

    /// Return the optional raw token or quoted value.
    #[must_use]
    pub const fn value(self) -> Option<&'a [u8]> {
        self.value
    }

    /// Return whether this is the valueless ICAP `ieof` extension.
    #[must_use]
    pub fn is_ieof(self) -> bool {
        self.value.is_none() && self.name.eq_ignore_ascii_case("ieof")
    }

    /// Parse this extension as a wire-width `use-original-body=N` offset.
    ///
    /// Consumers must use checked conversion and verify the offset against
    /// the retained original body before indexing it.
    pub fn use_original_body(self) -> Result<Option<u64>, InvalidChunkLine> {
        if !self.name.eq_ignore_ascii_case("use-original-body") {
            return Ok(None);
        }
        let value = self.value.ok_or(InvalidChunkLine)?;
        parse_decimal(value).map(Some)
    }

    /// Convert a `use-original-body=N` offset without truncation.
    ///
    /// The result must still be checked against the retained original body.
    pub fn use_original_body_usize(self) -> Result<Option<usize>, InvalidChunkLine> {
        self.use_original_body()?
            .map(usize::try_from)
            .transpose()
            .map_err(|_conversion_error| InvalidChunkLine)
    }
}

/// An iterator over a validated chunk extension sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkExtensions<'a> {
    raw: &'a [u8],
}

impl<'a> ChunkExtensions<'a> {
    fn new(raw: &'a [u8]) -> Result<Self, InvalidChunkLine> {
        validate_extensions(raw)?;
        Ok(Self { raw })
    }

    /// Return an empty extension sequence.
    #[must_use]
    pub const fn empty() -> Self {
        Self { raw: b"" }
    }

    /// Iterate over the extensions.
    pub fn iter(&self) -> ChunkExtensionIter<'a> {
        ChunkExtensionIter {
            remaining: self.raw,
        }
    }

    /// Return whether the sequence contains the ICAP `ieof` extension.
    #[must_use]
    pub fn has_ieof(&self) -> bool {
        self.iter().any(ChunkExtension::is_ieof)
    }
}

impl<'a> IntoIterator for &ChunkExtensions<'a> {
    type Item = ChunkExtension<'a>;
    type IntoIter = ChunkExtensionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator returned by [`ChunkExtensions::iter`].
#[derive(Clone, Debug)]
pub struct ChunkExtensionIter<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for ChunkExtensionIter<'a> {
    type Item = ChunkExtension<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let (extension, consumed) = parse_extension(self.remaining).ok()?;
        self.remaining = &self.remaining[consumed..];
        Some(extension)
    }
}

/// A decoded ICAP chunk-size line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkLine<'a> {
    size: u64,
    extensions: ChunkExtensions<'a>,
}

impl<'a> ChunkLine<'a> {
    /// Return the chunk data length as a wire-width counter.
    ///
    /// Consumers must use checked conversion and checked streaming counters;
    /// a declared size larger than the available body is a transaction error.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Convert the chunk data length to a platform index without truncation.
    ///
    /// The result must still be checked against the available body length.
    #[must_use]
    pub fn size_usize(&self) -> Option<usize> {
        usize::try_from(self.size).ok()
    }

    /// Return the parsed chunk extensions.
    #[must_use]
    pub const fn extensions(&self) -> &ChunkExtensions<'a> {
        &self.extensions
    }

    /// Return whether this line marks Preview end-of-file.
    #[must_use]
    pub fn is_ieof(&self) -> bool {
        self.size == 0 && self.extensions.has_ieof()
    }

    /// Return the wire-width original body offset of a partial response.
    ///
    /// Consumers must use checked conversion and verify the offset against
    /// the retained original body before indexing it.
    pub fn use_original_body(&self) -> Result<Option<u64>, InvalidChunkLine> {
        if self.size != 0 {
            return Ok(None);
        }
        for extension in &self.extensions {
            if let Some(offset) = extension.use_original_body()? {
                return Ok(Some(offset));
            }
        }
        Ok(None)
    }

    /// Convert the original body offset without truncation.
    ///
    /// The result must still be checked against the retained original body.
    pub fn use_original_body_usize(&self) -> Result<Option<usize>, InvalidChunkLine> {
        self.use_original_body()?
            .map(usize::try_from)
            .transpose()
            .map_err(|_conversion_error| InvalidChunkLine)
    }
}

/// A malformed or overflowing ICAP chunk-size line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidChunkLine;

impl fmt::Display for InvalidChunkLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ICAP chunk line")
    }
}

impl core::error::Error for InvalidChunkLine {}

/// An ICAP chunk-size line could not be decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkLineError {
    /// The line does not follow the chunk-size grammar.
    InvalidSyntax,
    /// The configured encoded line size was exceeded.
    LineTooLong,
}

impl fmt::Display for ChunkLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSyntax => "invalid ICAP chunk line",
            Self::LineTooLong => "ICAP chunk line is too long",
        })
    }
}

impl core::error::Error for ChunkLineError {}

impl From<InvalidChunkLine> for ChunkLineError {
    fn from(_: InvalidChunkLine) -> Self {
        Self::InvalidSyntax
    }
}

/// Incremental, allocation-free chunk-line terminator scanner.
///
/// The caller must preserve the already scanned prefix between calls. Once a
/// complete line is found, later calls return the same consumed byte count
/// until [`ChunkLineScanner::reset`] is called.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChunkLineScanner {
    scanned: usize,
    complete: Option<usize>,
}

impl ChunkLineScanner {
    /// Construct an empty scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scanned: 0,
            complete: None,
        }
    }

    /// Scan newly appended bytes for the end of a chunk-size line.
    pub fn scan(
        &mut self,
        src: &[u8],
        max_bytes: usize,
    ) -> Result<ParseStatus<()>, ChunkLineError> {
        if let Some(consumed) = self.complete {
            return Ok(ParseStatus::Complete((), consumed));
        }
        if src.len() < self.scanned {
            self.scanned = 0;
        }
        let bounded_len = src.len().min(max_bytes);
        if bounded_len < self.scanned {
            self.scanned = 0;
        }
        let start = self.scanned.saturating_sub(1);
        for index in start..bounded_len {
            match src[index] {
                b'\n' => {
                    if index == 0 || src[index - 1] != b'\r' {
                        return Err(ChunkLineError::InvalidSyntax);
                    }
                    let consumed = index + 1;
                    self.scanned = consumed;
                    self.complete = Some(consumed);
                    return Ok(ParseStatus::Complete((), consumed));
                }
                b'\r' if index + 1 < bounded_len && src[index + 1] != b'\n' => {
                    return Err(ChunkLineError::InvalidSyntax);
                }
                _ => {}
            }
        }
        self.scanned = bounded_len;
        if src.len() > max_bytes {
            Err(ChunkLineError::LineTooLong)
        } else {
            Ok(ParseStatus::Partial)
        }
    }

    /// Reset the scanner for the next line.
    pub const fn reset(&mut self) {
        self.scanned = 0;
        self.complete = None;
    }
}

/// Parse an ICAP chunk-size line, including Preview extensions.
pub fn parse_chunk_line(src: &[u8]) -> Result<ParseStatus<ChunkLine<'_>>, ChunkLineError> {
    parse_chunk_line_with_limit(src, DEFAULT_MAX_CHUNK_LINE_BYTES)
}

/// Parse an ICAP chunk-size line with an explicit encoded size bound.
pub fn parse_chunk_line_with_limit(
    src: &[u8],
    max_bytes: usize,
) -> Result<ParseStatus<ChunkLine<'_>>, ChunkLineError> {
    let bounded_len = src.len().min(max_bytes);
    match parse_chunk_line_inner(&src[..bounded_len])? {
        ParseStatus::Partial if src.len() > max_bytes => Err(ChunkLineError::LineTooLong),
        status => Ok(status),
    }
}

fn parse_chunk_line_inner(src: &[u8]) -> Result<ParseStatus<ChunkLine<'_>>, InvalidChunkLine> {
    let Some(line_end) = find_crlf(src)? else {
        return Ok(ParseStatus::Partial);
    };
    let line = &src[..line_end];
    let mut digit_end = 0;
    while line
        .get(digit_end)
        .is_some_and(|byte| byte.is_ascii_hexdigit())
    {
        digit_end += 1;
    }
    if digit_end == 0 {
        return Err(InvalidChunkLine);
    }
    let size = parse_hex(&line[..digit_end])?;
    let mut extension_start = digit_end;
    while line
        .get(extension_start)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        extension_start += 1;
    }
    let extensions = ChunkExtensions::new(&line[extension_start..])?;
    validate_reserved_extensions(size, extensions.iter())?;
    Ok(ParseStatus::Complete(
        ChunkLine { size, extensions },
        line_end + 2,
    ))
}

/// Encode an ICAP chunk-size line into `dst`.
pub fn encode_chunk_line(
    size: u64,
    extensions: &[ChunkExtension<'_>],
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    validate_reserved_extensions(size, extensions.iter().copied())
        .map_err(|_error| EncodeError::InvalidInput)?;
    let mut dst = Output::new(dst);
    let mut digits = [0; 16];
    let mut value = size;
    let mut start = digits.len();
    loop {
        start -= 1;
        let digit =
            u8::try_from(value & 0xf).map_err(|_conversion_error| EncodeError::InvalidInput)?;
        digits[start] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        value >>= 4;
        if value == 0 {
            break;
        }
    }
    dst.put(&digits[start..])?;
    for extension in extensions {
        dst.put(b"; ")?;
        dst.put(extension.name.as_bytes())?;
        if let Some(value) = extension.value {
            dst.put(b"=")?;
            dst.put(value)?;
        }
    }
    dst.put(b"\r\n")?;
    Ok(dst.len())
}

fn find_crlf(src: &[u8]) -> Result<Option<usize>, InvalidChunkLine> {
    for (index, byte) in src.iter().copied().enumerate() {
        match byte {
            b'\n' => {
                if index == 0 || src[index - 1] != b'\r' {
                    return Err(InvalidChunkLine);
                }
                return Ok(Some(index - 1));
            }
            b'\r' if src.get(index + 1).is_some_and(|byte| *byte != b'\n') => {
                return Err(InvalidChunkLine);
            }
            _ => {}
        }
    }
    Ok(None)
}

fn parse_hex(value: &[u8]) -> Result<u64, InvalidChunkLine> {
    value.iter().try_fold(0_u64, |result, byte| {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return Err(InvalidChunkLine),
        };
        result
            .checked_mul(16)
            .and_then(|result| result.checked_add(digit))
            .ok_or(InvalidChunkLine)
    })
}

fn parse_decimal(value: &[u8]) -> Result<u64, InvalidChunkLine> {
    if value.is_empty() {
        return Err(InvalidChunkLine);
    }
    value.iter().try_fold(0_u64, |result, byte| {
        if !byte.is_ascii_digit() {
            return Err(InvalidChunkLine);
        }
        let digit = u64::from(byte - b'0');
        result
            .checked_mul(10)
            .and_then(|result| result.checked_add(digit))
            .ok_or(InvalidChunkLine)
    })
}

fn validate_reserved_extension(extension: ChunkExtension<'_>) -> Result<(), InvalidChunkLine> {
    if extension.name.eq_ignore_ascii_case("ieof") {
        if extension.value.is_some() {
            return Err(InvalidChunkLine);
        }
    } else if extension.name.eq_ignore_ascii_case("use-original-body") {
        let value = extension.value.ok_or(InvalidChunkLine)?;
        parse_decimal(value)?;
    }
    Ok(())
}

fn validate_reserved_extensions<'a>(
    size: u64,
    extensions: impl IntoIterator<Item = ChunkExtension<'a>>,
) -> Result<(), InvalidChunkLine> {
    let mut saw_ieof = false;
    let mut saw_original_body = false;
    for extension in extensions {
        validate_reserved_extension(extension)?;
        let seen = if extension.name.eq_ignore_ascii_case("ieof") {
            &mut saw_ieof
        } else if extension.name.eq_ignore_ascii_case("use-original-body") {
            &mut saw_original_body
        } else {
            continue;
        };
        if size != 0 || core::mem::replace(seen, true) {
            return Err(InvalidChunkLine);
        }
    }
    if saw_ieof && saw_original_body {
        Err(InvalidChunkLine)
    } else {
        Ok(())
    }
}

fn validate_extensions(mut value: &[u8]) -> Result<(), InvalidChunkLine> {
    while !value.is_empty() {
        let (_, consumed) = parse_extension(value)?;
        value = &value[consumed..];
    }
    Ok(())
}

fn parse_extension(value: &[u8]) -> Result<(ChunkExtension<'_>, usize), InvalidChunkLine> {
    let mut offset = skip_whitespace(value, 0);
    if value.get(offset) != Some(&b';') {
        return Err(InvalidChunkLine);
    }
    offset += 1;
    offset = skip_whitespace(value, offset);
    let name_start = offset;
    while value
        .get(offset)
        .is_some_and(|byte| crate::proto::is_token_byte(*byte))
    {
        offset += 1;
    }
    if offset == name_start {
        return Err(InvalidChunkLine);
    }
    let name =
        core::str::from_utf8(&value[name_start..offset]).map_err(|_utf8_error| InvalidChunkLine)?;
    offset = skip_whitespace(value, offset);
    let extension_value = if value.get(offset) == Some(&b'=') {
        offset += 1;
        offset = skip_whitespace(value, offset);
        let value_start = offset;
        offset = parse_extension_value(value, offset)?;
        Some(&value[value_start..offset])
    } else {
        None
    };
    offset = skip_whitespace(value, offset);
    if value.get(offset).is_some_and(|byte| *byte != b';') {
        return Err(InvalidChunkLine);
    }
    Ok((
        ChunkExtension {
            name,
            value: extension_value,
        },
        offset,
    ))
}

fn parse_extension_value(value: &[u8], offset: usize) -> Result<usize, InvalidChunkLine> {
    if value.get(offset) == Some(&b'"') {
        let mut index = offset + 1;
        while let Some(byte) = value.get(index).copied() {
            match byte {
                b'"' => return Ok(index + 1),
                b'\\' => {
                    let escaped = value.get(index + 1).ok_or(InvalidChunkLine)?;
                    if !matches!(escaped, b'\t' | b' '..=b'~' | 0x80..=0xff) {
                        return Err(InvalidChunkLine);
                    }
                    index += 2;
                }
                b'\t' | b' '..=b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff => index += 1,
                _ => return Err(InvalidChunkLine),
            }
        }
        Err(InvalidChunkLine)
    } else {
        let mut index = offset;
        while value
            .get(index)
            .is_some_and(|byte| crate::proto::is_token_byte(*byte))
        {
            index += 1;
        }
        if index == offset {
            Err(InvalidChunkLine)
        } else {
            Ok(index)
        }
    }
}

fn valid_extension_value(value: &[u8]) -> bool {
    parse_extension_value(value, 0) == Ok(value.len())
}

fn skip_whitespace(value: &[u8], mut offset: usize) -> usize {
    while value
        .get(offset)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        offset += 1;
    }
    offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_and_preview_terminators() {
        let ParseStatus::Complete(line, consumed) = parse_chunk_line(b"0; ieof\r\nrest").unwrap()
        else {
            panic!("complete line expected");
        };
        assert_eq!(line.size(), 0);
        assert!(line.is_ieof());
        assert_eq!(consumed, 9);

        let ParseStatus::Complete(line, _) = parse_chunk_line(b"0\r\n").unwrap() else {
            panic!("complete line expected");
        };
        assert!(!line.is_ieof());

        assert_eq!(
            parse_chunk_line(b"0; ieof=value\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );

        let ParseStatus::Complete(line, _) = parse_chunk_line(b"0; other\r\n").unwrap() else {
            panic!("complete line expected");
        };
        assert!(!line.is_ieof());
    }

    #[test]
    fn parses_generic_extensions_without_copying() {
        let src = b"2a; foo=bar; quoted=\"a;b\"\r\n";
        let ParseStatus::Complete(line, consumed) = parse_chunk_line(src).unwrap() else {
            panic!("complete line expected");
        };
        let extensions: std::vec::Vec<_> = line.extensions().iter().collect();
        assert_eq!(line.size(), 42);
        assert_eq!(line.size_usize(), Some(42));
        assert_eq!(consumed, src.len());
        assert_eq!(extensions[0].name(), "foo");
        assert_eq!(extensions[0].value(), Some(b"bar".as_slice()));
        assert_eq!(extensions[1].value(), Some(b"\"a;b\"".as_slice()));
    }

    #[test]
    fn parses_uppercase_hex_and_quoted_escapes() {
        let wire = b"ABCDEF; quoted=\"a\\\"b\\\\c\"\r\n";
        let ParseStatus::Complete(line, consumed) = parse_chunk_line(wire).unwrap() else {
            panic!("complete line expected");
        };
        assert_eq!(line.size(), 0xabcdef);
        assert_eq!(consumed, wire.len());
        let extension = line.extensions().iter().next().unwrap();
        assert_eq!(extension.name(), "quoted");
        assert_eq!(extension.value(), Some(b"\"a\\\"b\\\\c\"".as_slice()));

        let ParseStatus::Complete(line, _) = parse_chunk_line(b"0 \t; ieof\r\n").unwrap() else {
            panic!("complete line expected");
        };
        assert!(line.is_ieof());
    }

    #[test]
    fn parses_partial_content_original_body_offset() {
        let ParseStatus::Complete(line, _) =
            parse_chunk_line(b"0; use-original-body=12\r\n").unwrap()
        else {
            panic!("complete line expected");
        };
        assert_eq!(line.use_original_body(), Ok(Some(12)));
        assert_eq!(line.use_original_body_usize(), Ok(Some(12)));
        let extension = line.extensions().iter().next().unwrap();
        assert_eq!(extension.use_original_body_usize(), Ok(Some(12)));

        assert_eq!(
            parse_chunk_line(b"1; use-original-body=12\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(
            parse_chunk_line(b"0; use-original-body=bogus\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(
            parse_chunk_line(b"0; use-original-body=-1\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(
            parse_chunk_line(b"0; use-original-body\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
    }

    #[test]
    fn reports_partial_and_invalid_lines() {
        assert_eq!(parse_chunk_line(b"10"), Ok(ParseStatus::Partial));
        assert_eq!(
            parse_chunk_line(b"\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(
            parse_chunk_line(b"xyz\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(
            parse_chunk_line(b"10000000000000000\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(
            parse_chunk_line(b"0; =bad\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(parse_chunk_line(b"0\n"), Err(ChunkLineError::InvalidSyntax));
        assert_eq!(
            parse_chunk_line(b"12\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(
            parse_chunk_line(b"0\rX"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(
            parse_chunk_line(b"0; quote=\"unterminated\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
        assert_eq!(
            parse_chunk_line(b"0; quote=\"bad\\\n\"\r\n"),
            Err(ChunkLineError::InvalidSyntax)
        );
    }

    #[test]
    fn accepts_unbounded_leading_zero_hex_digits() {
        let wire = b"00000000000000000\r\n";
        let ParseStatus::Complete(line, consumed) = parse_chunk_line(wire).unwrap() else {
            panic!("complete line expected");
        };
        assert_eq!(line.size(), 0);
        assert_eq!(consumed, wire.len());

        let wire = b"00000000000000000f\r\n";
        let ParseStatus::Complete(line, _) = parse_chunk_line(wire).unwrap() else {
            panic!("complete line expected");
        };
        assert_eq!(line.size(), 15);
    }

    #[test]
    fn enforces_chunk_line_bounds_incrementally() {
        assert_eq!(DEFAULT_MAX_CHUNK_LINE_BYTES, 8_192);
        let wire = b"0\r\nbody";
        let ParseStatus::Complete(line, consumed) = parse_chunk_line_with_limit(wire, 3).unwrap()
        else {
            panic!("complete line expected");
        };
        assert_eq!(line.size(), 0);
        assert_eq!(consumed, 3);
        assert_eq!(
            parse_chunk_line_with_limit(wire, 2),
            Err(ChunkLineError::LineTooLong)
        );

        assert_eq!(
            parse_chunk_line_with_limit(b"0000", 4),
            Ok(ParseStatus::Partial)
        );
        assert_eq!(
            parse_chunk_line_with_limit(b"00000", 4),
            Err(ChunkLineError::LineTooLong)
        );
        assert_eq!(
            ChunkLineError::InvalidSyntax.to_string(),
            "invalid ICAP chunk line"
        );
        assert_eq!(
            ChunkLineError::LineTooLong.to_string(),
            "ICAP chunk line is too long"
        );
    }

    #[test]
    fn chunk_line_round_trip() {
        let extensions = [
            ChunkExtension::new("foo", Some(b"bar")).unwrap(),
            ChunkExtension::new("ieof", None).unwrap(),
        ];
        let mut dst = [0; 64];
        let len = encode_chunk_line(0, &extensions, &mut dst).unwrap();
        let ParseStatus::Complete(line, consumed) = parse_chunk_line(&dst[..len]).unwrap() else {
            panic!("complete line expected");
        };
        assert_eq!(consumed, len);
        assert!(line.is_ieof());
        assert_eq!(line.extensions().iter().count(), 2);
    }

    #[test]
    fn rejects_reserved_extensions_in_invalid_contexts() {
        for wire in [
            b"5; ieof\r\n".as_slice(),
            b"5; use-original-body=0\r\n".as_slice(),
            b"0; ieof; ieof\r\n".as_slice(),
            b"0; use-original-body=0; use-original-body=1\r\n".as_slice(),
            b"0; ieof; use-original-body=0\r\n".as_slice(),
        ] {
            assert_eq!(parse_chunk_line(wire), Err(ChunkLineError::InvalidSyntax));
        }

        let ieof = ChunkExtension::new("ieof", None).unwrap();
        let original = ChunkExtension::new("use-original-body", Some(b"0")).unwrap();
        assert_eq!(
            encode_chunk_line(1, &[ieof], &mut [0; 64]),
            Err(EncodeError::InvalidInput)
        );
        assert_eq!(
            encode_chunk_line(0, &[ieof, original], &mut [0; 64]),
            Err(EncodeError::InvalidInput)
        );
    }

    #[test]
    fn chunk_scanner_handles_one_byte_increments() {
        let wire = b"0; ieof\r\nbody";
        let mut scanner = ChunkLineScanner::new();
        for len in 0..9 {
            assert_eq!(scanner.scan(&wire[..len], 9), Ok(ParseStatus::Partial));
        }
        assert_eq!(scanner.scan(wire, 9), Ok(ParseStatus::Complete((), 9)));
        for (replacement, limit) in [
            (wire.as_slice(), 8),
            (b"".as_slice(), 0),
            (b"replaced".as_slice(), 1),
            (b"0; ieof\r\n\r\n".as_slice(), 13),
        ] {
            assert_eq!(
                scanner.scan(replacement, limit),
                Ok(ParseStatus::Complete((), 9))
            );
        }
        scanner.reset();
        assert_eq!(scanner, ChunkLineScanner::new());
        assert_eq!(scanner.scan(b"abcd", 3), Err(ChunkLineError::LineTooLong));

        scanner.reset();
        assert_eq!(scanner.scan(b"abc", 3), Ok(ParseStatus::Partial));
        assert_eq!(scanner.scan(b"0\n", 3), Err(ChunkLineError::InvalidSyntax));
        scanner.reset();
        assert_eq!(scanner.scan(b"0\rX", 3), Err(ChunkLineError::InvalidSyntax));
        scanner.reset();
        assert_eq!(scanner.scan(b"0\rX", 2), Err(ChunkLineError::LineTooLong));
    }

    #[test]
    fn chunk_encoder_handles_numeric_and_buffer_boundaries() {
        for (size, expected) in [
            (0, "0\r\n"),
            (9, "9\r\n"),
            (10, "a\r\n"),
            (15, "f\r\n"),
            (16, "10\r\n"),
            (255, "ff\r\n"),
            (256, "100\r\n"),
            (u64::MAX, "ffffffffffffffff\r\n"),
        ] {
            let mut dst = [0; 32];
            let len = encode_chunk_line(size, &[], &mut dst).unwrap();
            assert_eq!(&dst[..len], expected.as_bytes());
            assert_eq!(
                encode_chunk_line(size, &[], &mut dst[..len - 1]),
                Err(EncodeError::BufferTooSmall)
            );
            let ParseStatus::Complete(parsed, consumed) = parse_chunk_line(&dst[..len]).unwrap()
            else {
                panic!("complete line expected");
            };
            assert_eq!(parsed.size(), size);
            assert_eq!(consumed, len);
        }
    }

    #[test]
    fn chunk_extension_constructor_validates_all_parts() {
        assert_eq!(ChunkExtension::new("", None), Err(InvalidChunkLine));
        assert_eq!(ChunkExtension::new("bad name", None), Err(InvalidChunkLine));
        assert_eq!(ChunkExtension::new("foo", Some(b"")), Err(InvalidChunkLine));
        assert_eq!(
            ChunkExtension::new("ieof", Some(b"value")),
            Err(InvalidChunkLine)
        );
        assert_eq!(
            ChunkExtension::new("use-original-body", None),
            Err(InvalidChunkLine)
        );
        assert_eq!(
            ChunkExtension::new("use-original-body", Some(b"bogus")),
            Err(InvalidChunkLine)
        );
        assert_eq!(
            ChunkExtension::new("foo", Some(b"\"bad\\\n\"")),
            Err(InvalidChunkLine)
        );
        assert_eq!(InvalidChunkLine.to_string(), "invalid ICAP chunk line");
    }
}
