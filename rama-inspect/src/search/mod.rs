//! Match displayed values or streamed bytes without buffering their formatted content.

use std::fmt::{self, Write};

use rama_utils::{
    hex::encode_byte_upper,
    octets::kib,
    str::utf8::{self, DecodeError, Incomplete},
};

use tokio::io::{AsyncRead, AsyncReadExt};

struct Matcher {
    needle: Vec<char>,
    failure: Vec<usize>,
    prefix: usize,
    matched: bool,
}

impl Matcher {
    fn new(needle: &str) -> Self {
        let needle: Vec<_> = needle.chars().flat_map(char::to_lowercase).collect();
        let mut failure = vec![0; needle.len()];
        let mut prefix = 0;
        for index in 1..needle.len() {
            while prefix > 0 && needle[index] != needle[prefix] {
                prefix = failure[prefix - 1];
            }
            if needle[index] == needle[prefix] {
                prefix += 1;
            }
            failure[index] = prefix;
        }
        Self {
            matched: needle.is_empty(),
            needle,
            failure,
            prefix: 0,
        }
    }

    fn push(&mut self, c: char) -> fmt::Result {
        if self.matched {
            return Err(fmt::Error);
        }
        for c in c.to_lowercase() {
            while self.prefix > 0 && self.needle[self.prefix] != c {
                self.prefix = self.failure[self.prefix - 1];
            }
            if self.needle[self.prefix] == c {
                self.prefix += 1;
            }
            if self.prefix == self.needle.len() {
                self.matched = true;
                return Err(fmt::Error);
            }
        }
        Ok(())
    }
}

impl Write for Matcher {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for c in value.chars() {
            self.push(c)?;
        }
        Ok(())
    }
}

pub fn matches_display(value: &impl fmt::Display, needle: &str) -> bool {
    let mut matcher = Matcher::new(needle);
    _ = write!(&mut matcher, "{value}");
    matcher.matched
}

// Feed the contents of a native Debug string, omitting this fragment's surrounding
// quotes. This preserves Rust's escaping rules without intermediate strings.
struct QuotedFragment<'a> {
    matcher: &'a mut Matcher,
    started: bool,
    last: Option<char>,
}

impl Write for QuotedFragment<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for c in value.chars() {
            if !self.started {
                self.started = true;
                continue;
            }
            if let Some(previous) = self.last.replace(c) {
                self.matcher.push(previous)?;
            }
        }
        Ok(())
    }
}

fn text_fragment(matcher: &mut Matcher, text: &str) {
    _ = write!(
        &mut QuotedFragment {
            matcher,
            started: false,
            last: None
        },
        "{text:?}"
    );
}

/// Search the same UTF-8-debug-or-hex representation as `rama_utils::fmt::utf8_or_hex`.
/// Memory is bounded by the query and a 16 KiB read buffer. Both representations are
/// matched in one pass; EOF determines whether the complete payload is valid UTF-8.
pub async fn matches_reader(
    mut reader: impl AsyncRead + Unpin,
    needle: &str,
) -> std::io::Result<bool> {
    if needle.is_empty() {
        return Ok(true);
    }
    let mut text = Matcher::new(needle);
    let mut hex = Matcher::new(needle);
    _ = text.write_char('"');
    _ = hex.write_str("0x");
    let mut buffer = vec![0; kib(16)];
    let mut incomplete = Incomplete::empty();
    let mut utf8 = true;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            if !incomplete.is_empty() {
                utf8 = false;
            }
            _ = text.write_char('"');
            return Ok(if utf8 { text.matched } else { hex.matched });
        }
        if !hex.matched {
            for &byte in &buffer[..count] {
                let encoded = encode_byte_upper(byte);
                _ = hex.write_char(char::from(encoded[0]));
                _ = hex.write_char(char::from(encoded[1]));
            }
        }
        let mut input = &buffer[..count];
        if utf8 && !incomplete.is_empty() {
            match incomplete.try_complete(input) {
                Some((Ok(fragment), remaining)) => {
                    text_fragment(&mut text, fragment);
                    input = remaining;
                }
                Some((Err(_), _)) => utf8 = false,
                None => continue,
            }
        }
        if utf8 {
            match utf8::decode(input) {
                Ok(fragment) => text_fragment(&mut text, fragment),
                Err(DecodeError::Incomplete {
                    valid_prefix,
                    incomplete_suffix,
                }) => {
                    text_fragment(&mut text, valid_prefix);
                    incomplete = incomplete_suffix;
                }
                Err(DecodeError::Invalid { valid_prefix, .. }) => {
                    text_fragment(&mut text, valid_prefix);
                    utf8 = false;
                }
            }
        }
        if hex.matched && (!utf8 || text.matched) {
            return Ok(true);
        }
    }
}

/// Search the hex display of bytes, including when the payload is valid UTF-8.
/// This is useful when a protocol explicitly classifies a payload as binary.
pub async fn matches_hex_reader(
    mut reader: impl AsyncRead + Unpin,
    needle: &str,
) -> std::io::Result<bool> {
    let mut matcher = Matcher::new(needle);
    _ = matcher.write_str("0x");
    let mut buffer = vec![0; kib(16)];
    while !matcher.matched {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        for &byte in &buffer[..count] {
            let encoded = encode_byte_upper(byte);
            _ = matcher.write_char(char::from(encoded[0]));
            _ = matcher.write_char(char::from(encoded[1]));
        }
    }
    Ok(matcher.matched)
}

#[cfg(test)]
mod tests;
