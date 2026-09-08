//! Match displayed values or streamed bytes without buffering their formatted content.

use std::fmt::{self, Write};

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
    let mut buffer = vec![0; rama_utils::octets::kib(16) + 4];
    let mut carry = 0;
    let mut utf8 = true;
    loop {
        let count = reader.read(&mut buffer[carry..]).await?;
        if count == 0 {
            if carry != 0 {
                utf8 = false;
            }
            _ = text.write_char('"');
            return Ok(if utf8 { text.matched } else { hex.matched });
        }
        if !hex.matched {
            for &byte in &buffer[carry..carry + count] {
                let encoded = rama_utils::hex::encode_byte_upper(byte);
                _ = hex.write_char(char::from(encoded[0]));
                _ = hex.write_char(char::from(encoded[1]));
            }
        }
        let length = carry + count;
        if utf8 {
            match std::str::from_utf8(&buffer[..length]) {
                Ok(value) => {
                    text_fragment(&mut text, value);
                    carry = 0;
                }
                Err(error) => {
                    text_fragment(
                        &mut text,
                        std::str::from_utf8(&buffer[..error.valid_up_to()])
                            .map_err(std::io::Error::other)?,
                    );
                    if error.error_len().is_some() {
                        utf8 = false;
                        carry = 0;
                    } else {
                        carry = length - error.valid_up_to();
                        buffer.copy_within(error.valid_up_to()..length, 0);
                    }
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
    let mut buffer = vec![0; rama_utils::octets::kib(16)];
    while !matcher.matched {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        for &byte in &buffer[..count] {
            let encoded = rama_utils::hex::encode_byte_upper(byte);
            _ = matcher.write_char(char::from(encoded[0]));
            _ = matcher.write_char(char::from(encoded[1]));
        }
    }
    Ok(matcher.matched)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn streamed_search_matches_native_display_across_unicode_boundaries() {
        let mut text = "x".repeat(rama_utils::octets::kib(16) - 1);
        text.push_str("🙂\"\n\0'\u{200d}İΣabcabcabd");
        let mut binary = text.as_bytes().to_vec();
        binary.extend_from_slice(&[0xff, 0xaa]);
        for data in [text.as_bytes(), binary.as_slice(), b"", b"a'b\nc"] {
            for needle in [
                "🙂",
                "\\n",
                "\\u{200d}",
                "'",
                "İΣ",
                "abcabd",
                "0x78",
                "ffaa",
                "missing",
                "\"",
                "",
            ] {
                assert_eq!(
                    matches_reader(data, needle).await.unwrap(),
                    matches_display(&rama_utils::fmt::utf8_or_hex(data), needle),
                    "{needle:?}"
                );
            }
        }
    }
}
