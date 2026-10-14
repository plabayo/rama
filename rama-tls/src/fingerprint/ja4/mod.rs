mod server;
mod tls;

pub use server::Ja4S;
pub use tls::{Ja4, Ja4ComputeError};

use std::fmt;

use rama_net::tls::ApplicationProtocol;

use sha2::{Digest as _, Sha256};

#[derive(Default)]
struct HashWriter {
    hasher: Sha256,
    wrote_bytes: bool,
}

impl fmt::Write for HashWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.wrote_bytes |= !value.is_empty();
        self.hasher.update(value.as_bytes());
        Ok(())
    }
}

/// Hash formatted bytes into the 12-hex-char truncated SHA-256 digest used by
/// the JA4 family without first allocating the unhashed string. Empty output
/// maps to the all-zero sentinel per the spec.
fn write_hash12(
    output: &mut impl fmt::Write,
    write_value: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
) -> fmt::Result {
    let mut writer = HashWriter::default();
    write_value(&mut writer)?;

    if !writer.wrote_bytes {
        output.write_str("000000000000")
    } else {
        let digest = writer.hasher.finalize();
        rama_utils::fmt::hex(&digest[..6]).write_to(output)
    }
}

fn write_hex_list<W, T>(writer: &mut W, values: impl IntoIterator<Item = T>) -> fmt::Result
where
    W: fmt::Write + ?Sized,
    T: fmt::LowerHex,
{
    let mut first = true;
    for value in values {
        if !first {
            writer.write_char(',')?;
        }
        first = false;
        write!(writer, "{value:04x}")?;
    }
    Ok(())
}

/// The JA4 ALPN marker: the first and last character, a single character supplying both, a
/// non-ASCII one (or an invalid byte) written as `9`, and `00` without ALPN.
fn alpn_markers(alpn: Option<&ApplicationProtocol>) -> (char, char) {
    let Some(alpn) = alpn else {
        return ('0', '0');
    };
    let text = String::from_utf8_lossy(alpn.as_bytes());
    let ascii = |c: char| if c.is_ascii() { c } else { '9' };
    let mut chars = text.chars();
    let Some(first) = chars.next().map(ascii) else {
        return ('0', '0');
    };
    let last = chars.next_back().map(ascii).unwrap_or(first);
    (first, last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_markers_follow_the_reference_rules() {
        let markers = |alpn: &[u8]| alpn_markers(Some(&ApplicationProtocol::from(alpn)));
        assert_eq!(alpn_markers(None), ('0', '0'));
        assert_eq!(markers(b""), ('0', '0'));
        assert_eq!(markers(b"x"), ('x', 'x'));
        assert_eq!(markers(b"7"), ('7', '7'));
        assert_eq!(markers(b"ab"), ('a', 'b'));
        assert_eq!(markers(b"h2"), ('h', '2'));
        assert_eq!(markers(b"http/1.1"), ('h', '1'));
        // Non-ASCII characters and invalid bytes are written as `9`.
        assert_eq!(markers("é".as_bytes()), ('9', '9'));
        assert_eq!(markers(b"\xffx\xff"), ('9', '9'));
        assert_eq!(markers(b"x\xff"), ('x', '9'));
        assert_eq!(markers(b"\xffx"), ('9', 'x'));
    }
}
