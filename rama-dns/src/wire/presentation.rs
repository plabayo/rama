use core::fmt;

pub(super) struct CharacterString<'a>(pub(super) &'a [u8]);

impl fmt::Display for CharacterString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(self.0) {
            Ok(text) => write!(f, "{text:?}"),
            Err(_) => Hex(self.0).fmt(f),
        }
    }
}

pub(super) struct Hex<'a>(pub(super) &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}
