/// Incremental Internet checksum (RFC 1071).
///
/// Slice boundaries may occur between the two bytes of a word. Odd trailing
/// bytes are padded with zero only when [`Self::finish`] is called.
#[derive(Debug, Clone, Default)]
pub struct InternetChecksum {
    sum: u16,
    high: Option<u8>,
}

impl InternetChecksum {
    /// Start a checksum.
    #[must_use]
    pub const fn new() -> Self {
        Self { sum: 0, high: None }
    }

    /// Add bytes in network order.
    pub fn update(&mut self, mut bytes: &[u8]) {
        if let Some(high) = self.high.take() {
            if let Some((&low, rest)) = bytes.split_first() {
                self.add(u16::from_be_bytes([high, low]));
                bytes = rest;
            } else {
                self.high = Some(high);
                return;
            }
        }
        let (pairs, remainder) = bytes.as_chunks::<2>();
        for pair in pairs {
            self.add(u16::from_be_bytes([pair[0], pair[1]]));
        }
        self.high = remainder.first().copied();
    }

    fn add(&mut self, word: u16) {
        let sum = u32::from(self.sum) + u32::from(word);
        // Two 16-bit words sum to at most 0x1fffe, so one carry fold fits u16.
        self.sum = ((sum & 0xffff) + (sum >> 16)) as u16;
    }

    /// Complemented checksum, suitable for writing in network byte order.
    /// Checking a complete valid message including its checksum yields zero.
    #[must_use]
    pub fn finish(mut self) -> u16 {
        if let Some(high) = self.high {
            self.add(u16::from(high) << 8);
        }
        // Every addition is already folded, including the padded final byte.
        !self.sum
    }
}

/// Internet checksum of a contiguous byte string.
#[must_use]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = InternetChecksum::new();
    sum.update(bytes);
    sum.finish()
}
