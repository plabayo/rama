//! Software CRC32C (Castagnoli) implementation used by the PROXY protocol v2
//! `PP2_TYPE_CRC32C` TLV.
//!
//! See the vendored specification at
//! `rama-haproxy/specifications/proxy-protocol.txt`, section 2.2.5
//! and RFC 3309. The polynomial is `0x1EDC6F41` (reversed `0x82F63B78`).

const POLY: u32 = 0x82F63B78;

const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

/// Incremental CRC32C (Castagnoli) hasher.
///
/// Allows computing the checksum across multiple non-contiguous byte ranges
/// without materialising them into a single buffer — used by
/// `Header::verify_crc32c` to substitute the CRC field with four zero bytes
/// during computation (spec section 2.2.5) without copying the header.
///
/// Internal: the one-shot [`crc32c`] function is the public surface; this
/// hasher is only re-exported within the crate.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Crc32cHasher {
    state: u32,
}

impl Crc32cHasher {
    pub(crate) const fn new() -> Self {
        Self {
            state: 0xFFFF_FFFFu32,
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut crc = self.state;
        for &b in data {
            let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
            crc = (crc >> 8) ^ TABLE[idx];
        }
        self.state = crc;
    }

    pub(crate) fn finalize(self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(data: &[u8]) -> u32 {
        let mut h = Crc32cHasher::new();
        h.update(data);
        h.finalize()
    }

    #[test]
    fn known_vectors() {
        // RFC 3720 / iSCSI test vectors for CRC32C.
        assert_eq!(hash(b""), 0);
        assert_eq!(hash(b"a"), 0xC1D04330);
        // 32 zero bytes
        assert_eq!(hash(&[0u8; 32]), 0x8A9136AA);
        // 32 0xff bytes
        assert_eq!(hash(&[0xFFu8; 32]), 0x62A8AB43);
        // 0..31
        let mut buf = [0u8; 32];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(hash(&buf), 0x46DD794E);
    }

    #[test]
    fn hasher_splits_match_oneshot() {
        // Feeding the same bytes in two pieces must match the one-shot result.
        let data = b"the quick brown fox jumps over the lazy dog";
        let oneshot = hash(data);
        for split in 0..=data.len() {
            let mut h = Crc32cHasher::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), oneshot, "split at {split}");
        }
    }
}
