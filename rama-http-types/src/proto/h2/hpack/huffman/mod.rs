mod table;

use self::table::{DECODE_TABLE, ENCODE_TABLE};
use crate::proto::h2::hpack::DecoderError;

use rama_core::bytes::{BufMut, BytesMut};

const BRANCH: u16 = 0x8000;
const TABLE_INDEX_MASK: u16 = 0x7f00;
const TABLE_WIDTH: usize = 256;

pub(crate) fn decode(src: &[u8], buf: &mut BytesMut) -> Result<BytesMut, DecoderError> {
    decode_bounded(src, buf, usize::MAX).map_err(|_bounded_error| DecoderError::InvalidHuffmanCode)
}

/// A bounded Huffman decoding failure.
pub(crate) enum BoundedDecodeError {
    InvalidCode,
    LengthLimit,
}

/// Decode while checking the output bound before every write or allocation.
pub(crate) fn decode_bounded(
    src: &[u8],
    buf: &mut BytesMut,
    max_len: usize,
) -> Result<BytesMut, BoundedDecodeError> {
    if buf.len() > max_len {
        return Err(BoundedDecodeError::LengthLimit);
    }
    buf.reserve(src.len().saturating_mul(2).min(max_len - buf.len()));

    let mut table = 0;
    let mut acc = 0u32;
    let mut bits = 0;

    for &byte in src {
        acc = (acc << 8) | byte as u32;
        bits += 8;

        while bits >= 8 {
            let index = (acc >> (bits - 8)) as u8 as usize;
            let entry = DECODE_TABLE[table * TABLE_WIDTH + index];

            if entry & BRANCH == 0 {
                if buf.len() == max_len {
                    return Err(BoundedDecodeError::LengthLimit);
                }
                buf.put_u8(entry as u8);
                table = 0;
                bits -= (entry >> 8) as usize;
            } else {
                table = ((entry & TABLE_INDEX_MASK) >> 8) as usize;
                if table == 0 {
                    return Err(BoundedDecodeError::InvalidCode);
                }
                bits -= 8;
            }
        }
    }

    // Fewer than eight bits remain. A prefix of the EOS code (all ones) is
    // valid padding only when the previous symbol has completed.
    while bits > 0 {
        debug_assert!(bits < 8);
        let padding = (1u32 << bits) - 1;
        if table == 0 && acc & padding == padding {
            break;
        }

        let index = (acc << (8 - bits)) as u8 as usize;
        let entry = DECODE_TABLE[table * TABLE_WIDTH + index];
        if entry & BRANCH != 0 {
            return Err(BoundedDecodeError::InvalidCode);
        }

        let used = (entry >> 8) as usize;
        if used > bits {
            return Err(BoundedDecodeError::InvalidCode);
        }

        if buf.len() == max_len {
            return Err(BoundedDecodeError::LengthLimit);
        }
        buf.put_u8(entry as u8);
        table = 0;
        bits -= used;
    }

    if table == 0 {
        Ok(buf.split())
    } else {
        Err(BoundedDecodeError::InvalidCode)
    }
}

/// Exact encoded length, without allocating a temporary output buffer.
pub(crate) fn encoded_len(src: &[u8]) -> usize {
    src.iter()
        .map(|&b| ENCODE_TABLE[b as usize].0)
        .sum::<usize>()
        .div_ceil(8)
}

pub(crate) fn encode<B: BufMut>(src: &[u8], dst: &mut B) {
    encode_bytes(src.iter().copied(), dst);
}

pub(crate) fn encode_lowercase_ascii(src: &[u8], dst: &mut BytesMut) {
    encode_bytes(src.iter().map(|b| b.to_ascii_lowercase()), dst);
}

fn encode_bytes<B: BufMut>(bytes: impl IntoIterator<Item = u8>, dst: &mut B) {
    let mut bits: u64 = 0;
    let mut bits_left = 40;

    for b in bytes {
        let (nbits, code) = ENCODE_TABLE[b as usize];

        bits |= code << (bits_left - nbits);
        bits_left -= nbits;

        while bits_left <= 32 {
            dst.put_u8((bits >> 32) as u8);

            bits <<= 8;
            bits_left += 8;
        }
    }

    if bits_left != 40 {
        // This writes the EOS token
        bits |= (1 << bits_left) - 1;
        dst.put_u8((bits >> 32) as u8);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn decode(src: &[u8]) -> Result<BytesMut, DecoderError> {
        let mut buf = BytesMut::new();
        super::decode(src, &mut buf)
    }

    #[test]
    fn decode_single_byte() {
        assert_eq!("o", decode(&[0b00111111]).unwrap());
        assert_eq!("0", decode(&[7]).unwrap());
        assert_eq!("A", decode(&[(0x21 << 2) + 3]).unwrap());
    }

    #[test]
    fn single_char_multi_byte() {
        assert_eq!("#", decode(&[255, 160 + 15]).unwrap());
        assert_eq!("$", decode(&[255, 200 + 7]).unwrap());
        assert_eq!("\x0a", decode(&[255, 255, 255, 240 + 3]).unwrap());
    }

    #[test]
    fn multi_char() {
        assert_eq!("!0", decode(&[254, 1]).unwrap());
        assert_eq!(" !", decode(&[0b01010011, 0b11111000]).unwrap());
    }

    #[test]
    fn encode_single_byte() {
        let mut dst = BytesMut::with_capacity(1);

        encode(b"o", &mut dst);
        assert_eq!(&dst[..], &[0b00111111]);

        dst.clear();
        encode(b"0", &mut dst);
        assert_eq!(&dst[..], &[7]);

        dst.clear();
        encode(b"A", &mut dst);
        assert_eq!(&dst[..], &[(0x21 << 2) + 3]);
    }

    #[test]
    fn encode_decode_str() {
        const DATA: &[&str] = &[
            "hello world",
            ":method",
            ":scheme",
            ":authority",
            "yahoo.co.jp",
            "GET",
            "http",
            ":path",
            "/images/top/sp2/cmn/logo-ns-130528.png",
            "example.com",
            "hpack-test",
            "xxxxxxx1",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:16.0) Gecko/20100101 Firefox/16.0",
            "accept",
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "cookie",
            "B=76j09a189a6h4&b=3&s=0b",
            "TE",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi non bibendum libero. \
             Etiam ultrices lorem ut.",
        ];

        for s in DATA {
            let mut dst = BytesMut::with_capacity(s.len());

            encode(s.as_bytes(), &mut dst);

            let decoded = decode(&dst).unwrap();

            assert_eq!(&decoded[..], s.as_bytes());
        }
    }

    #[test]
    fn encode_decode_u8() {
        const DATA: &[&[u8]] = &[b"\0", b"\0\0\0", b"\0\x01\x02\x03\x04\x05", b"\xFF\xF8"];

        for s in DATA {
            let mut dst = BytesMut::with_capacity(s.len());

            encode(s, &mut dst);

            let decoded = decode(&dst).unwrap();

            assert_eq!(&decoded[..], &s[..]);
        }
    }

    #[test]
    fn encode_decode_all_octets() {
        let src: Vec<_> = (0..=u8::MAX).collect();
        let mut encoded = BytesMut::new();
        encode(&src, &mut encoded);
        assert_eq!(decode(&encoded).unwrap(), src);
    }

    #[test]
    fn decode_matches_independent_bitwise_oracle() {
        #[derive(Default)]
        struct Node {
            children: [Option<usize>; 2],
            symbol: Option<usize>,
        }

        // Build a bit-at-a-time trie from the codebook, without using the
        // production decoder's generated byte lookup table or tail logic.
        fn oracle(src: &[u8], nodes: &[Node]) -> Option<Vec<u8>> {
            let mut out = Vec::new();
            let mut node = 0;
            let mut pending_bits = 0;
            let mut pending_ones = true;
            for byte in src {
                for shift in (0..8).rev() {
                    let bit = usize::from((byte >> shift) & 1);
                    node = nodes[node].children[bit]?;
                    pending_bits += 1;
                    pending_ones &= bit == 1;
                    if let Some(symbol) = nodes[node].symbol {
                        // Symbol 256 is EOS and must never occur in a string.
                        out.push(u8::try_from(symbol).ok()?);
                        node = 0;
                        pending_bits = 0;
                        pending_ones = true;
                    }
                }
            }
            (pending_bits <= 7 && pending_ones).then_some(out)
        }

        let mut nodes = vec![Node::default()];
        for (symbol, &(width, code)) in ENCODE_TABLE.iter().enumerate() {
            let mut node = 0;
            for shift in (0..width).rev() {
                let bit = usize::from((code >> shift) & 1 != 0);
                node = if let Some(child) = nodes[node].children[bit] {
                    child
                } else {
                    let child = nodes.len();
                    nodes.push(Node::default());
                    nodes[node].children[bit] = Some(child);
                    child
                };
            }
            nodes[node].symbol = Some(symbol);
        }

        let check = |src: &[u8]| {
            let expected = oracle(src, &nodes);
            assert_eq!(
                decode(src).ok().as_deref(),
                expected.as_deref(),
                "{src:02x?}"
            );
            if let Some(expected) = expected {
                let bounded = decode_bounded(src, &mut BytesMut::new(), expected.len());
                assert_eq!(bounded.ok().as_deref(), Some(expected.as_slice()));
                if !expected.is_empty() {
                    assert!(matches!(
                        decode_bounded(src, &mut BytesMut::new(), expected.len() - 1),
                        Err(BoundedDecodeError::LengthLimit)
                    ));
                }
            }
        };
        check(&[]);
        for byte in 0..=u8::MAX {
            check(&[byte]);
        }
        for pair in 0..=u16::MAX {
            check(&pair.to_be_bytes());
        }
        // Fixed xorshift seed keeps arbitrary malformed and longer inputs
        // reproducible without relying on a random-number dependency.
        let mut seed = 42u64;
        for sample in 0..100_000 {
            let mut input = [0u8; 39];
            for byte in &mut input[..1 + sample % 39] {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *byte = seed.to_le_bytes()[0];
            }
            check(&input[..1 + sample % 39]);
        }
    }

    #[test]
    fn rejects_eos_and_invalid_padding() {
        assert_eq!(decode(&[0xff]), Err(DecoderError::InvalidHuffmanCode));
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xff]),
            Err(DecoderError::InvalidHuffmanCode)
        );
        assert_eq!(decode(&[0]), Err(DecoderError::InvalidHuffmanCode));
    }
}

/*
// uncomment to run benchmarks
#[cfg(test)]
mod bench {
    extern crate test;

    use self::test::{black_box, Bencher};
    use super::*;

    fn decode_input(b: &mut Bencher, input: &[u8]) {
        let mut encoded = BytesMut::new();
        encode(input, &mut encoded);

        let mut scratch = BytesMut::with_capacity(input.len() * 2);
        b.bytes = encoded.len() as u64;
        b.iter(|| {
            let decoded = decode(black_box(encoded.as_ref()), &mut scratch).unwrap();
            black_box(decoded);
        });
    }

    #[bench]
    fn decode_short_ascii(b: &mut Bencher) {
        decode_input(b, b"www.example.com");
    }

    #[bench]
    fn decode_header_value(b: &mut Bencher) {
        decode_input(
            b,
            b"text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8",
        );
    }

    #[bench]
    fn decode_long_ascii(b: &mut Bencher) {
        decode_input(
            b,
            b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:16.0) Gecko/20100101 Firefox/16.0",
        );
    }

    #[bench]
    fn decode_all_octets(b: &mut Bencher) {
        let input: Vec<_> = (0..=u8::MAX).collect();
        decode_input(b, &input);
    }
}
*/
