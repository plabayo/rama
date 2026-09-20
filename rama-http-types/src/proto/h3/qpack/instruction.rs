//! QPACK encoder-stream (RFC 9204 §4.3) and decoder-stream (RFC 9204 §4.4) instructions.
//!
//! These are structural representations decoded from a slice cursor. Applying them to the dynamic
//! table (and the accounting behind Insert Count Increment / Section Acknowledgment / Stream
//! Cancellation) is the connection-scoped codec's job in `rama-http-core`.

use rama_core::bytes::{BufMut, Bytes};

use super::prefix::{PrefixError, decode_int, decode_string, encode_int, encode_string};

/// An instruction on the QPACK encoder stream (encoder → decoder, RFC 9204 §4.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EncoderInstruction {
    /// Set Dynamic Table Capacity (RFC 9204 §4.3.1).
    SetDynamicTableCapacity {
        /// The new maximum table capacity in bytes.
        capacity: u64,
    },
    /// Insert with Name Reference (RFC 9204 §4.3.2): a new entry whose name is an existing entry.
    InsertWithNameRef {
        /// Whether the name index is static (`T=1`) or dynamic (`T=0`, relative index).
        is_static: bool,
        /// The static index, or the relative dynamic index of the name.
        name_index: u64,
        /// The literal value.
        value: Bytes,
        /// Whether the value was Huffman-encoded on the wire.
        value_huffman: bool,
    },
    /// Insert with Literal Name (RFC 9204 §4.3.3): a new entry with a literal name and value.
    InsertWithLiteralName {
        /// The literal name.
        name: Bytes,
        /// Whether the name was Huffman-encoded on the wire.
        name_huffman: bool,
        /// The literal value.
        value: Bytes,
        /// Whether the value was Huffman-encoded on the wire.
        value_huffman: bool,
    },
    /// Duplicate (RFC 9204 §4.3.4): re-insert an existing entry (e.g. to avoid eviction).
    Duplicate {
        /// The relative index of the entry to duplicate.
        index: u64,
    },
}

impl EncoderInstruction {
    /// Encode this instruction into `dst`.
    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        match self {
            Self::InsertWithNameRef {
                is_static,
                name_index,
                value,
                value_huffman,
            } => {
                let flags = 0x80 | if *is_static { 0x40 } else { 0 };
                encode_int(dst, *name_index, 6, flags);
                encode_string(dst, value, 7, 0, *value_huffman);
            }
            Self::InsertWithLiteralName {
                name,
                name_huffman,
                value,
                value_huffman,
            } => {
                // 01 H NameLen(5+)
                encode_string(dst, name, 5, 0x40, *name_huffman);
                encode_string(dst, value, 7, 0, *value_huffman);
            }
            Self::SetDynamicTableCapacity { capacity } => {
                encode_int(dst, *capacity, 5, 0x20);
            }
            Self::Duplicate { index } => {
                encode_int(dst, *index, 5, 0);
            }
        }
    }

    /// Decode one encoder-stream instruction, bounding each decoded string by `max_string_len`.
    pub fn decode(src: &mut &[u8], max_string_len: usize) -> Result<Self, PrefixError> {
        let first = *src.first().ok_or(PrefixError::UnexpectedEnd)?;
        if first & 0x80 != 0 {
            let is_static = first & 0x40 != 0;
            let name_index = decode_int(src, 6)?;
            let value = decode_string(src, 7, max_string_len)?;
            Ok(Self::InsertWithNameRef {
                is_static,
                name_index,
                value: value.value.freeze(),
                value_huffman: value.huffman,
            })
        } else if first & 0x40 != 0 {
            let name = decode_string(src, 5, max_string_len)?;
            let value = decode_string(src, 7, max_string_len)?;
            Ok(Self::InsertWithLiteralName {
                name: name.value.freeze(),
                name_huffman: name.huffman,
                value: value.value.freeze(),
                value_huffman: value.huffman,
            })
        } else if first & 0x20 != 0 {
            let capacity = decode_int(src, 5)?;
            Ok(Self::SetDynamicTableCapacity { capacity })
        } else {
            let index = decode_int(src, 5)?;
            Ok(Self::Duplicate { index })
        }
    }
}

/// An instruction on the QPACK decoder stream (decoder → encoder, RFC 9204 §4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecoderInstruction {
    /// Section Acknowledgment (RFC 9204 §4.4.1): the decoder finished a field section on a stream.
    SectionAcknowledgment {
        /// The stream on which the acknowledged field section was received.
        stream_id: u64,
    },
    /// Stream Cancellation (RFC 9204 §4.4.2): a stream was reset/abandoned before decoding.
    StreamCancellation {
        /// The stream that was cancelled.
        stream_id: u64,
    },
    /// Insert Count Increment (RFC 9204 §4.4.3): the decoder inserted more entries.
    InsertCountIncrement {
        /// The number of entries newly acknowledged.
        increment: u64,
    },
}

impl DecoderInstruction {
    /// Encode this instruction into `dst`.
    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        match self {
            Self::SectionAcknowledgment { stream_id } => encode_int(dst, *stream_id, 7, 0x80),
            Self::StreamCancellation { stream_id } => encode_int(dst, *stream_id, 6, 0x40),
            Self::InsertCountIncrement { increment } => encode_int(dst, *increment, 6, 0),
        }
    }

    /// Decode one decoder-stream instruction.
    pub fn decode(src: &mut &[u8]) -> Result<Self, PrefixError> {
        let first = *src.first().ok_or(PrefixError::UnexpectedEnd)?;
        if first & 0x80 != 0 {
            Ok(Self::SectionAcknowledgment {
                stream_id: decode_int(src, 7)?,
            })
        } else if first & 0x40 != 0 {
            Ok(Self::StreamCancellation {
                stream_id: decode_int(src, 6)?,
            })
        } else {
            Ok(Self::InsertCountIncrement {
                increment: decode_int(src, 6)?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::bytes::BytesMut;

    fn enc(inst: &EncoderInstruction) -> Vec<u8> {
        let mut buf = BytesMut::new();
        inst.encode(&mut buf);
        buf.to_vec()
    }

    #[test]
    fn appendix_b2_encoder_stream() {
        // 3fbd01 c00f www.example.com c10c /sample/path
        let mut cursor =
            &hex(b"3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468")[..];

        assert_eq!(
            EncoderInstruction::decode(&mut cursor, 4096).unwrap(),
            EncoderInstruction::SetDynamicTableCapacity { capacity: 220 }
        );
        match EncoderInstruction::decode(&mut cursor, 4096).unwrap() {
            EncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
                ..
            } => {
                assert!(is_static);
                assert_eq!(name_index, 0); // :authority
                assert_eq!(&value[..], b"www.example.com");
            }
            other => panic!("{other:?}"),
        }
        match EncoderInstruction::decode(&mut cursor, 4096).unwrap() {
            EncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
                ..
            } => {
                assert!(is_static);
                assert_eq!(name_index, 1); // :path
                assert_eq!(&value[..], b"/sample/path");
            }
            other => panic!("{other:?}"),
        }
        assert!(cursor.is_empty());
    }

    #[test]
    fn appendix_b3_insert_literal_name() {
        // 4a custom-key 0c custom-value
        let mut cursor = &hex(b"4a637573746f6d2d6b65790c637573746f6d2d76616c7565")[..];
        match EncoderInstruction::decode(&mut cursor, 4096).unwrap() {
            EncoderInstruction::InsertWithLiteralName { name, value, .. } => {
                assert_eq!(&name[..], b"custom-key");
                assert_eq!(&value[..], b"custom-value");
            }
            other => panic!("{other:?}"),
        }
        assert!(cursor.is_empty());
    }

    #[test]
    fn appendix_b4_duplicate() {
        let mut cursor = &[0x02u8][..];
        assert_eq!(
            EncoderInstruction::decode(&mut cursor, 4096).unwrap(),
            EncoderInstruction::Duplicate { index: 2 }
        );
    }

    #[test]
    fn appendix_b5_insert_dynamic_name() {
        // 81 0d custom-value2
        let mut cursor = &hex(b"810d637573746f6d2d76616c756532")[..];
        match EncoderInstruction::decode(&mut cursor, 4096).unwrap() {
            EncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
                ..
            } => {
                assert!(!is_static);
                assert_eq!(name_index, 1); // relative dynamic index 1
                assert_eq!(&value[..], b"custom-value2");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn decoder_stream_appendix_b() {
        // B.2 ack stream 4 = 0x84
        let mut cursor = &[0x84u8][..];
        assert_eq!(
            DecoderInstruction::decode(&mut cursor).unwrap(),
            DecoderInstruction::SectionAcknowledgment { stream_id: 4 }
        );
        // B.3 insert count increment 1 = 0x01
        let mut cursor = &[0x01u8][..];
        assert_eq!(
            DecoderInstruction::decode(&mut cursor).unwrap(),
            DecoderInstruction::InsertCountIncrement { increment: 1 }
        );
        // B.4 stream cancellation stream 8 = 0x48
        let mut cursor = &[0x48u8][..];
        assert_eq!(
            DecoderInstruction::decode(&mut cursor).unwrap(),
            DecoderInstruction::StreamCancellation { stream_id: 8 }
        );
    }

    #[test]
    fn set_capacity_round_trip() {
        let inst = EncoderInstruction::SetDynamicTableCapacity { capacity: 220 };
        assert_eq!(enc(&inst), vec![0x3f, 0xbd, 0x01]);
        let mut cursor = &enc(&inst)[..];
        assert_eq!(EncoderInstruction::decode(&mut cursor, 4096).unwrap(), inst);
    }

    #[test]
    fn incomplete_is_distinct() {
        // insert-with-name-ref opcode byte only, missing value
        let mut cursor = &[0xc0u8][..];
        assert_eq!(
            EncoderInstruction::decode(&mut cursor, 4096),
            Err(PrefixError::UnexpectedEnd)
        );
    }

    fn hex(s: &[u8]) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| {
                let hi = (s[2 * i] as char).to_digit(16).unwrap();
                let lo = (s[2 * i + 1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect()
    }
}
