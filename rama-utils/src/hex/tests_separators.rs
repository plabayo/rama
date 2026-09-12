use super::*;
use crate::fmt::hex;

#[test]
fn every_output_path_round_trips_literal_framing() {
    let bytes: Vec<_> = (0..=255).chain([0, 0xab, 255]).collect();
    for prefix in ["", "0x", "00", "🔑:"] {
        for separator in ["", ":", " ", "ab", " :: ", "→", "\0"] {
            for case in [HexCase::Lower, HexCase::Upper] {
                let format = match case {
                    HexCase::Lower => Format::new().with_lower_case(),
                    HexCase::Upper => Format::new().with_upper_case(),
                }
                .with_prefix(prefix)
                .with_separator(separator);
                for bytes in [&bytes[..0], &bytes[..1], &bytes[..3], &bytes[..]] {
                    let digits: Vec<_> = bytes
                        .iter()
                        .map(|b| match case {
                            HexCase::Lower => format!("{b:02x}"),
                            HexCase::Upper => format!("{b:02X}"),
                        })
                        .collect();
                    let expected = format!("{prefix}{}", digits.join(separator));
                    let view = hex(bytes).with_format(format);
                    assert_eq!(view.to_string(), expected);
                    assert_eq!(view.encoded_len(), expected.len());
                    assert_eq!(view.to_vec(), expected.as_bytes());
                    let mut text = String::from("existing");
                    view.append_to_string(&mut text);
                    assert_eq!(text, format!("existing{expected}"));
                    let mut encoded = Vec::from(&b"existing"[..]);
                    view.append_to_vec(&mut encoded);
                    assert_eq!(encoded, text.as_bytes());
                    let mut storage = crate::std::vec![0xcc; expected.len() + 1];
                    assert_eq!(
                        view.encode_to_slice(&mut storage).unwrap(),
                        expected.as_bytes()
                    );
                    assert_eq!(storage[expected.len()], 0xcc);
                    assert_eq!(format.decode::<Vec<u8>>(&expected).unwrap(), bytes);
                    let mut decoded = crate::std::vec![0xcc; bytes.len() + 1];
                    assert_eq!(format.decode_into(&expected, &mut decoded).unwrap(), bytes);
                    assert_eq!(decoded[bytes.len()], 0xcc);
                    let mut appended = Vec::from([42]);
                    assert_eq!(
                        format.decode_append(&expected, &mut appended).unwrap(),
                        bytes.len()
                    );
                    assert_eq!(&appended[1..], bytes);
                    assert_eq!(appended[0], 42);
                    #[cfg(feature = "std")]
                    {
                        let mut output = Vec::from([42]);
                        assert_eq!(
                            format.decode_write(&expected, &mut output).unwrap(),
                            bytes.len()
                        );
                        assert_eq!(&output[1..], bytes);
                        assert_eq!(output[0], 42);
                    }
                }
                let text = hex(&[0, 0xab, 255]).with_format(format).to_string();
                assert_eq!(format.decode::<[u8; 3]>(text).unwrap(), [0, 0xab, 255]);
            }
        }
    }
}

#[test]
fn builders_borrow_and_format_flags_keep_the_separator() {
    let bytes = Vec::from([0, 0xab, 255]);
    let prefix = String::from("hash:");
    let view = hex(&bytes).with_custom_prefix(&prefix).with_upper_case();
    {
        let separator = String::from(":");
        let view = view.with_separator(&separator);
        assert_eq!(view.to_string(), "hash:00:AB:FF");
        assert_eq!(format!("{view:x}"), "00:ab:ff");
        assert_eq!(format!("{view:X}"), "00:AB:FF");
        assert_eq!(format!("{view:#x}"), "0x00:ab:ff");
        assert_eq!(format!("{view:#X}"), "0x00:AB:FF");
        assert_eq!(view.with_prefix(false).to_string(), "00:AB:FF");
        assert_eq!(view.with_prefix(true).to_string(), "0x00:AB:FF");
        assert_eq!(view.with_separator("").to_string(), "hash:00ABFF");
        assert_eq!(view.with_custom_prefix("").to_string(), "00:AB:FF");
        let format = Format::new()
            .with_separator(&separator)
            .with_prefix(&prefix);
        assert_eq!(
            format.decode::<[u8; 3]>("hash:00:AB:ff").unwrap(),
            [0, 0xab, 255]
        );
    }
    assert_eq!(view.to_string(), "hash:00ABFF");
    let separator = "sep".repeat(100);
    let view = hex(&[0, 1]).with_separator(&separator);
    assert_eq!(view.to_string(), format!("00{separator}01"));
    assert_eq!(
        Format::new()
            .with_separator(&separator)
            .decode::<[u8; 2]>(view.to_vec())
            .unwrap(),
        [0, 1]
    );
}

#[test]
fn malformed_framing_preserves_every_destination() {
    use DecodeError::{InvalidDigit, InvalidSeparator, OddLength};
    let format = Format::new().with_prefix("🔑:").with_separator(":");
    let prefix_len = "🔑:".len();
    for (input, error) in [
        ("0", OddLength),
        (
            "00:",
            InvalidSeparator {
                index: prefix_len + 2,
            },
        ),
        (
            "00:11:",
            InvalidSeparator {
                index: prefix_len + 5,
            },
        ),
        (
            "0011",
            InvalidSeparator {
                index: prefix_len + 2,
            },
        ),
        (
            "00-11",
            InvalidSeparator {
                index: prefix_len + 2,
            },
        ),
        (
            "00::11",
            InvalidDigit {
                byte: b':',
                index: prefix_len + 3,
            },
        ),
        (
            "00:gg",
            InvalidDigit {
                byte: b'g',
                index: prefix_len + 3,
            },
        ),
        (
            "00:0g",
            InvalidDigit {
                byte: b'g',
                index: prefix_len + 4,
            },
        ),
        ("00:11:2", OddLength),
        (
            ":00",
            InvalidDigit {
                byte: b':',
                index: prefix_len,
            },
        ),
    ] {
        let input = format!("🔑:{input}");
        assert_eq!(format.decode::<Vec<u8>>(&input).unwrap_err(), error);
        assert_eq!(format.decode::<[u8; 2]>(&input).unwrap_err(), error);
        let mut fixed = [0xcc; 8];
        assert_eq!(format.decode_into(&input, &mut fixed).unwrap_err(), error);
        assert_eq!(fixed, [0xcc; 8]);
        let mut growing = Vec::from([42]);
        assert_eq!(
            format.decode_append(&input, &mut growing).unwrap_err(),
            error
        );
        assert_eq!(growing, [42]);
        #[cfg(feature = "std")]
        {
            let mut writer = Vec::from([42]);
            let DecodeWriteError::Decode(actual) =
                format.decode_write(&input, &mut writer).unwrap_err()
            else {
                panic!("expected decode error")
            };
            assert_eq!(actual, error);
            assert_eq!(writer, [42]);
        }
    }
    let error = InvalidSeparator { index: 7 };
    assert_eq!(error.to_string(), "invalid hex separator at byte 7");
    assert_eq!(
        Format::new()
            .with_separator("::")
            .decode::<Vec<u8>>("00:11")
            .unwrap_err(),
        InvalidSeparator { index: 2 }
    );
    assert_eq!(
        Format::new()
            .with_separator(":")
            .decode::<Vec<u8>>(b"00:\xff0")
            .unwrap_err(),
        InvalidDigit {
            byte: 255,
            index: 3
        }
    );
}

#[test]
fn framed_writes_check_capacity_and_propagate_errors() {
    let view = hex(&[0, 0xab, 255])
        .with_custom_prefix("🔑:")
        .with_separator("→");
    let expected = view.to_vec();
    for capacity in 0..expected.len() {
        let mut output = crate::std::vec![0xcc; capacity];
        assert_eq!(
            view.encode_to_slice(&mut output).unwrap_err(),
            BufferTooSmall {
                required: expected.len(),
                available: capacity
            }
        );
        assert_eq!(output, crate::std::vec![0xcc; capacity]);
    }
    struct Limited {
        remaining: usize,
        bytes: Vec<u8>,
    }
    impl fmt::Write for Limited {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let n = self.remaining.min(value.len());
            self.bytes.extend_from_slice(&value.as_bytes()[..n]);
            self.remaining -= n;
            if n == value.len() {
                Ok(())
            } else {
                Err(fmt::Error)
            }
        }
    }
    for remaining in 0..expected.len() {
        let mut writer = Limited {
            remaining,
            bytes: Vec::new(),
        };
        assert_eq!(view.write_to(&mut writer), Err(fmt::Error));
        assert_eq!(writer.bytes, expected[..remaining]);
    }
    let mut exact = crate::std::vec![0; expected.len()];
    assert_eq!(view.encode_to_slice(&mut exact).unwrap(), expected);
}

#[test]
fn setters_and_const_builders_keep_borrowed_configuration() {
    fn shorten<'a>(view: Hex<'static>, prefix: &'a str, separator: &'a str) -> Hex<'a> {
        view.with_custom_prefix(prefix).with_separator(separator)
    }
    fn shorten_format<'a>(format: Format<'static>, prefix: &'a str) -> Format<'a> {
        format.with_prefix(prefix)
    }
    const FORMAT: Format<'static> = Format::new()
        .with_upper_case()
        .with_prefix("0x")
        .with_separator(":");
    const LOWER: Format<'static> = FORMAT.with_lower_case();
    assert_eq!(hex(&[0, 0xab]).with_format(LOWER).to_string(), "0x00:ab");
    const VIEW: Hex<'static> = Hex::new(&[0, 0xab])
        .with_format(FORMAT)
        .with_custom_prefix("hash:");
    assert_eq!(VIEW.to_string(), "hash:00:AB");
    let prefix = String::from("borrowed:");
    let separator = String::from("-");
    assert_eq!(
        shorten(VIEW, &prefix, &separator).to_string(),
        "borrowed:00-AB"
    );
    assert_eq!(
        hex(&[0, 0xab])
            .with_format(shorten_format(FORMAT, &prefix))
            .to_string(),
        "borrowed:00:AB"
    );
    let mut format = Format::new();
    format
        .set_upper_case()
        .set_prefix(&prefix)
        .set_separator(&separator);
    assert_eq!(
        format.decode::<[u8; 2]>("borrowed:00-aB").unwrap(),
        [0, 0xab]
    );
    let mut view = hex(&[0, 0xab]);
    view.set_format(format);
    assert_eq!(view.to_string(), "borrowed:00-AB");
    view.set_lower_case().set_prefix(true).set_separator(":");
    assert_eq!(view.to_string(), "0x00:ab");
    view.set_custom_prefix(&prefix);
    assert_eq!(view.to_string(), "borrowed:00:ab");
    view.set_prefix(false);
    assert_eq!(view.to_string(), "00:ab");
    view.set_upper_case();
    assert_eq!(view.to_string(), "00:AB");
    format.set_lower_case();
    assert_eq!(
        hex(&[0, 0xab]).with_format(format).to_string(),
        "borrowed:00-ab"
    );
}
