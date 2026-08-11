use rama_core::bytes::BytesMut;

use crate::byte_sets::is_unreserved_byte;

/// Normalize percent-encoding in place per RFC 3986 §6.2.2.1 and §6.2.2.2.
pub(crate) fn normalize_pct(buf: &mut BytesMut) {
    if !buf.contains(&b'%') {
        return;
    }

    let bytes = buf.as_mut();
    let mut read = 0;
    let mut write = 0;
    while read < bytes.len() {
        if bytes[read] == b'%' && read + 2 < bytes.len() {
            let high = bytes[read + 1];
            let low = bytes[read + 2];
            if let Some(decoded) = rama_utils::hex::decode_pair(high, low) {
                if is_unreserved_byte(decoded) {
                    bytes[write] = decoded;
                    write += 1;
                    read += 3;
                    continue;
                }

                bytes[write] = b'%';
                bytes[write + 1] = high.to_ascii_uppercase();
                bytes[write + 2] = low.to_ascii_uppercase();
                write += 3;
                read += 3;
                continue;
            }
        }

        if write != read {
            bytes[write] = bytes[read];
        }
        write += 1;
        read += 1;
    }
    buf.truncate(write);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(input: &[u8]) -> Vec<u8> {
        let mut bytes = BytesMut::from(input);
        normalize_pct(&mut bytes);
        bytes.to_vec()
    }

    #[test]
    fn decodes_unreserved_octets() {
        assert_eq!(normalize(b"exa%6Dple"), b"example");
        assert_eq!(normalize(b"path%2D1%2E0"), b"path-1.0");
    }

    #[test]
    fn preserves_reserved_octets_with_uppercase_hex() {
        assert_eq!(normalize(b"foo%2fbar"), b"foo%2Fbar");
        assert_eq!(normalize(b"a%26b"), b"a%26b");
    }

    #[test]
    fn leaves_plain_and_malformed_input_unchanged() {
        assert_eq!(normalize(b"plain"), b"plain");
        assert_eq!(normalize(b"x%6"), b"x%6");
    }
}
