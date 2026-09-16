//! TLS 1.3 key derivation encoding (RFC 8446, section 7.1).

/// Encode the HKDF info field, adding the TLS 1.3 label prefix.
pub fn encode_hkdf_label(
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, InvalidHkdfLabel> {
    let output_len = u16::try_from(output_len).map_err(|_error| InvalidHkdfLabel)?;
    if label.is_empty() || label.len() > 249 || context.len() > 255 {
        return Err(InvalidHkdfLabel);
    }
    let mut encoded = Vec::with_capacity(10 + label.len() + context.len());
    encoded.extend_from_slice(&output_len.to_be_bytes());
    encoded.push((6 + label.len()) as u8);
    encoded.extend_from_slice(b"tls13 ");
    encoded.extend_from_slice(label);
    encoded.push(context.len() as u8);
    encoded.extend_from_slice(context);
    Ok(encoded)
}

rama_utils::macros::error::static_str_error! {
    #[doc = "TLS 1.3 HKDF label, context or output length is out of range"]
    pub struct InvalidHkdfLabel;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9001_initial_label() {
        assert_eq!(
            encode_hkdf_label(b"client in", &[], 32).unwrap(),
            b"\x00\x20\x0ftls13 client in\x00"
        );
        assert_eq!(
            encode_hkdf_label(b"key", &[1, 2, 3], 16).unwrap(),
            b"\x00\x10\x09tls13 key\x03\x01\x02\x03"
        );
    }

    #[test]
    fn vector_length_boundaries() {
        encode_hkdf_label(&[], &[], 32).unwrap_err();
        encode_hkdf_label(&[0; 250], &[], 32).unwrap_err();
        encode_hkdf_label(b"key", &[0; 256], 32).unwrap_err();
        encode_hkdf_label(b"key", &[], 65536).unwrap_err();
        let max = encode_hkdf_label(&[0; 249], &[1; 255], 65535).unwrap();
        assert_eq!(&max[..3], &[255, 255, 255]);
        assert_eq!(max[258], 255);
        assert_eq!(&max[259..], &[1; 255]);
    }
}
