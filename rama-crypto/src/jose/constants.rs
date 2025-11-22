pub(crate) use der_encoding_tags::*;
pub(crate) use rsa_algorithm_identifier::RSA_ALGORITHM_IDENTIFIER;
mod der_encoding_tags {
    /// Identifier tag for a DER encoded integer.
    /// Defined in [ITU X.680](https://www.itu.int/rec/T-REC-X.690/).
    pub(crate) const DER_TAG_INTEGER: u8 = 0x02;
    /// Identifier tag for a DER encoded bit string.
    /// Defined in [ITU X.680](https://www.itu.int/rec/T-REC-X.690/).
    pub(crate) const DER_TAG_BIT_STRING: u8 = 0x03;
    /// Identifier tag for a DER encoded sequence.
    /// Defined in [ITU X.680](https://www.itu.int/rec/T-REC-X.690/).
    pub(crate) const DER_TAG_SEQUENCE: u8 = 0x30;
    /// Maximum length of a DER encoded length in short form.
    /// Defined in [ITU X.690](https://www.itu.int/rec/T-REC-X.690/).
    pub(crate) const DER_LENGTH_SHORT_FORM_MAX: usize = 127;
    /// Octet that indicates that no unused bits are present in a bit string.
    /// Defined in section 8.6 of [ITU X.690](https://www.itu.int/rec/T-REC-X.690/).
    pub(crate) const BIT_STRING_NO_UNUSED_BITS: u8 = 0x00;
}

/// Byte representation of RSA encryption algorithm identifier.
/// See appendix C of [RFC 8017](https://datatracker.ietf.org/doc/rfc8017/)
mod rsa_algorithm_identifier {
    const SEQUENCE_TAG: u8 = 0x30;
    const LENGTH: u8 = 0x0d;
    const OBJECT_IDENTIFIER_TAG: u8 = 0x06;
    const LENGTH_OID: u8 = 0x09;
    const NULL_TAG: u8 = 0x05;
    const LENGTH_NULL: u8 = 0x00;

    pub(crate) const RSA_ALGORITHM_IDENTIFIER: [u8; 15] = [
        SEQUENCE_TAG,
        LENGTH,
        OBJECT_IDENTIFIER_TAG,
        LENGTH_OID,
        // OID: 1.2.840.113549.1.1.1
        0x2a,
        0x86,
        0x48,
        0x86,
        0xf7,
        0x0d,
        0x01,
        0x01,
        0x01,
        NULL_TAG,
        LENGTH_NULL,
    ];
}

// Integer encoding constants
pub(crate) const INTEGER_SIGN_BIT_MASK: u8 = 0x80;
