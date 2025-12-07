use rama_utils::collections::NonEmptyVec;

use self::sealed::CmpCoding;

rama_utils::macros::enums::enum_builder! {
    /// Directive for the [`ContentEncoding`] header.
    @String
    pub enum ContentEncodingDirective {
        /// A format using the [Lempel-Ziv coding](https://en.wikipedia.org/wiki/LZ77_and_LZ78#LZ77) (LZ77),
        /// with a 32-bit CRC. This is the original format of the UNIX gzip program.
        ///
        /// The HTTP/1.1 standard also recommends that the servers supporting this
        /// content-encoding should recognize x-gzip as an alias, for compatibility purposes.
        Gzip => "gzip" | "x-gzip",
        /// A format using the [Lempel-Ziv-Welch](https://en.wikipedia.org/wiki/LZW) (LZW) algorithm.
        /// The value name was taken from the UNIX compress program,
        /// which implemented this algorithm. Like the compress program,
        /// which has disappeared from most UNIX distributions,
        /// this content-encoding is not used by many browsers today,
        /// partly because of a patent issue (it expired in 2003).
        Compress => "compress",
        /// Using the zlib structure (defined in [RFC 1950](https://datatracker.ietf.org/doc/html/rfc1950))
        /// with the [deflate](https://en.wikipedia.org/wiki/Deflate) compression algorithm
        /// (defined in [RFC 1951](https://datatracker.ietf.org/doc/html/rfc1951)).
        Deflate => "deflate",
        /// A format using the [Brotli](https://developer.mozilla.org/en-US/docs/Glossary/Brotli_compression)
        /// algorithm structure (defined in [RFC 7932](https://datatracker.ietf.org/doc/html/rfc7932)).
        Brotli => "br",
        /// A format using the [Zstandard](https://developer.mozilla.org/en-US/docs/Glossary/Zstandard_compression)
        /// algorithm structure (defined in [RFC 8878](https://datatracker.ietf.org/doc/html/rfc8878)).
        ZStandard => "zstd",
        /// A format that uses the [Dictionary-Compressed Brotli algorithm](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-compression-dictionary#name-dictionary-compressed-brotl).
        /// See [Compression Dictionary Transport](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Compression_dictionary_transport).
        ///
        /// Experimental directive still in Draft!
        DCBrotli => "dcb",
        /// A format that uses the [Dictionary-Compressed Zstandard algorithm](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-compression-dictionary#name-dictionary-compressed-zstan).
        /// See [Compression Dictionary Transport](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Compression_dictionary_transport).
        ///
        /// Experimental directive still in Draft!
        DCZStandard => "dcz",
    }
}

derive_non_empty_flat_csv_header! {
    #[header(name = CONTENT_ENCODING, sep = Comma)]
    #[derive(Clone, Debug)]
    /// `Content-Encoding` header, defined in
    /// [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-3.1.2.2)
    ///
    /// The `Content-Encoding` header field indicates what content codings
    /// have been applied to the representation, beyond those inherent in the
    /// media type, and thus what decoding mechanisms have to be applied in
    /// order to obtain data in the media type referenced by the Content-Type
    /// header field.  Content-Encoding is primarily used to allow a
    /// representation's data to be compressed without losing the identity of
    /// its underlying media type.
    ///
    /// # ABNF
    ///
    /// ```text
    /// Content-Encoding = 1#content-coding
    /// ```
    ///
    /// # Example values
    ///
    /// * `gzip`
    /// * `br`
    /// * `zstd`
    /// * `deflate, gzip`
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_http_headers::ContentEncoding;
    ///
    /// let content_enc = ContentEncoding::gzip();
    /// ```
    pub struct ContentEncoding(pub NonEmptyVec<ContentEncodingDirective>);
}

impl ContentEncoding {
    /// Create a new [`ContentEncoding`] header with multiple directives.
    ///
    /// Meaning the content is encoded with all given directives and in order.
    #[inline]
    #[must_use]
    pub fn new_multi(directives: NonEmptyVec<ContentEncodingDirective>) -> Self {
        Self(directives)
    }

    /// A constructor to easily create a `Content-Encoding: gzip` header.
    #[inline]
    #[must_use]
    pub fn gzip() -> Self {
        Self(NonEmptyVec::new(ContentEncodingDirective::Gzip))
    }

    /// A constructor to easily create a `Content-Encoding: br` header.
    #[inline]
    #[must_use]
    pub fn brotli() -> Self {
        Self(NonEmptyVec::new(ContentEncodingDirective::Brotli))
    }

    /// A constructor to easily create a `Content-Encoding: zstd` header.
    #[inline]
    #[must_use]
    pub fn zstd() -> Self {
        Self(NonEmptyVec::new(ContentEncodingDirective::ZStandard))
    }

    /// Check if this header contains a given "coding".
    ///
    /// This can be used with these argument types:
    ///
    /// - `&str`
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http_headers::ContentEncoding;
    ///
    /// let content_enc = ContentEncoding::gzip();
    ///
    /// assert!(content_enc.contains_directive("gzip"));
    /// assert!(!content_enc.contains_directive("br"));
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn contains_directive(&self, coding: impl CmpCoding) -> bool {
        self.0.iter().any(|other| coding.cmp_coding(other))
    }
}

mod sealed {
    use super::ContentEncodingDirective;

    pub trait CmpCoding: Sealed {}

    pub trait Sealed {
        fn cmp_coding(&self, other: &ContentEncodingDirective) -> bool;
    }

    impl CmpCoding for &str {}

    impl Sealed for &str {
        #[inline(always)]
        fn cmp_coding(&self, other: &ContentEncodingDirective) -> bool {
            self.trim().eq_ignore_ascii_case(other.as_str())
        }
    }

    impl CmpCoding for ContentEncodingDirective {}

    impl Sealed for ContentEncodingDirective {
        fn cmp_coding(&self, other: &ContentEncodingDirective) -> bool {
            self.eq(other)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_header_single() {
        let ContentEncoding(directives) = test_decode(&["deflate, gzip"]).unwrap();

        assert_eq!(directives.len(), 2);
        assert_eq!(directives[0], ContentEncodingDirective::Deflate);
        assert_eq!(directives[1], ContentEncodingDirective::Gzip);

        let header = ContentEncoding(directives);

        assert!(header.contains_directive(ContentEncodingDirective::Deflate));
        assert!(header.contains_directive(ContentEncodingDirective::Gzip));
        assert!(!header.contains_directive(ContentEncodingDirective::Brotli));
    }

    #[test]
    fn decode_header_multi() {
        let ContentEncoding(directives) = test_decode(&["deflate, gzip", "compress"]).unwrap();

        assert_eq!(directives.len(), 3);
        assert_eq!(directives[0], ContentEncodingDirective::Deflate);
        assert_eq!(directives[1], ContentEncodingDirective::Gzip);
        assert_eq!(directives[2], ContentEncodingDirective::Compress);

        let header = ContentEncoding(directives);

        assert!(header.contains_directive(ContentEncodingDirective::Deflate));
        assert!(header.contains_directive(ContentEncodingDirective::Gzip));
        assert!(header.contains_directive(ContentEncodingDirective::Compress));
        assert!(!header.contains_directive(ContentEncodingDirective::Brotli));
    }

    #[test]
    fn encode_single() {
        let allow = ContentEncoding::new(ContentEncodingDirective::Brotli);

        let headers = test_encode(allow);
        assert_eq!(headers["content-encoding"], "br");
    }

    #[test]
    fn encode_multi() {
        let allow = ContentEncoding::new_multi(non_empty_vec![
            ContentEncodingDirective::Deflate,
            ContentEncodingDirective::Gzip
        ]);

        let headers = test_encode(allow);
        assert_eq!(headers["content-encoding"], "deflate, gzip");
    }

    #[test]
    fn decode_with_empty_header_value() {
        let ContentEncoding(directives) = test_decode(&[""]).unwrap();

        assert_eq!(directives.len(), 1);
        assert_eq!(
            directives[0],
            ContentEncodingDirective::Unknown("".to_owned())
        );
    }

    #[test]
    fn decode_with_no_headers() {
        assert!(test_decode::<ContentEncoding>(&[]).is_none());
    }

    #[test]
    fn decode_header_unknown_directive() {
        let ContentEncoding(directives) = test_decode(&["foobar"]).unwrap();

        assert_eq!(directives.len(), 1);
        assert_eq!(
            directives[0],
            ContentEncodingDirective::Unknown("foobar".to_owned())
        );
    }
}
