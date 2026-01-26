rama_utils::macros::enums::enum_builder! {
    /// Directive for the [`TransferEncoding`] header.
    @String
    pub enum TransferEncodingDirective {
        /// A format using the [Lempel-Ziv-Welch](https://en.wikipedia.org/wiki/LZW) (LZW) algorithm.
        ///
        /// The value name was taken from the UNIX compress program,
        /// which implemented this algorithm. Like the compress program,
        /// which has disappeared from most UNIX distributions,
        /// this content-encoding is used by almost no browsers today,
        /// partly because of a patent issue (which expired in 2003).
        Compress => "compress",
        /// Using the zlib structure (defined in [RFC 1950](https://datatracker.ietf.org/doc/html/rfc1950))
        /// with the [deflate](https://en.wikipedia.org/wiki/Deflate) compression algorithm
        /// (defined in [RFC 1951](https://datatracker.ietf.org/doc/html/rfc1951)).
        Deflate => "deflate",
        /// A format using the [Lempel-Ziv coding](https://en.wikipedia.org/wiki/LZ77_and_LZ78#LZ77) (LZ77),
        /// with a 32-bit CRC. This is the original format of the UNIX gzip program.
        ///
        /// The HTTP/1.1 standard also recommends that the servers supporting this
        /// content-encoding should recognize x-gzip as an alias, for compatibility purposes.
        Gzip => "gzip" | "x-gzip",
        /// Data is sent in a series of chunks.
        ///
        /// Content can be sent in streams of unknown size to be transferred as a sequence of
        /// length-delimited buffers, so the sender can keep a connection open,
        /// and let the recipient know when it has received the entire message.
        /// The Content-Length header must be omitted, and at the beginning of each chunk,
        /// a string of hex digits indicate the size of the chunk-data in octets,
        /// followed by `\r\n` and then the chunk itself, followed by another `\r\n`.
        /// The terminating chunk is a zero-length chunk.
        Chunked => "chunked",
    }
}

derive_non_empty_flat_csv_header! {
    #[header(name = TRANSFER_ENCODING, sep = Comma)]
    #[derive(Clone, Debug)]
    /// `Transfer-Encoding` header, defined in
    /// [RFC7230](https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.1)
    ///
    /// The `Transfer-Encoding` header field lists the transfer coding names
    /// corresponding to the sequence of transfer codings that have been (or
    /// will be) applied to the payload body in order to form the message
    /// body.
    ///
    /// Note that setting this header will *remove* any previously set
    /// `Content-Length` header, in accordance with
    /// [RFC7230](https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.2):
    ///
    /// > A sender MUST NOT send a Content-Length header field in any message
    /// > that contains a Transfer-Encoding header field.
    ///
    /// # ABNF
    ///
    /// ```text
    /// Transfer-Encoding = 1#transfer-coding
    /// ```
    ///
    /// # Example values
    ///
    /// * `chunked`
    /// * `gzip, chunked`
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http_headers::TransferEncoding;
    ///
    /// let transfer = TransferEncoding::chunked();
    /// ```
    pub struct TransferEncoding(pub NonEmptySmallVec<2, TransferEncodingDirective>);
}

impl TransferEncoding {
    /// Constructor for the most common Transfer-Encoding, `chunked`.
    #[must_use]
    #[inline(always)]
    pub fn chunked() -> Self {
        Self::new(TransferEncodingDirective::Chunked)
    }

    /// Returns whether this ends with the `chunked` encoding.
    #[must_use]
    pub fn is_chunked(&self) -> bool {
        self.0.last().eq(&TransferEncodingDirective::Chunked)
    }
}

#[cfg(test)]
mod tests {
    use rama_utils::collections::non_empty_smallvec;

    use super::super::{test_decode, test_encode};
    use super::{TransferEncoding, TransferEncodingDirective};

    #[test]
    fn chunked_is_chunked() {
        assert!(TransferEncoding::chunked().is_chunked());
    }

    #[test]
    fn decode_gzip_chunked_is_chunked() {
        let te = test_decode::<TransferEncoding>(&["gzip, chunked"]).unwrap();
        assert!(te.is_chunked());
    }

    #[test]
    fn decode_chunked_gzip_is_not_chunked() {
        let te = test_decode::<TransferEncoding>(&["chunked, gzip"]).unwrap();
        assert!(!te.is_chunked());
    }

    #[test]
    fn decode_notchunked_is_not_chunked() {
        let te = test_decode::<TransferEncoding>(&["notchunked"]).unwrap();
        assert!(!te.is_chunked());
    }

    #[test]
    fn decode_multiple_is_chunked() {
        let te = test_decode::<TransferEncoding>(&["gzip", "chunked"]).unwrap();
        assert!(te.is_chunked());
    }

    #[test]
    fn encode_single() {
        let allow = TransferEncoding::new(TransferEncodingDirective::Gzip);

        let headers = test_encode(allow);
        assert_eq!(headers["transfer-encoding"], "gzip");
    }

    #[test]
    fn encode_multi() {
        let allow = TransferEncoding(non_empty_smallvec![
            TransferEncodingDirective::Deflate,
            TransferEncodingDirective::Chunked,
        ]);

        let headers = test_encode(allow);
        assert_eq!(headers["transfer-encoding"], "deflate, chunked");
    }
}
