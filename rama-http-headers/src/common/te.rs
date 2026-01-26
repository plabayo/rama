use crate::specifier::QualityValue;
use rama_utils::collections::NonEmptySmallVec;

rama_utils::macros::enums::enum_builder! {
    /// Directive for the [`Te`] header.
    @String
    pub enum TeDirective {
        /// A format using the [Lempel-Ziv-Welch](https://en.wikipedia.org/wiki/LZW) (LZW) algorithm
        /// is accepted as a transfer coding name.
        Compress => "compress",
        /// Using the zlib structure (defined in [RFC 1950](https://datatracker.ietf.org/doc/html/rfc1950))
        /// is accepted as a transfer coding name.
        Deflate => "deflate",
        /// A format using the [Lempel-Ziv coding](https://en.wikipedia.org/wiki/LZ77_and_LZ78#LZ77)(LZ77),
        /// with a 32-bit CRC is accepted as a transfer coding name.
        Gzip => "gzip",
        /// Indicates that the client will not discard trailer fields in a
        /// [chunked transfer coding](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Transfer-Encoding#chunked).
        Trailers => "trailers",
    }
}

derive_non_empty_flat_csv_header! {
    #[header(name = TE, sep = Comma)]
    #[derive(Clone, Debug, PartialEq)]
    /// `TE` header, defined in
    /// [RFC7230](https://datatracker.ietf.org/doc/html/rfc7230#section-4.3)
    ///
    /// As RFC7230 states, "The "TE" header field in a request indicates what transfer codings,
    /// besides chunked, the client is willing to accept in response, and
    /// whether or not the client is willing to accept trailer fields in a
    /// chunked transfer coding."
    ///
    /// For HTTP/1.1 compliant clients `chunked` transfer codings are assumed to be acceptable and
    /// so should never appear in this header.
    ///
    /// # ABNF
    ///
    /// ```text
    /// TE        = "TE" ":" #( t-codings )
    /// t-codings = "trailers" | ( transfer-extension [ accept-params ] )
    /// ```
    ///
    /// # Example values
    /// * `trailers`
    /// * `trailers, deflate;q=0.5`
    pub struct Te(pub NonEmptySmallVec<2, QualityValue<TeDirective>>);
}

impl Te {
    /// Create a `TE: trailers` header.
    #[must_use]
    pub fn trailers() -> Self {
        Self(NonEmptySmallVec::new(QualityValue::new_value(
            TeDirective::Trailers,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use crate::specifier::Quality;

    #[test]
    fn decode_header_compress() {
        let Te(direcives) = test_decode(&["compress"]).unwrap();

        assert_eq!(direcives.len(), 1);
        assert_eq!(direcives[0].value.as_str(), "compress");
        assert_eq!(direcives[0].quality, Quality::one());
    }

    #[test]
    fn decode_header_trailers_deflate() {
        let Te(direcives) = test_decode(&["trailers, deflate;q=0.5"]).unwrap();

        assert_eq!(direcives.len(), 2);
        assert_eq!(direcives[0].value.as_str(), "trailers");
        assert_eq!(direcives[0].quality, Quality::one());
        assert_eq!(direcives[1].value.as_str(), "deflate");
        assert_eq!(direcives[1].quality, Quality::new_clamped(500));
    }

    #[test]
    fn decode_header_trailers_deflate_split() {
        let Te(direcives) = test_decode(&["trailers", "deflate;q=0.5"]).unwrap();

        assert_eq!(direcives.len(), 2);
        assert_eq!(direcives[0].value.as_str(), "trailers");
        assert_eq!(direcives[0].quality, Quality::one());
        assert_eq!(direcives[1].value.as_str(), "deflate");
        assert_eq!(direcives[1].quality, Quality::new_clamped(500));
    }

    #[test]
    fn encode() {
        let te = Te::trailers();
        let headers = test_encode(te);
        assert_eq!(headers["te"], "trailers");
    }
}
