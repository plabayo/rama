//! Utility types and functions that can be used in context of encoding headers.

use rama_utils::macros::match_ignore_ascii_case_str;
use std::fmt;

mod accept_encoding;
pub use accept_encoding::AcceptEncoding;

use super::specifier::{Quality, QualityValue};

pub trait SupportedEncodings: Copy {
    fn gzip(&self) -> bool;
    fn deflate(&self) -> bool;
    fn br(&self) -> bool;
    fn zstd(&self) -> bool;
}

impl SupportedEncodings for bool {
    fn gzip(&self) -> bool {
        *self
    }

    fn deflate(&self) -> bool {
        *self
    }

    fn br(&self) -> bool {
        *self
    }

    fn zstd(&self) -> bool {
        *self
    }
}

#[derive(Copy, Clone, Debug, Ord, PartialOrd, PartialEq, Eq, Hash)]
/// This enum's variants are ordered from least to most preferred.
pub enum Encoding {
    Identity,
    Deflate,
    Gzip,
    Brotli,
    Zstd,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<Encoding> for http::HeaderValue {
    #[inline]
    fn from(encoding: Encoding) -> Self {
        http::HeaderValue::from_static(encoding.as_str())
    }
}

impl Encoding {
    fn as_str(self) -> &'static str {
        match self {
            Encoding::Identity => "identity",
            Encoding::Gzip => "gzip",
            Encoding::Deflate => "deflate",
            Encoding::Brotli => "br",
            Encoding::Zstd => "zstd",
        }
    }

    pub fn to_file_extension(self) -> Option<&'static std::ffi::OsStr> {
        match self {
            Encoding::Gzip => Some(std::ffi::OsStr::new(".gz")),
            Encoding::Deflate => Some(std::ffi::OsStr::new(".zz")),
            Encoding::Brotli => Some(std::ffi::OsStr::new(".br")),
            Encoding::Zstd => Some(std::ffi::OsStr::new(".zst")),
            Encoding::Identity => None,
        }
    }

    fn parse(s: &str, supported_encoding: impl SupportedEncodings) -> Option<Encoding> {
        match_ignore_ascii_case_str! {
            match (s) {
                "gzip" | "x-gzip" if supported_encoding.gzip() => Some(Encoding::Gzip),
                "deflate" if supported_encoding.deflate() => Some(Encoding::Deflate),
                "br" if supported_encoding.br() => Some(Encoding::Brotli),
                "zstd" if supported_encoding.zstd() => Some(Encoding::Zstd),
                "identity" => Some(Encoding::Identity),
                _ => None,
            }
        }
    }

    pub fn maybe_from_content_encoding_header(
        headers: &http::HeaderMap,
        supported_encoding: impl SupportedEncodings,
    ) -> Option<Self> {
        headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|hval| hval.to_str().ok())
            .and_then(|s| Encoding::parse(s, supported_encoding))
    }

    #[inline]
    pub fn from_content_encoding_header(
        headers: &http::HeaderMap,
        supported_encoding: impl SupportedEncodings,
    ) -> Self {
        Encoding::maybe_from_content_encoding_header(headers, supported_encoding)
            .unwrap_or(Encoding::Identity)
    }

    pub fn maybe_from_accept_encoding_headers(
        headers: &http::HeaderMap,
        supported_encoding: impl SupportedEncodings,
    ) -> Option<Self> {
        Encoding::maybe_preferred_encoding(parse_accept_encoding_headers(
            headers,
            supported_encoding,
        ))
    }

    #[inline]
    pub fn from_accept_encoding_headers(
        headers: &http::HeaderMap,
        supported_encoding: impl SupportedEncodings,
    ) -> Self {
        Encoding::maybe_from_accept_encoding_headers(headers, supported_encoding)
            .unwrap_or(Encoding::Identity)
    }

    pub fn maybe_preferred_encoding(
        accepted_encodings: impl Iterator<Item = QualityValue<Encoding>>,
    ) -> Option<Self> {
        accepted_encodings
            .filter(|qval| qval.quality.as_u16() > 0)
            .max_by_key(|qval| (qval.quality, qval.value))
            .map(|qval| qval.value)
    }
}

/// based on https://github.com/http-rs/accept-encoding
pub fn parse_accept_encoding_headers<'a>(
    headers: &'a http::HeaderMap,
    supported_encoding: impl SupportedEncodings + 'a,
) -> impl Iterator<Item = QualityValue<Encoding>> + 'a {
    headers
        .get_all(http::header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|hval| hval.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(move |v| {
            let mut v = v.splitn(2, ';');

            let encoding = match Encoding::parse(v.next().unwrap().trim(), supported_encoding) {
                Some(encoding) => encoding,
                None => return None, // ignore unknown encodings
            };

            let qval = if let Some(qval) = v.next() {
                qval.trim().parse::<Quality>().ok()?
            } else {
                Quality::one()
            };

            Some(QualityValue::new(encoding, qval))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Copy, Clone, Default)]
    struct SupportedEncodingsAll;

    impl SupportedEncodings for SupportedEncodingsAll {
        fn gzip(&self) -> bool {
            true
        }

        fn deflate(&self) -> bool {
            true
        }

        fn br(&self) -> bool {
            true
        }

        fn zstd(&self) -> bool {
            true
        }
    }

    #[test]
    fn no_accept_encoding_header() {
        let encoding =
            Encoding::from_accept_encoding_headers(&http::HeaderMap::new(), SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);
    }

    #[test]
    fn accept_encoding_header_single_encoding() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Gzip, encoding);
    }

    #[test]
    fn accept_encoding_header_two_encodings() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip,br"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn accept_encoding_header_gzip_x_gzip() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip,x-gzip"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Gzip, encoding);
    }

    #[test]
    fn accept_encoding_header_x_gzip_deflate() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("deflate,x-gzip"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Gzip, encoding);
    }

    #[test]
    fn accept_encoding_header_three_encodings() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip,deflate,br"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn accept_encoding_header_two_encodings_with_one_qvalue() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.5,br"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn accept_encoding_header_three_encodings_with_one_qvalue() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.5,deflate,br"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn two_accept_encoding_headers_with_one_qvalue() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.5"),
        );
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("br"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn two_accept_encoding_headers_three_encodings_with_one_qvalue() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.5,deflate"),
        );
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("br"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn three_accept_encoding_headers_with_one_qvalue() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.5"),
        );
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("deflate"),
        );
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("br"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn accept_encoding_header_two_encodings_with_two_qvalues() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.5,br;q=0.8"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.8,br;q=0.5"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Gzip, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.995,br;q=0.999"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn accept_encoding_header_three_encodings_with_three_qvalues() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.5,deflate;q=0.6,br;q=0.8"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.8,deflate;q=0.6,br;q=0.5"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Gzip, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.6,deflate;q=0.8,br;q=0.5"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Deflate, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.995,deflate;q=0.997,br;q=0.999"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn accept_encoding_header_invalid_encdoing() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("invalid,gzip"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Gzip, encoding);
    }

    #[test]
    fn accept_encoding_header_with_qvalue_zero() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0."),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0,br;q=0.5"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn accept_encoding_header_with_uppercase_letters() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gZiP"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Gzip, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.5,br;Q=0.8"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn accept_encoding_header_with_allowed_spaces() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static(" gzip\t; q=0.5 ,\tbr ;\tq=0.8\t"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Brotli, encoding);
    }

    #[test]
    fn accept_encoding_header_with_invalid_spaces() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q =0.5"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q= 0.5"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);
    }

    #[test]
    fn accept_encoding_header_with_invalid_quvalues() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=-0.1"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=00.5"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0.5000"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=.5"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=1.01"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);

        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=1.001"),
        );
        let encoding = Encoding::from_accept_encoding_headers(&headers, SupportedEncodingsAll);
        assert_eq!(Encoding::Identity, encoding);
    }
}
