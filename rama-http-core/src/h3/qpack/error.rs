//! Connection-scoped QPACK errors (RFC 9204 §6).

use rama_http_types::proto::h3::Code;
use rama_http_types::proto::h3::qpack::PrefixError;
use rama_http_types::proto::h3::qpack::field::InvalidPrefix;

/// A QPACK error that maps to an HTTP/3 connection error code (RFC 9204 §6).
///
/// The `&'static str` reason is a fixed diagnostic label, not a formatted string, so no allocation
/// happens on the error path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QpackError {
    /// `QPACK_DECOMPRESSION_FAILED` (0x0200): a field section could not be decoded.
    DecompressionFailed(&'static str),
    /// `QPACK_ENCODER_STREAM_ERROR` (0x0201): the peer's encoder stream was invalid.
    EncoderStreamError(&'static str),
    /// `QPACK_DECODER_STREAM_ERROR` (0x0202): the peer's decoder stream was invalid.
    DecoderStreamError(&'static str),
}

impl QpackError {
    /// The HTTP/3 error code for this error.
    #[must_use]
    pub const fn code(self) -> Code {
        match self {
            Self::DecompressionFailed(_) => Code::QPACK_DECOMPRESSION_FAILED,
            Self::EncoderStreamError(_) => Code::QPACK_ENCODER_STREAM_ERROR,
            Self::DecoderStreamError(_) => Code::QPACK_DECODER_STREAM_ERROR,
        }
    }

    /// The fixed diagnostic reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::DecompressionFailed(r)
            | Self::EncoderStreamError(r)
            | Self::DecoderStreamError(r) => r,
        }
    }
}

impl core::fmt::Display for QpackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({})", self.reason(), self.code())
    }
}

impl std::error::Error for QpackError {}

impl From<PrefixError> for QpackError {
    fn from(e: PrefixError) -> Self {
        match e {
            PrefixError::UnexpectedEnd => Self::DecompressionFailed("truncated field section"),
            _ => Self::DecompressionFailed("malformed field section"),
        }
    }
}

impl From<InvalidPrefix> for QpackError {
    fn from(e: InvalidPrefix) -> Self {
        match e {
            InvalidPrefix::NeedMore => Self::DecompressionFailed("truncated field section prefix"),
            _ => Self::DecompressionFailed("invalid field section prefix"),
        }
    }
}
