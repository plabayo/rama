//! A Proxy Protocol Parser written in Rust.
//! Supports both text and binary versions of the header protocol.
//!
//! Forked from <https://github.com/misalcedo/ppp> (Apache-2.0 license),
//! a crate originally developed by Miguel D. Salcedo. The fork happened
//! on commit `28c5db92fda7337fc1ef36e6f19db96d511cd319`.

mod ip;

pub mod v1;
pub mod v2;

/// The canonical way to determine when a streamed header should be retried in a streaming context.
/// The protocol states that servers may choose to support partial headers or to close the connection if the header is not present all at once.
pub trait PartialResult {
    /// Tests whether this `Result` is successful or whether the error is terminal.
    /// A terminal error will not result in a success even with more bytes.
    /// Retrying with the same -- or more -- input will not change the result.
    fn is_complete(&self) -> bool {
        !self.is_incomplete()
    }

    /// Tests whether this `Result` is incomplete.
    /// An action that leads to an incomplete result may have a different result with more bytes.
    /// Retrying with the same input will not change the result.
    fn is_incomplete(&self) -> bool;
}

impl<T, E: PartialResult> PartialResult for Result<T, E> {
    fn is_incomplete(&self) -> bool {
        match self {
            Ok(_) => false,
            Err(error) => error.is_incomplete(),
        }
    }
}

impl PartialResult for v1::ParseError {
    fn is_incomplete(&self) -> bool {
        matches!(
            self,
            Self::Partial
                | Self::MissingPrefix
                | Self::MissingProtocol
                | Self::MissingSourceAddress
                | Self::MissingDestinationAddress
                | Self::MissingSourcePort
                | Self::MissingDestinationPort
                | Self::MissingNewLine
        )
    }
}

impl PartialResult for v1::BinaryParseError {
    fn is_incomplete(&self) -> bool {
        match self {
            Self::Parse(error) => error.is_incomplete(),
            Self::InvalidUtf8(_) => false,
        }
    }
}

impl PartialResult for v2::ParseError {
    fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete(..) | Self::Partial(..))
    }
}

/// An enumeration of the supported header version's parse results.
/// Useful for parsing either version 1 or version 2 of the PROXY protocol.
///
/// ## Examples
/// ```rust
/// use rama_haproxy::protocol::{HeaderResult, PartialResult, v1, v2};
///
/// let input = "PROXY UNKNOWN\r\n";
/// let header = HeaderResult::parse(input.as_bytes());
///
/// assert_eq!(header, Ok(v1::Header::new(input, v1::Addresses::Unknown)).into());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "this `HeaderResult` may contain a V1 or V2 `Err` variant, which should be handled"]
pub enum HeaderResult<'a> {
    /// Version 1 of the PROXY protocol header.
    V1(Result<v1::Header<'a>, v1::BinaryParseError>),
    /// Version 2 of the PROXY protocol header.
    V2(Result<v2::Header<'a>, v2::ParseError>),
}

impl<'a> From<Result<v1::Header<'a>, v1::BinaryParseError>> for HeaderResult<'a> {
    fn from(result: Result<v1::Header<'a>, v1::BinaryParseError>) -> Self {
        HeaderResult::V1(result)
    }
}

impl<'a> From<Result<v2::Header<'a>, v2::ParseError>> for HeaderResult<'a> {
    fn from(result: Result<v2::Header<'a>, v2::ParseError>) -> Self {
        HeaderResult::V2(result)
    }
}

impl PartialResult for HeaderResult<'_> {
    fn is_incomplete(&self) -> bool {
        match self {
            Self::V1(result) => result.is_incomplete(),
            Self::V2(result) => result.is_incomplete(),
        }
    }
}

impl<'a> HeaderResult<'a> {
    /// Parses a PROXY protocol version 2 `Header`.
    /// If the input is not a valid version 2 `Header`, attempts to parse a version 1 `Header`.
    pub fn parse(input: &'a [u8]) -> Self {
        let header = v2::Header::try_from(input);

        if header.is_complete() && header.is_err() {
            v1::Header::try_from(input).into()
        } else {
            header.into()
        }
    }
}
