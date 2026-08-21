//! Borrowed ICAP wire decoders and fixed-buffer encoders.

/// A completed incremental frame boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Framed {
    consumed: usize,
}

impl Framed {
    const fn new(consumed: usize) -> Self {
        Self { consumed }
    }

    /// Return the number of stream bytes through the frame boundary.
    #[must_use]
    pub const fn consumed(self) -> usize {
        self.consumed
    }
}

/// The result of incrementally scanning newly received stream bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanStatus<S> {
    /// More bytes are required; continue with the returned scanner.
    Partial(S),
    /// The frame boundary was found and the scanner was consumed.
    Complete(Framed),
}

mod chunk;
mod encapsulated;
mod head;

pub use chunk::{
    ChunkExtension, ChunkExtensionIter, ChunkExtensions, ChunkLine, ChunkLineError,
    ChunkLineScanner, DEFAULT_MAX_CHUNK_LINE_BYTES, InvalidChunkLine, encode_chunk_line,
    parse_chunk_line, parse_chunk_line_with_limit,
};
pub use encapsulated::{
    Encapsulated, EncapsulatedContext, EncapsulatedIter, encode_encapsulated, parse_encapsulated,
};
pub use head::{
    CompositionValidation, DEFAULT_MAX_HEAD_BYTES, DEFAULT_MAX_HEADERS, EncodeError,
    HeadParserConfig, HeadScanner, Header, HeaderFolding, HeaderSlot, HeaderValue,
    HeaderValueSegments, InvalidComposition, InvalidHeader, ParseError, ParseStatus, ParsedHeaders,
    RequestHead, RequestLine, ResponseHead, ResponseLine, ServiceTagSyntax, TrailerScanner,
    Trailers, encode_parsed_request_head, encode_parsed_response_head, encode_request_head,
    encode_response_head, parse_request_head, parse_request_head_with_config, parse_response_head,
    parse_response_head_with_config, parse_trailers, parse_trailers_with_config,
};

#[cfg(feature = "std")]
pub(crate) use head::{encode_request_head_iter, encode_response_head_iter};
