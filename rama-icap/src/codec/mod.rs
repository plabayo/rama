//! Borrowed ICAP wire decoders and fixed-buffer encoders.

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
    DEFAULT_MAX_HEAD_BYTES, DEFAULT_MAX_HEADERS, EncodeError, HeadParserConfig, HeadScanner,
    Header, HeaderFolding, HeaderSlot, HeaderValue, HeaderValueSegments, InvalidComposition,
    InvalidHeader, ParseError, ParseStatus, ParsedHeaders, RequestHead, RequestLine, ResponseHead,
    ResponseLine, encode_parsed_request_head, encode_parsed_response_head, encode_request_head,
    encode_response_head, parse_request_head, parse_request_head_with_config, parse_response_head,
    parse_response_head_with_config,
};
