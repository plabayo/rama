//! Bounded asynchronous ICAP framing over an arbitrary byte stream.

use core::fmt;
use std::io;

use rama_core::{
    bytes::{Buf as _, Bytes, BytesMut},
    io::Io,
};
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf,
};

use crate::{
    codec::{
        self, ChunkExtension, ChunkLineError, ChunkLineScanner, DEFAULT_MAX_CHUNK_LINE_BYTES,
        DEFAULT_MAX_HEADERS, HeadParserConfig, HeadScanner, HeaderSlot, ParseError, ParseStatus,
        ScanStatus, TrailerScanner,
    },
    message::{
        BuildError, EncapsulatedParts, Request, Response, TrailerBlock, header_value_has_token,
    },
    proto::{EncapsulatedSection, MethodKind, Preview, StatusCode, chunk_extension, header},
};

/// Default number of bytes reserved for each socket read.
pub const DEFAULT_READ_BUFFER_BYTES: usize = 8 * 1024;

/// Default maximum bytes in encapsulated HTTP header sections.
pub const DEFAULT_MAX_ENCAPSULATED_HEADER_BYTES: usize = 128 * 1024;

/// Bounds and parser policy for an ICAP connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionOptions {
    head: HeadParserConfig,
    max_headers: usize,
    max_chunk_line_bytes: usize,
    max_encapsulated_header_bytes: usize,
    read_buffer_bytes: usize,
}

impl ConnectionOptions {
    /// Construct strict, bounded connection options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            head: HeadParserConfig::new(),
            max_headers: DEFAULT_MAX_HEADERS,
            max_chunk_line_bytes: DEFAULT_MAX_CHUNK_LINE_BYTES,
            max_encapsulated_header_bytes: DEFAULT_MAX_ENCAPSULATED_HEADER_BYTES,
            read_buffer_bytes: DEFAULT_READ_BUFFER_BYTES,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the ICAP head and trailer parser policy.
        pub const fn head_parser(mut self, head: HeadParserConfig) -> Self {
            self.head = head;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum number of ICAP headers or HTTP trailers.
        pub const fn max_headers(mut self, max_headers: usize) -> Self {
            self.max_headers = max_headers;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum encoded chunk-size line length.
        pub const fn max_chunk_line_bytes(mut self, max_bytes: usize) -> Self {
            self.max_chunk_line_bytes = max_bytes;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum combined encapsulated HTTP head length.
        pub const fn max_encapsulated_header_bytes(
            mut self,
            max_bytes: usize,
        ) -> Self {
            self.max_encapsulated_header_bytes = max_bytes;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the target socket read-buffer increment.
        pub const fn read_buffer_bytes(mut self, bytes: usize) -> Self {
            self.read_buffer_bytes = bytes;
            self
        }
    }

    /// Return the ICAP head and trailer parser policy.
    #[must_use]
    pub const fn head_parser(self) -> HeadParserConfig {
        self.head
    }

    /// Return the maximum number of decoded header fields.
    #[must_use]
    pub const fn max_headers(self) -> usize {
        self.max_headers
    }

    /// Return the maximum encoded chunk-size line length.
    #[must_use]
    pub const fn max_chunk_line_bytes(self) -> usize {
        self.max_chunk_line_bytes
    }

    /// Return the encapsulated HTTP head bound.
    #[must_use]
    pub const fn max_encapsulated_header_bytes(self) -> usize {
        self.max_encapsulated_header_bytes
    }

    /// Return the target socket read-buffer increment.
    #[must_use]
    pub const fn read_buffer_bytes(self) -> usize {
        self.read_buffer_bytes
    }
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// The semantic end of an ICAP chunk stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyEnd {
    /// The complete encapsulated entity body was received.
    Complete,
    /// A Preview ended without `ieof` and awaits a server decision.
    Preview,
    /// A 206 response switches to the original body at this offset.
    PartialContent {
        /// Peer-supplied byte offset in the original HTTP entity body.
        ///
        /// A client can use its response verification metadata to determine
        /// whether this offset was checked against a known original length.
        use_original_body: u64,
    },
}

/// An asynchronous ICAP transaction error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The underlying byte stream failed.
    Io(io::Error),
    /// An ICAP head or trailer is malformed.
    Head(ParseError),
    /// An ICAP chunk line is malformed.
    ChunkLine(ChunkLineError),
    /// Owned message metadata is inconsistent.
    Message(BuildError),
    /// Framing is valid in isolation but invalid in this transaction.
    InvalidSequence(&'static str),
    /// The connection API was called in an invalid state.
    InvalidState(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("ICAP connection I/O error"),
            Self::Head(_) => f.write_str("invalid ICAP head or trailer"),
            Self::ChunkLine(_) => f.write_str("invalid ICAP chunk line"),
            Self::Message(_) => f.write_str("invalid ICAP message"),
            Self::InvalidSequence(message) | Self::InvalidState(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Head(error) => Some(error),
            Self::ChunkLine(error) => Some(error),
            Self::Message(error) => Some(error),
            Self::InvalidSequence(_) | Self::InvalidState(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ParseError> for Error {
    fn from(value: ParseError) -> Self {
        Self::Head(value)
    }
}

impl From<ChunkLineError> for Error {
    fn from(value: ChunkLineError) -> Self {
        Self::ChunkLine(value)
    }
}

impl From<BuildError> for Error {
    fn from(value: BuildError) -> Self {
        Self::Message(value)
    }
}

pub(crate) struct FramedIo<IO> {
    pub(crate) read: FramedRead<ReadHalf<IO>>,
    pub(crate) write: FramedWrite<WriteHalf<IO>>,
}

pub(crate) struct FramedRead<R> {
    io: R,
    buffer: BytesMut,
    header_slots: Vec<HeaderSlot>,
    options: ConnectionOptions,
    head_scanner: HeadScanner,
    head_scanned: usize,
    trailer_scanner: TrailerScanner,
    trailer_scanned: usize,
    chunk_line_scanner: ChunkLineScanner,
    chunk_line_scanned: usize,
    pending_response: Option<PendingResponseHead>,
}

struct PendingResponseHead {
    head: Bytes,
    method: MethodKind,
    status: StatusCode,
    sections: Option<SectionList>,
    close: bool,
}

pub(crate) struct FramedWrite<W> {
    io: W,
}

impl<IO> FramedIo<IO>
where
    IO: Io + Unpin,
{
    pub(crate) fn new(io: IO, options: ConnectionOptions) -> Self {
        let (read, write) = tokio::io::split(io);
        Self {
            read: FramedRead {
                io: read,
                buffer: BytesMut::with_capacity(options.read_buffer_bytes.max(1)),
                header_slots: vec![HeaderSlot::EMPTY; options.max_headers],
                options,
                head_scanner: HeadScanner::new(),
                head_scanned: 0,
                trailer_scanner: TrailerScanner::new(),
                trailer_scanned: 0,
                chunk_line_scanner: ChunkLineScanner::new(),
                chunk_line_scanned: 0,
                pending_response: None,
            },
            write: FramedWrite { io: write },
        }
    }

    pub(crate) fn into_parts(self) -> (IO, Bytes) {
        (
            self.read.io.unsplit(self.write.io),
            self.read.buffer.freeze(),
        )
    }

    pub(crate) const fn options(&self) -> &ConnectionOptions {
        &self.read.options
    }
}

impl<R> FramedRead<R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) async fn read_request(&mut self) -> Result<Option<Request>, Error> {
        let Some(framed_len) = self.read_head_frame(true, "ICAP request head").await? else {
            return Ok(None);
        };
        let ParseStatus::Complete(head, consumed) = codec::parse_request_head_with_config(
            &self.buffer[..framed_len],
            &mut self.header_slots,
            self.options.head,
        )?
        else {
            return Err(Error::InvalidSequence(
                "framed ICAP request head did not parse completely",
            ));
        };
        if consumed != framed_len {
            return Err(Error::InvalidSequence(
                "ICAP request parser disagreed with its frame boundary",
            ));
        }
        let method = head.line().method().kind();
        let preview = head.preview();
        let close = head.headers().any(|field| {
            field.name().eq_ignore_ascii_case(header::CONNECTION)
                && header_value_has_token(field.value(), b"close")
        });
        let allow_204 = head.headers().any(|field| {
            field.name().eq_ignore_ascii_case(header::ALLOW)
                && header_value_has_token(field.value(), b"204")
        });
        let allow_206 = head.headers().any(|field| {
            field.name().eq_ignore_ascii_case(header::ALLOW)
                && header_value_has_token(field.value(), b"206")
        });
        let sections = copy_sections(head.encapsulated());
        let head = self.buffer.split_to(consumed).freeze();
        let encapsulated = self.read_encapsulated_prefix(sections.as_ref()).await?;
        if preview.is_some() && encapsulated.as_ref().is_none_or(|parts| !parts.has_body()) {
            return Err(Error::InvalidSequence(
                "Preview requires an encapsulated entity body",
            ));
        }
        Ok(Some(Request::from_wire(
            head,
            method,
            preview,
            encapsulated,
            allow_204,
            allow_206,
            close,
        )))
    }

    pub(crate) async fn read_response(&mut self, method: MethodKind) -> Result<Response, Error> {
        if let Some(pending) = &self.pending_response
            && pending.method != method
        {
            return Err(Error::InvalidState(
                "pending ICAP response belongs to another request method",
            ));
        }
        if self.pending_response.is_none() {
            let framed_len = self
                .read_head_frame(false, "ICAP response head")
                .await?
                .ok_or_else(|| unexpected_eof("ICAP response head"))?;
            let ParseStatus::Complete(head, consumed) = codec::parse_response_head_with_config(
                method,
                &self.buffer[..framed_len],
                &mut self.header_slots,
                self.options.head,
            )?
            else {
                return Err(Error::InvalidSequence(
                    "framed ICAP response head did not parse completely",
                ));
            };
            if consumed != framed_len {
                return Err(Error::InvalidSequence(
                    "ICAP response parser disagreed with its frame boundary",
                ));
            }
            let status = head.line().status();
            let close = head.headers().any(|field| {
                field.name().eq_ignore_ascii_case(header::CONNECTION)
                    && header_value_has_token(field.value(), b"close")
            });
            let sections = copy_sections(head.encapsulated());
            let head = self.buffer.split_to(consumed).freeze();
            self.pending_response = Some(PendingResponseHead {
                head,
                method,
                status,
                sections,
                close,
            });
        }
        let sections = self
            .pending_response
            .as_ref()
            .and_then(|pending| pending.sections);
        let encapsulated = self.read_encapsulated_prefix(sections.as_ref()).await?;
        let pending = self.pending_response.take().ok_or(Error::InvalidState(
            "pending ICAP response disappeared while reading it",
        ))?;
        Ok(Response::from_wire(
            pending.head,
            pending.method,
            pending.status,
            encapsulated,
            pending.close,
        ))
    }

    async fn read_head_frame(
        &mut self,
        clean_eof: bool,
        context: &'static str,
    ) -> Result<Option<usize>, Error> {
        loop {
            let scanner = core::mem::take(&mut self.head_scanner);
            match scanner.scan(&self.buffer[self.head_scanned..], self.options.head)? {
                ScanStatus::Partial(scanner) => {
                    self.head_scanner = scanner;
                    self.head_scanned = self.buffer.len();
                    if self.head_scanned >= self.options.head.max_bytes() {
                        return Err(ParseError::HeadTooLarge.into());
                    }
                    if !self.read_more().await? {
                        return if clean_eof && self.buffer.is_empty() {
                            Ok(None)
                        } else {
                            Err(unexpected_eof(context).into())
                        };
                    }
                }
                ScanStatus::Complete(framed) => {
                    self.head_scanner = HeadScanner::new();
                    self.head_scanned = 0;
                    return Ok(Some(framed.consumed()));
                }
            }
        }
    }

    async fn read_encapsulated_prefix(
        &mut self,
        sections: Option<&SectionList>,
    ) -> Result<Option<EncapsulatedParts>, Error> {
        let Some(sections) = sections else {
            return Ok(None);
        };
        let body = sections
            .as_slice()
            .last()
            .copied()
            .ok_or(Error::InvalidSequence(
                "Encapsulated contains no terminal body section",
            ))?;
        let len = body.offset_usize().ok_or(Error::InvalidSequence(
            "encapsulated HTTP head offset exceeds this platform",
        ))?;
        if len > self.options.max_encapsulated_header_bytes {
            return Err(Error::InvalidSequence(
                "encapsulated HTTP heads exceed the configured limit",
            ));
        }
        self.ensure(len, "encapsulated HTTP heads").await?;
        let prefix = self.buffer.split_to(len).freeze();
        EncapsulatedParts::from_sections(sections.as_slice(), &prefix)
            .map(Some)
            .map_err(Into::into)
    }

    async fn read_more(&mut self) -> Result<bool, io::Error> {
        self.buffer.reserve(self.options.read_buffer_bytes.max(1));
        self.io
            .read_buf(&mut self.buffer)
            .await
            .map(|read| read != 0)
    }

    async fn ensure(&mut self, len: usize, context: &'static str) -> Result<(), Error> {
        while self.buffer.len() < len {
            if !self.read_more().await? {
                return Err(unexpected_eof(context).into());
            }
        }
        Ok(())
    }

    async fn read_chunk_line(&mut self) -> Result<(u64, bool, Option<u64>), Error> {
        loop {
            let scanner = core::mem::take(&mut self.chunk_line_scanner);
            match scanner.scan(
                &self.buffer[self.chunk_line_scanned..],
                self.options.max_chunk_line_bytes,
            )? {
                ScanStatus::Partial(scanner) => {
                    self.chunk_line_scanner = scanner;
                    self.chunk_line_scanned = self.buffer.len();
                    if self.chunk_line_scanned >= self.options.max_chunk_line_bytes {
                        return Err(ChunkLineError::LineTooLong.into());
                    }
                    if !self.read_more().await? {
                        return Err(unexpected_eof("ICAP chunk line").into());
                    }
                }
                ScanStatus::Complete(framed) => {
                    self.chunk_line_scanner = ChunkLineScanner::new();
                    self.chunk_line_scanned = 0;
                    let framed_len = framed.consumed();
                    let ParseStatus::Complete(line, consumed) = codec::parse_chunk_line_with_limit(
                        &self.buffer[..framed_len],
                        self.options.max_chunk_line_bytes,
                    )?
                    else {
                        return Err(Error::InvalidSequence(
                            "framed ICAP chunk line did not parse completely",
                        ));
                    };
                    if consumed != framed_len {
                        return Err(Error::InvalidSequence(
                            "ICAP chunk parser disagreed with its frame boundary",
                        ));
                    }
                    let result = (
                        line.size(),
                        line.is_ieof(),
                        line.use_original_body().map_err(ChunkLineError::from)?,
                    );
                    self.buffer.advance(consumed);
                    return Ok(result);
                }
            }
        }
    }

    async fn read_trailers(&mut self) -> Result<TrailerBlock, Error> {
        loop {
            let scanner = core::mem::take(&mut self.trailer_scanner);
            match scanner.scan(&self.buffer[self.trailer_scanned..], self.options.head)? {
                ScanStatus::Partial(scanner) => {
                    self.trailer_scanner = scanner;
                    self.trailer_scanned = self.buffer.len();
                    if self.trailer_scanned >= self.options.head.max_bytes() {
                        return Err(ParseError::HeadTooLarge.into());
                    }
                    if !self.read_more().await? {
                        return Err(unexpected_eof("HTTP trailer block").into());
                    }
                }
                ScanStatus::Complete(framed) => {
                    self.trailer_scanner = TrailerScanner::new();
                    self.trailer_scanned = 0;
                    let framed_len = framed.consumed();
                    let ParseStatus::Complete(_, consumed) = codec::parse_trailers_with_config(
                        &self.buffer[..framed_len],
                        &mut self.header_slots,
                        self.options.head,
                    )?
                    else {
                        return Err(Error::InvalidSequence(
                            "framed HTTP trailer block did not parse completely",
                        ));
                    };
                    if consumed != framed_len {
                        return Err(Error::InvalidSequence(
                            "HTTP trailer parser disagreed with its frame boundary",
                        ));
                    }
                    return Ok(TrailerBlock::from_validated(
                        self.buffer.split_to(consumed).freeze(),
                    ));
                }
            }
        }
    }
}

impl<W> FramedWrite<W>
where
    W: AsyncWrite + Unpin,
{
    pub(crate) async fn write_request_head(&mut self, request: &Request) -> Result<(), Error> {
        self.io
            .write_all(request.head_bytes())
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn write_request_prefix(&mut self, request: &Request) -> Result<(), Error> {
        self.write_prefix(request.encapsulated()).await
    }

    pub(crate) async fn write_response(&mut self, response: &Response) -> Result<(), Error> {
        self.io.write_all(response.head_bytes()).await?;
        self.write_prefix(response.encapsulated()).await
    }

    pub(crate) async fn write_continue(&mut self) -> Result<(), Error> {
        self.io.write_all(b"ICAP/1.0 100 Continue\r\n\r\n").await?;
        self.flush().await
    }

    async fn write_prefix(&mut self, parts: Option<&EncapsulatedParts>) -> Result<(), Error> {
        if let Some(parts) = parts {
            if let Some(value) = parts.request_header() {
                self.io.write_all(value).await?;
            }
            if let Some(value) = parts.response_header() {
                self.io.write_all(value).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn write_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        let mut line = [0; 32];
        let len = codec::encode_chunk_line(
            u64::try_from(data.len())
                .map_err(|_error| Error::InvalidSequence("ICAP data segment is too large"))?,
            &[],
            &mut line,
        )
        .map_err(BuildError::from)?;
        self.io.write_all(&line[..len]).await?;
        self.io.write_all(data).await?;
        self.io.write_all(b"\r\n").await?;
        Ok(())
    }

    pub(crate) async fn write_end(
        &mut self,
        terminal: Terminal,
        trailers: &TrailerBlock,
    ) -> Result<(), Error> {
        let mut line = [0; 96];
        let mut decimal = [0; 20];
        let extension = match terminal {
            Terminal::Complete => None,
            Terminal::PreviewEof => Some(
                ChunkExtension::new(chunk_extension::IEOF, None).map_err(ChunkLineError::from)?,
            ),
            Terminal::UseOriginalBody(offset) => {
                let value = encode_decimal(offset, &mut decimal);
                Some(
                    ChunkExtension::new(chunk_extension::USE_ORIGINAL_BODY, Some(value))
                        .map_err(ChunkLineError::from)?,
                )
            }
        };
        let extensions = extension.as_slice();
        let len = codec::encode_chunk_line(0, extensions, &mut line).map_err(BuildError::from)?;
        self.io.write_all(&line[..len]).await?;
        self.io.write_all(trailers.as_bytes()).await?;
        Ok(())
    }

    pub(crate) async fn flush(&mut self) -> Result<(), Error> {
        self.io.flush().await.map_err(Into::into)
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), Error> {
        self.io.shutdown().await.map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum BodyContext {
    Request,
    Preview(Preview),
    Continuation,
    Response {
        status: StatusCode,
        original_body_len: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug)]
enum ReadState {
    Line,
    Data(u64),
    DataEnd,
    Trailers {
        ieof: bool,
        use_original_body: Option<u64>,
    },
    End,
}

pub(crate) struct BodyReader {
    context: BodyContext,
    state: ReadState,
    end: Option<BodyEnd>,
    trailers: Option<TrailerBlock>,
    preview_bytes: u64,
    received_bytes: u64,
}

impl BodyReader {
    pub(crate) const fn new(context: BodyContext) -> Self {
        Self {
            context,
            state: ReadState::Line,
            end: None,
            trailers: None,
            preview_bytes: 0,
            received_bytes: 0,
        }
    }

    pub(crate) const fn with_received_bytes(context: BodyContext, received_bytes: u64) -> Self {
        Self {
            context,
            state: ReadState::Line,
            end: None,
            trailers: None,
            preview_bytes: 0,
            received_bytes,
        }
    }

    pub(crate) fn end(&self) -> Option<BodyEnd> {
        self.end
    }

    pub(crate) fn trailers(&self) -> Option<&TrailerBlock> {
        self.trailers.as_ref()
    }

    pub(crate) const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    pub(crate) async fn next_data<IO>(
        &mut self,
        framed: &mut FramedRead<IO>,
    ) -> Result<Option<Bytes>, Error>
    where
        IO: AsyncRead + Unpin,
    {
        loop {
            match self.state {
                ReadState::End => return Ok(None),
                ReadState::Data(mut remaining) => {
                    if framed.buffer.is_empty() && !framed.read_more().await? {
                        return Err(unexpected_eof("ICAP chunk data").into());
                    }
                    let available = u64::try_from(framed.buffer.len()).unwrap_or(u64::MAX);
                    let take = remaining.min(available);
                    let take = usize::try_from(take).map_err(|_error| {
                        Error::InvalidSequence("ICAP chunk segment exceeds this platform")
                    })?;
                    remaining -= u64::try_from(take).unwrap_or(0);
                    self.state = if remaining == 0 {
                        ReadState::DataEnd
                    } else {
                        ReadState::Data(remaining)
                    };
                    self.received_bytes = self
                        .received_bytes
                        .checked_add(u64::try_from(take).unwrap_or(0))
                        .ok_or(Error::InvalidSequence("ICAP body length overflowed"))?;
                    return Ok(Some(framed.buffer.split_to(take).freeze()));
                }
                ReadState::DataEnd => {
                    framed.ensure(2, "ICAP chunk data terminator").await?;
                    if &framed.buffer[..2] != b"\r\n" {
                        return Err(Error::InvalidSequence(
                            "ICAP chunk data lacks a CRLF terminator",
                        ));
                    }
                    framed.buffer.advance(2);
                    self.state = ReadState::Line;
                }
                ReadState::Trailers {
                    ieof,
                    use_original_body,
                } => {
                    let trailers = framed.read_trailers().await?;
                    let end = classify_end(self.context, ieof, use_original_body, &trailers)?;
                    self.end = Some(end);
                    self.trailers = Some(trailers);
                    self.state = ReadState::End;
                    return Ok(None);
                }
                ReadState::Line => {
                    let (size, ieof, use_original_body) = framed.read_chunk_line().await?;
                    if size != 0 {
                        if let BodyContext::Preview(limit) = self.context {
                            self.preview_bytes = self
                                .preview_bytes
                                .checked_add(size)
                                .ok_or(Error::InvalidSequence("ICAP Preview length overflowed"))?;
                            if self.preview_bytes > limit.as_u64() {
                                return Err(Error::InvalidSequence(
                                    "ICAP Preview exceeds its advertised limit",
                                ));
                            }
                        }
                        self.state = ReadState::Data(size);
                        continue;
                    }
                    self.state = ReadState::Trailers {
                        ieof,
                        use_original_body,
                    };
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Terminal {
    Complete,
    PreviewEof,
    UseOriginalBody(u64),
}

fn classify_end(
    context: BodyContext,
    ieof: bool,
    use_original_body: Option<u64>,
    trailers: &TrailerBlock,
) -> Result<BodyEnd, Error> {
    match context {
        BodyContext::Preview(_) => {
            if use_original_body.is_some() {
                return Err(Error::InvalidSequence(
                    "use-original-body is invalid in an ICAP request",
                ));
            }
            if ieof {
                Ok(BodyEnd::Complete)
            } else if trailers.is_empty() {
                Ok(BodyEnd::Preview)
            } else {
                Err(Error::InvalidSequence(
                    "an incomplete Preview cannot carry trailers",
                ))
            }
        }
        BodyContext::Request | BodyContext::Continuation => {
            if ieof || use_original_body.is_some() {
                Err(Error::InvalidSequence(
                    "reserved terminal extension is invalid here",
                ))
            } else {
                Ok(BodyEnd::Complete)
            }
        }
        BodyContext::Response {
            status,
            original_body_len,
        } => {
            if ieof {
                return Err(Error::InvalidSequence(
                    "ieof is invalid in an ICAP response",
                ));
            }
            match (status, use_original_body) {
                (StatusCode::PARTIAL_CONTENT, Some(offset)) => {
                    if original_body_len.is_some_and(|len| offset >= len) {
                        return Err(Error::InvalidSequence(
                            "use-original-body exceeds the original body",
                        ));
                    }
                    Ok(BodyEnd::PartialContent {
                        use_original_body: offset,
                    })
                }
                (_, Some(_)) => Err(Error::InvalidSequence(
                    "use-original-body requires a 206 response",
                )),
                (_, None) => Ok(BodyEnd::Complete),
            }
        }
    }
}

#[derive(Clone, Copy)]
struct SectionList {
    values: [EncapsulatedSection; 3],
    len: usize,
}

impl SectionList {
    fn as_slice(&self) -> &[EncapsulatedSection] {
        &self.values[..self.len]
    }
}

fn copy_sections(encapsulated: Option<codec::Encapsulated<'_>>) -> Option<SectionList> {
    encapsulated.map(|encapsulated| {
        let mut values = [
            EncapsulatedSection::new(crate::proto::EncapsulatedKind::NullBody, 0),
            EncapsulatedSection::new(crate::proto::EncapsulatedKind::NullBody, 0),
            EncapsulatedSection::new(crate::proto::EncapsulatedKind::NullBody, 0),
        ];
        let mut len = 0;
        for section in encapsulated {
            values[len] = section;
            len += 1;
        }
        SectionList { values, len }
    })
}

fn encode_decimal(mut value: u64, dst: &mut [u8; 20]) -> &[u8] {
    let mut start = dst.len();
    loop {
        start -= 1;
        dst[start] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        if value == 0 {
            return &dst[start..];
        }
    }
}

fn unexpected_eof(context: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("connection closed while reading {context}"),
    )
}
