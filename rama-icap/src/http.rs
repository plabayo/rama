//! Typed HTTP integration for ICAP messages and streaming bodies.

use core::fmt;
use std::{collections::VecDeque, pin::Pin};

use rama_core::{
    Service as RamaService,
    bytes::{Bytes, BytesMut},
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
    futures::StreamExt as _,
    io::Io,
};
use rama_http_types::{
    Body, HeaderMap, Request as HttpRequest, Response as HttpResponse,
    body::{Frame, StreamingBody, util::BodyStream},
    proto::h1::head::{self, HeadError, HeadParser},
};

use crate::{
    client::{
        ClientConnection as RawClientConnection, ClientResponse as RawClientResponse,
        ClientTransaction, PreviewOutcome, SourceOutcome, WriteOutcome,
    },
    codec::{Header, ParseError as IcapParseError, RequestLine, ResponseLine},
    io::{BodyEnd, Error as TransactionError},
    message::{
        BuildError, EncapsulatedParts, Request as IcapRequest, Response as IcapResponse,
        TrailerBlock,
    },
    proto::{EncapsulatedKind, MethodKind, Preview, StatusCode},
    server::{IncomingRequest as RawIncomingRequest, OutgoingBody, OutgoingResponse},
};

/// Parsed HTTP heads and body role from an ICAP `Encapsulated` value.
#[derive(Debug)]
pub struct Encapsulated {
    request: Option<HttpRequest<()>>,
    response: Option<HttpResponse<()>>,
    body_kind: EncapsulatedKind,
}

impl Encapsulated {
    /// Parse the typed HTTP heads with the default bounded parser.
    pub fn parse(parts: &EncapsulatedParts) -> Result<Self, Error> {
        Self::parse_with(parts, &HeadParser::new())
    }

    /// Parse the typed HTTP heads with an explicit parser configuration.
    pub fn parse_with(parts: &EncapsulatedParts, parser: &HeadParser) -> Result<Self, Error> {
        Ok(Self {
            request: parts
                .request_header()
                .map(|head| parser.parse_request(head))
                .transpose()?,
            response: parts
                .response_header()
                .map(|head| parser.parse_response(head))
                .transpose()?,
            body_kind: parts.body_kind(),
        })
    }

    /// Encode an encapsulated HTTP request head.
    pub fn from_request<T>(
        request: &HttpRequest<T>,
        body_kind: EncapsulatedKind,
    ) -> Result<EncapsulatedParts, Error> {
        if !matches!(
            body_kind,
            EncapsulatedKind::RequestBody | EncapsulatedKind::NullBody
        ) {
            return Err(Error::invalid_body_kind());
        }
        Ok(EncapsulatedParts::new(
            Some(head::encode_request(request)?),
            None,
            body_kind,
        )?)
    }

    /// Encode an encapsulated HTTP response head.
    pub fn from_response<T>(
        response: &HttpResponse<T>,
        body_kind: EncapsulatedKind,
    ) -> Result<EncapsulatedParts, Error> {
        if !matches!(
            body_kind,
            EncapsulatedKind::ResponseBody | EncapsulatedKind::NullBody
        ) {
            return Err(Error::invalid_body_kind());
        }
        Ok(EncapsulatedParts::new(
            None,
            Some(head::encode_response(response)?),
            body_kind,
        )?)
    }

    /// Encode original request and response heads around a response body.
    pub fn from_request_response<R, S>(
        request: &HttpRequest<R>,
        response: &HttpResponse<S>,
        body_kind: EncapsulatedKind,
    ) -> Result<EncapsulatedParts, Error> {
        if !matches!(
            body_kind,
            EncapsulatedKind::ResponseBody | EncapsulatedKind::NullBody
        ) {
            return Err(Error::invalid_body_kind());
        }
        Ok(EncapsulatedParts::new(
            Some(head::encode_request(request)?),
            Some(head::encode_response(response)?),
            body_kind,
        )?)
    }

    /// Return the encapsulated HTTP request head, when present.
    #[must_use]
    pub const fn request(&self) -> Option<&HttpRequest<()>> {
        self.request.as_ref()
    }

    /// Return the encapsulated HTTP response head, when present.
    #[must_use]
    pub const fn response(&self) -> Option<&HttpResponse<()>> {
        self.response.as_ref()
    }

    /// Return which entity body follows the HTTP heads.
    #[must_use]
    pub const fn body_kind(&self) -> EncapsulatedKind {
        self.body_kind
    }

    /// Split the parsed HTTP metadata into its parts.
    pub fn into_parts(
        self,
    ) -> (
        Option<HttpRequest<()>>,
        Option<HttpResponse<()>>,
        EncapsulatedKind,
    ) {
        (self.request, self.response, self.body_kind)
    }

    fn with_base_extensions(self, base: &Extensions) -> Self {
        Self {
            request: self.request.map(|request| {
                let extensions = request.extensions().with_base(base);
                request.with_extensions(extensions)
            }),
            response: self.response.map(|response| {
                let extensions = response.extensions().with_base(base);
                response.with_extensions(extensions)
            }),
            body_kind: self.body_kind,
        }
    }
}

impl EncapsulatedParts {
    /// Parse the encapsulated HTTP heads with the default bounded parser.
    pub fn parse_http(&self) -> Result<Encapsulated, Error> {
        Encapsulated::parse(self)
    }

    /// Parse the encapsulated HTTP heads with explicit parser bounds.
    pub fn parse_http_with(&self, parser: &HeadParser) -> Result<Encapsulated, Error> {
        Encapsulated::parse_with(self, parser)
    }
}

/// An owned ICAP service request with typed HTTP heads and streaming body.
///
/// Pulling the body past an incomplete Preview boundary sends `100 Continue`.
/// Returning a response before doing so rejects the remainder of the Preview.
pub struct IncomingRequest {
    icap: IcapRequest,
    encapsulated: Option<Encapsulated>,
    body: Body,
    extensions: Extensions,
}

impl IncomingRequest {
    /// Convert the protocol service input without buffering its entity body.
    pub fn from_icap(request: RawIncomingRequest) -> Result<Self, Error> {
        Self::from_icap_with(request, &HeadParser::new())
    }

    /// Convert the protocol input with explicit HTTP head parser bounds.
    pub fn from_icap_with(request: RawIncomingRequest, parser: &HeadParser) -> Result<Self, Error> {
        let (icap, body, extensions) = request.into_parts();
        let encapsulated = icap
            .encapsulated()
            .map(|parts| Encapsulated::parse_with(parts, parser))
            .transpose()?
            .map(|parts| parts.with_base_extensions(&extensions));
        Ok(Self {
            icap,
            encapsulated,
            body: Body::from_frame_stream(body),
            extensions,
        })
    }

    /// Return the ICAP request metadata.
    #[must_use]
    pub const fn icap(&self) -> &IcapRequest {
        &self.icap
    }

    /// Return the typed encapsulated HTTP metadata, when present.
    #[must_use]
    pub const fn encapsulated(&self) -> Option<&Encapsulated> {
        self.encapsulated.as_ref()
    }

    /// Return the streaming encapsulated entity body.
    pub const fn body(&self) -> &Body {
        &self.body
    }

    /// Return the mutable streaming encapsulated entity body.
    pub const fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    /// Split the typed service request into its protocol parts.
    pub fn into_parts(self) -> (IcapRequest, Option<Encapsulated>, Body, Extensions) {
        (self.icap, self.encapsulated, self.body, self.extensions)
    }
}

impl ExtensionsRef for IncomingRequest {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl fmt::Debug for IncomingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncomingRequest")
            .field("icap", &self.icap)
            .field("encapsulated", &self.encapsulated)
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

impl RawIncomingRequest {
    /// Parse the encapsulated HTTP heads and retain its streaming body.
    pub fn into_http(self) -> Result<IncomingRequest, Error> {
        IncomingRequest::from_icap(self)
    }

    /// Parse HTTP heads using explicit bounds and retain the streaming body.
    pub fn into_http_with(self, parser: &HeadParser) -> Result<IncomingRequest, Error> {
        IncomingRequest::from_icap_with(self, parser)
    }
}

/// Adapter from the protocol server input to typed HTTP service input.
///
/// Use this as the inner service of [`crate::server::Server`] while keeping
/// ordinary Rama layers around the typed `Service<IncomingRequest>`.
#[derive(Clone, Debug)]
pub struct HttpService<S> {
    inner: S,
    parser: HeadParser,
}

impl<S> HttpService<S> {
    /// Wrap a typed HTTP adaptation service.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            parser: HeadParser::new(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the parser used for encapsulated HTTP heads.
        pub const fn parser(mut self, parser: HeadParser) -> Self {
            self.parser = parser;
            self
        }
    }

    rama_utils::macros::define_inner_service_accessors!();
}

impl<S> RamaService<RawIncomingRequest> for HttpService<S>
where
    S: RamaService<IncomingRequest, Output = OutgoingResponse, Error: Into<BoxError>>,
{
    type Output = OutgoingResponse;
    type Error = BoxError;

    async fn serve(&self, request: RawIncomingRequest) -> Result<Self::Output, Self::Error> {
        let request = IncomingRequest::from_icap_with(request, &self.parser)?;
        self.inner.serve(request).await.map_err(Into::into)
    }
}

enum OriginalHead {
    Request(HttpRequest<()>),
    Response(HttpResponse<()>),
}

impl OriginalHead {
    fn request(&self) -> Option<&HttpRequest<()>> {
        match self {
            Self::Request(request) => Some(request),
            Self::Response(_) => None,
        }
    }

    fn response(&self) -> Option<&HttpResponse<()>> {
        match self {
            Self::Request(_) => None,
            Self::Response(response) => Some(response),
        }
    }

    fn with_base_extensions(self, base: &Extensions) -> Self {
        match self {
            Self::Request(request) => {
                let extensions = request.extensions().with_base(base);
                Self::Request(request.with_extensions(extensions))
            }
            Self::Response(response) => {
                let extensions = response.extensions().with_base(base);
                Self::Response(response.with_extensions(extensions))
            }
        }
    }
}

/// A typed HTTP request prepared for a streaming ICAP client transaction.
///
/// Preview bytes are retained as cheap `Bytes`/header-map clones so a 204 or
/// 206 result can replay the original message. Advertising `Allow: 204`
/// outside Preview necessarily retains every streamed original frame until
/// the ICAP decision, as required by RFC 3507 section 4.6.
pub struct ClientRequest {
    icap: IcapRequest,
    original: OriginalHead,
    body: Body,
}

impl ClientRequest {
    /// Build a REQMOD request around one streaming HTTP request.
    pub fn reqmod<B>(
        line: RequestLine<'_>,
        headers: &[Header<'_>],
        request: HttpRequest<B>,
        preview: Option<Preview>,
    ) -> Result<Self, Error>
    where
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        if line.method().kind() != MethodKind::Reqmod {
            return Err(Error::invalid_method());
        }
        let (parts, body) = request.into_parts();
        let original_body_len = body.size_hint().exact();
        let body_kind = if body.is_end_stream() {
            EncapsulatedKind::NullBody
        } else {
            EncapsulatedKind::RequestBody
        };
        let original = HttpRequest::from_parts(parts, ());
        let encapsulated = Encapsulated::from_request(&original, body_kind)?;
        let mut icap = build_client_request(line, headers, encapsulated, preview)?;
        if body_kind != EncapsulatedKind::NullBody
            && let Some(len) = original_body_len
        {
            icap = icap.try_with_original_body_len(len)?;
        }
        Ok(Self {
            icap,
            original: OriginalHead::Request(original),
            body: Body::new(body),
        })
    }

    /// Build a RESPMOD request around original request and response heads.
    pub fn respmod<R, B>(
        line: RequestLine<'_>,
        headers: &[Header<'_>],
        request: &HttpRequest<R>,
        response: HttpResponse<B>,
        preview: Option<Preview>,
    ) -> Result<Self, Error>
    where
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        if line.method().kind() != MethodKind::Respmod {
            return Err(Error::invalid_method());
        }
        let (parts, body) = response.into_parts();
        let original_body_len = body.size_hint().exact();
        let body_kind = if body.is_end_stream() {
            EncapsulatedKind::NullBody
        } else {
            EncapsulatedKind::ResponseBody
        };
        let original = HttpResponse::from_parts(parts, ());
        let encapsulated = Encapsulated::from_request_response(request, &original, body_kind)?;
        let mut icap = build_client_request(line, headers, encapsulated, preview)?;
        if body_kind != EncapsulatedKind::NullBody
            && let Some(len) = original_body_len
        {
            icap = icap.try_with_original_body_len(len)?;
        }
        Ok(Self {
            icap,
            original: OriginalHead::Response(original),
            body: Body::new(body),
        })
    }

    /// Return the encoded ICAP request and encapsulated HTTP heads.
    #[must_use]
    pub const fn icap(&self) -> &IcapRequest {
        &self.icap
    }

    /// Return the streaming original HTTP entity body.
    pub const fn body(&self) -> &Body {
        &self.body
    }

    /// Return the original HTTP request head for REQMOD.
    #[must_use]
    pub fn original_request(&self) -> Option<&HttpRequest<()>> {
        self.original.request()
    }

    /// Return the original HTTP response head for RESPMOD.
    #[must_use]
    pub fn original_response(&self) -> Option<&HttpResponse<()>> {
        self.original.response()
    }

    fn into_parts(self) -> (IcapRequest, OriginalHead, Body) {
        (self.icap, self.original, self.body)
    }
}

impl fmt::Debug for ClientRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientRequest")
            .field("icap", &self.icap)
            .finish_non_exhaustive()
    }
}

impl<IO> RawClientConnection<IO>
where
    IO: Io + Unpin,
{
    /// Send a typed HTTP adaptation request with the default head parser.
    ///
    /// The HTTP entity body remains streaming. While its next frame is
    /// pending, the connection monitors for an early ICAP response as
    /// required by the ICAP errata. Cancelling this operation leaves the
    /// connection non-reusable.
    pub async fn send_http(
        &mut self,
        request: ClientRequest,
    ) -> Result<ClientResponse<'_, IO>, Error> {
        self.send_http_with(request, HeadParser::new()).await
    }

    /// Send a typed HTTP adaptation request with explicit parser bounds.
    pub async fn send_http_with(
        &mut self,
        request: ClientRequest,
        parser: HeadParser,
    ) -> Result<ClientResponse<'_, IO>, Error> {
        let driven = drive_client_request(self, request).await?;
        ClientResponse::from_icap(driven, parser)
    }
}

#[derive(Clone, Copy, Debug)]
enum ClientSendPhase {
    Preview { remaining: u64 },
    Body,
}

struct DrivenClientResponse<'a, IO> {
    response: RawClientResponse<'a, IO>,
    original_head: OriginalHead,
    original_body: OriginalBody,
}

struct OriginalBody {
    source: Pin<Box<BodyStream<Body>>>,
    buffered: VecDeque<Frame<Bytes>>,
    retain: bool,
}

impl OriginalBody {
    fn new(body: Body, retain: bool) -> Self {
        Self {
            source: Box::pin(BodyStream::new(body)),
            buffered: VecDeque::new(),
            retain,
        }
    }

    fn stop_retaining(&mut self) {
        self.retain = false;
        self.buffered.clear();
    }

    async fn next_source(&mut self) -> Result<Option<Frame<Bytes>>, Error> {
        let frame = self
            .source
            .as_mut()
            .next()
            .await
            .transpose()
            .map_err(Error::http_body)?;
        if self.retain
            && let Some(frame) = &frame
        {
            self.buffered.push_back(frame.clone());
        }
        Ok(frame)
    }

    async fn next_replay(
        &mut self,
        skip: &mut u64,
        require_octet: bool,
        selected_octet: &mut bool,
    ) -> Result<Option<Frame<Bytes>>, Error> {
        loop {
            let frame = if let Some(frame) = self.buffered.pop_front() {
                Some(frame)
            } else {
                self.source
                    .as_mut()
                    .next()
                    .await
                    .transpose()
                    .map_err(Error::http_body)?
            };
            let Some(frame) = frame else {
                validate_replay_offset(*skip, require_octet, *selected_octet)?;
                return Ok(None);
            };
            match frame.into_data() {
                Ok(mut data) => {
                    let discard = usize::try_from(*skip).unwrap_or(usize::MAX).min(data.len());
                    *skip -= u64::try_from(discard).unwrap_or(0);
                    if discard == data.len() {
                        continue;
                    }
                    data = data.slice(discard..);
                    *selected_octet = true;
                    return Ok(Some(Frame::data(data)));
                }
                Err(frame) => {
                    validate_replay_offset(*skip, require_octet, *selected_octet)?;
                    return Ok(Some(frame));
                }
            }
        }
    }
}

fn validate_replay_offset(
    remaining: u64,
    require_octet: bool,
    selected_octet: bool,
) -> Result<(), Error> {
    if remaining != 0 || (require_octet && !selected_octet) {
        Err(Error::invalid_sequence(
            "206 original-body offset does not select a source body octet",
        ))
    } else {
        Ok(())
    }
}

async fn drive_client_request<'a, IO>(
    connection: &'a mut RawClientConnection<IO>,
    request: ClientRequest,
) -> Result<DrivenClientResponse<'a, IO>, Error>
where
    IO: Io + Unpin,
{
    let (icap, original_head, body) = request.into_parts();
    let preview = icap.preview();
    let retain_original = preview.is_some() || icap.allows_204() || icap.allows_206();
    let retain_after_preview = icap.allows_204();
    let mut transaction = Some(connection.start(icap).await?);
    let mut original_body = OriginalBody::new(body, retain_original);
    let mut phase = preview.map_or(ClientSendPhase::Body, |limit| ClientSendPhase::Preview {
        remaining: limit.as_u64(),
    });
    let mut pending_data = None;
    let mut trailers = None;
    let mut saw_trailers = false;

    loop {
        if matches!(phase, ClientSendPhase::Preview { remaining: 0 }) {
            let outcome = take_transaction(&mut transaction)?
                .finish_preview(false)
                .await?;
            match outcome {
                PreviewOutcome::Continue(next) => {
                    transaction = Some(next);
                    phase = ClientSendPhase::Body;
                    if !retain_after_preview {
                        original_body.stop_retaining();
                    }
                }
                PreviewOutcome::Response(response) => {
                    return Ok(DrivenClientResponse {
                        response,
                        original_head,
                        original_body,
                    });
                }
            }
        }

        let frame = if let Some(data) = pending_data.take() {
            Some(Frame::data(data))
        } else {
            let outcome = transaction
                .as_mut()
                .ok_or_else(|| Error::invalid_sequence("ICAP client transaction disappeared"))?
                .next_source_or_response(original_body.next_source())
                .await?;
            match outcome {
                SourceOutcome::Item(frame) => frame?,
                SourceOutcome::ResponseAvailable => {
                    if matches!(phase, ClientSendPhase::Preview { .. }) {
                        let response =
                            finish_early_preview(take_transaction(&mut transaction)?).await?;
                        return Ok(DrivenClientResponse {
                            response,
                            original_head,
                            original_body,
                        });
                    }
                    let response = take_transaction(&mut transaction)?.abandon().await?;
                    return Ok(DrivenClientResponse {
                        response,
                        original_head,
                        original_body,
                    });
                }
            }
        };

        let Some(frame) = frame else {
            let empty_trailers = TrailerBlock::empty();
            let trailers = trailers.as_ref().unwrap_or(&empty_trailers);
            let transaction = take_transaction(&mut transaction)?;
            let response = match phase {
                ClientSendPhase::Preview { .. } => match transaction
                    .finish_preview_with_trailers(true, trailers)
                    .await?
                {
                    PreviewOutcome::Response(response) => response,
                    PreviewOutcome::Continue(_) => {
                        return Err(Error::invalid_sequence(
                            "ICAP server continued a complete HTTP body Preview",
                        ));
                    }
                },
                ClientSendPhase::Body => transaction.finish_with_trailers(trailers).await?,
            };
            return Ok(DrivenClientResponse {
                response,
                original_head,
                original_body,
            });
        };

        match frame.into_data() {
            Ok(mut data) => {
                if saw_trailers {
                    return Err(Error::invalid_frame(
                        "HTTP body produced data after trailers",
                    ));
                }
                if data.is_empty() {
                    continue;
                }

                let send = match &mut phase {
                    ClientSendPhase::Preview { remaining } => {
                        let take = usize::try_from(*remaining)
                            .unwrap_or(usize::MAX)
                            .min(data.len());
                        if take == 0 {
                            pending_data = Some(data);
                            let outcome = take_transaction(&mut transaction)?
                                .finish_preview(false)
                                .await?;
                            match outcome {
                                PreviewOutcome::Continue(next) => {
                                    transaction = Some(next);
                                    phase = ClientSendPhase::Body;
                                    if !retain_after_preview {
                                        original_body.stop_retaining();
                                    }
                                    continue;
                                }
                                PreviewOutcome::Response(response) => {
                                    return Ok(DrivenClientResponse {
                                        response,
                                        original_head,
                                        original_body,
                                    });
                                }
                            }
                        }
                        *remaining -= u64::try_from(take).unwrap_or(0);
                        if take < data.len() {
                            pending_data = Some(data.split_off(take));
                        }
                        data
                    }
                    ClientSendPhase::Body => data,
                };

                let outcome = transaction
                    .as_mut()
                    .ok_or_else(|| Error::invalid_sequence("ICAP client transaction disappeared"))?
                    .write_data(&send)
                    .await?;
                if outcome == WriteOutcome::ResponseAvailable {
                    if matches!(phase, ClientSendPhase::Preview { .. }) {
                        let response =
                            finish_early_preview(take_transaction(&mut transaction)?).await?;
                        return Ok(DrivenClientResponse {
                            response,
                            original_head,
                            original_body,
                        });
                    }
                    let response = take_transaction(&mut transaction)?.abandon().await?;
                    return Ok(DrivenClientResponse {
                        response,
                        original_head,
                        original_body,
                    });
                }

                if pending_data.is_some() {
                    let outcome = take_transaction(&mut transaction)?
                        .finish_preview(false)
                        .await?;
                    match outcome {
                        PreviewOutcome::Continue(next) => {
                            transaction = Some(next);
                            phase = ClientSendPhase::Body;
                            if !retain_after_preview {
                                original_body.stop_retaining();
                            }
                        }
                        PreviewOutcome::Response(response) => {
                            return Ok(DrivenClientResponse {
                                response,
                                original_head,
                                original_body,
                            });
                        }
                    }
                }
            }
            Err(frame) => {
                let fields = frame.into_trailers().map_err(|_frame| {
                    Error::invalid_frame("HTTP body produced an unsupported frame")
                })?;
                if saw_trailers {
                    return Err(Error::invalid_frame(
                        "HTTP body produced more than one trailer frame",
                    ));
                }
                trailers = Some(encode_http_trailers(&fields)?);
                saw_trailers = true;
            }
        }
    }
}

fn take_transaction<'a, IO>(
    transaction: &mut Option<ClientTransaction<'a, IO>>,
) -> Result<ClientTransaction<'a, IO>, Error> {
    transaction
        .take()
        .ok_or_else(|| Error::invalid_sequence("ICAP client transaction disappeared"))
}

async fn finish_early_preview<'a, IO>(
    transaction: ClientTransaction<'a, IO>,
) -> Result<RawClientResponse<'a, IO>, Error>
where
    IO: Io + Unpin,
{
    match transaction.finish_preview(false).await? {
        PreviewOutcome::Response(response) => Ok(response),
        PreviewOutcome::Continue(_) => Err(Error::invalid_sequence(
            "ICAP server continued after sending a final response",
        )),
    }
}

fn encode_http_trailers(fields: &HeaderMap) -> Result<TrailerBlock, Error> {
    let mut encoded = BytesMut::with_capacity(fields.len().saturating_mul(32).saturating_add(2));
    head::encode_header_fields(fields, &mut encoded);
    encoded.extend_from_slice(b"\r\n");
    Ok(TrailerBlock::from_bytes(encoded.freeze())?)
}

/// A typed, streaming response to an HTTP adaptation request.
///
/// Adapted HTTP heads retain zero-copy header-value slices from their ICAP
/// wire buffers. Entity data is exposed as ref-counted `Bytes` chunks. For a
/// negotiated 204 or 206 response, the stream transparently replays the
/// retained original body bytes required to produce the final HTTP message.
pub struct ClientResponse<'a, IO> {
    inner: RawClientResponse<'a, IO>,
    encapsulated: Option<Encapsulated>,
    original_head: OriginalHead,
    original_body: OriginalBody,
    parser: HeadParser,
    mode: ResponseBodyMode,
    replay_skip: u64,
    replay_requires_octet: bool,
    replay_selected_octet: bool,
    adapted_trailers: Option<HeaderMap>,
    output_trailers: Option<HeaderMap>,
    adapted_trailers_parsed: bool,
    trailers_emitted: bool,
    output_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseBodyMode {
    Adapted,
    Partial,
    Original,
}

impl<'a, IO> ClientResponse<'a, IO>
where
    IO: Io + Unpin,
{
    fn from_icap(driven: DrivenClientResponse<'a, IO>, parser: HeadParser) -> Result<Self, Error> {
        let DrivenClientResponse {
            response: inner,
            original_head,
            original_body,
        } = driven;
        let original_head = original_head.with_base_extensions(inner.extensions());
        let encapsulated = inner
            .response()
            .encapsulated()
            .map(|parts| Encapsulated::parse_with(parts, &parser))
            .transpose()?
            .map(|parts| {
                let request_base = original_head
                    .request()
                    .map(ExtensionsRef::extensions)
                    .unwrap_or_else(|| inner.extensions());
                let response_base = original_head
                    .response()
                    .map(ExtensionsRef::extensions)
                    .unwrap_or_else(|| inner.extensions());
                Encapsulated {
                    request: parts.request.map(|request| {
                        let extensions = request.extensions().with_base(request_base);
                        request.with_extensions(extensions)
                    }),
                    response: parts.response.map(|response| {
                        let extensions = response.extensions().with_base(response_base);
                        response.with_extensions(extensions)
                    }),
                    body_kind: parts.body_kind,
                }
            });
        let mode = match inner.response().status() {
            StatusCode::NO_MODIFICATION_NEEDED => ResponseBodyMode::Original,
            StatusCode::PARTIAL_CONTENT => ResponseBodyMode::Partial,
            _ => ResponseBodyMode::Adapted,
        };
        if matches!(mode, ResponseBodyMode::Original | ResponseBodyMode::Partial)
            && !original_body.retain
        {
            return Err(Error::invalid_sequence(
                "ICAP response requires unavailable original HTTP body data",
            ));
        }
        Ok(Self {
            inner,
            encapsulated,
            original_head,
            original_body,
            parser,
            mode,
            replay_skip: 0,
            replay_requires_octet: false,
            replay_selected_octet: false,
            adapted_trailers: None,
            output_trailers: None,
            adapted_trailers_parsed: false,
            trailers_emitted: false,
            output_complete: false,
        })
    }

    /// Return the ICAP response metadata.
    #[must_use]
    pub const fn icap(&self) -> &IcapResponse {
        self.inner.response()
    }

    /// Return the typed encapsulated HTTP metadata, when present.
    #[must_use]
    pub const fn encapsulated(&self) -> Option<&Encapsulated> {
        self.encapsulated.as_ref()
    }

    /// Return the original HTTP request head for a REQMOD transaction.
    #[must_use]
    pub fn original_request(&self) -> Option<&HttpRequest<()>> {
        self.original_head.request()
    }

    /// Return the original HTTP response head for a RESPMOD transaction.
    #[must_use]
    pub fn original_response(&self) -> Option<&HttpResponse<()>> {
        self.original_head.response()
    }

    /// Return the resulting HTTP request head for a REQMOD transaction.
    ///
    /// A 204 response returns the retained original head. Other successful
    /// adaptations return the encapsulated head supplied by the ICAP server.
    #[must_use]
    pub fn request(&self) -> Option<&HttpRequest<()>> {
        if self.inner.response().status() == StatusCode::NO_MODIFICATION_NEEDED {
            self.original_head.request()
        } else {
            self.encapsulated.as_ref().and_then(Encapsulated::request)
        }
    }

    /// Return the resulting HTTP response head for a RESPMOD transaction.
    #[must_use]
    pub fn response(&self) -> Option<&HttpResponse<()>> {
        if self.inner.response().status() == StatusCode::NO_MODIFICATION_NEEDED {
            self.original_head.response()
        } else {
            self.encapsulated.as_ref().and_then(Encapsulated::response)
        }
    }

    /// Read the next zero-copy data segment of the resulting HTTP body.
    ///
    /// Trailer frames are consumed and remain available through
    /// [`trailers`](Self::trailers). Use [`next_frame`](Self::next_frame) to
    /// receive trailers as a frame.
    pub async fn next_data(&mut self) -> Result<Option<Bytes>, Error> {
        let Some(frame) = self.next_frame().await? else {
            return Ok(None);
        };
        match frame.into_data() {
            Ok(data) => Ok(Some(data)),
            Err(_trailers) => Ok(None),
        }
    }

    /// Read the next data or trailer frame of the resulting HTTP body.
    ///
    /// This includes original-body replay for 204 and 206 responses.
    pub async fn next_frame(&mut self) -> Result<Option<Frame<Bytes>>, Error> {
        if self.output_complete {
            return Ok(None);
        }
        loop {
            match self.mode {
                ResponseBodyMode::Adapted => {
                    if let Some(data) = self.inner.next_data().await? {
                        return Ok(Some(Frame::data(data)));
                    }
                    self.parse_adapted_trailers()?;
                    self.output_trailers = self.adapted_trailers.clone();
                    return Ok(self.finish_output());
                }
                ResponseBodyMode::Partial => {
                    if let Some(data) = self.inner.next_data().await? {
                        return Ok(Some(Frame::data(data)));
                    }
                    self.parse_adapted_trailers()?;
                    match self.inner.body_end() {
                        Some(BodyEnd::PartialContent { use_original_body }) => {
                            self.replay_skip = use_original_body;
                            self.replay_requires_octet = true;
                            self.replay_selected_octet = false;
                            self.mode = ResponseBodyMode::Original;
                        }
                        Some(BodyEnd::Complete) => {
                            self.output_trailers = self.adapted_trailers.clone();
                            return Ok(self.finish_output());
                        }
                        _ => {
                            return Err(Error::invalid_sequence(
                                "206 response ended without a valid body terminal",
                            ));
                        }
                    }
                }
                ResponseBodyMode::Original => {
                    let frame = self
                        .original_body
                        .next_replay(
                            &mut self.replay_skip,
                            self.replay_requires_octet,
                            &mut self.replay_selected_octet,
                        )
                        .await?;
                    if let Some(frame) = frame {
                        match frame.into_data() {
                            Ok(data) => return Ok(Some(Frame::data(data))),
                            Err(frame) => {
                                let original = frame.into_trailers().map_err(|_frame| {
                                    Error::invalid_frame(
                                        "original HTTP body produced an unsupported frame",
                                    )
                                })?;
                                self.output_trailers =
                                    self.adapted_trailers.clone().or(Some(original));
                                return Ok(self.finish_output());
                            }
                        }
                    } else {
                        self.output_trailers = self.adapted_trailers.clone();
                        return Ok(self.finish_output());
                    }
                }
            }
        }
    }

    /// Return the terminal ICAP body state after the data stream completes.
    #[must_use]
    pub const fn body_end(&self) -> Option<BodyEnd> {
        self.inner.body_end()
    }

    /// Return trailers of the resulting HTTP body after it completes.
    #[must_use]
    pub const fn trailers(&self) -> Option<&HeaderMap> {
        self.output_trailers.as_ref()
    }

    /// Return original entity-body bytes sent in complete ICAP chunks.
    #[must_use]
    pub const fn original_body_bytes_sent(&self) -> u64 {
        self.inner.original_body_bytes_sent()
    }

    /// Return the exact original entity-body length, when known.
    #[must_use]
    pub const fn original_body_len(&self) -> Option<u64> {
        self.inner.original_body_len()
    }

    /// Return whether a 206 original-body offset was locally verified.
    #[must_use]
    pub const fn original_body_offset_is_verified(&self) -> Option<bool> {
        self.inner.original_body_offset_is_verified()
    }

    /// Drain and discard the resulting HTTP entity body.
    pub async fn drain(&mut self) -> Result<(), Error> {
        while self.next_frame().await?.is_some() {}
        Ok(())
    }

    /// Return the ICAP response after its body has completed.
    pub fn into_icap(self) -> Result<IcapResponse, Error> {
        if !self.output_complete {
            return Err(Error::invalid_sequence(
                "resulting HTTP body has not completed",
            ));
        }
        Ok(self.inner.into_response()?)
    }

    fn parse_adapted_trailers(&mut self) -> Result<(), Error> {
        if !self.adapted_trailers_parsed {
            self.adapted_trailers = self
                .inner
                .trailers()
                .filter(|trailers| !trailers.is_empty())
                .map(|trailers| self.parser.parse_fields(trailers.as_bytes()))
                .transpose()?;
            self.adapted_trailers_parsed = true;
        }
        Ok(())
    }

    fn finish_output(&mut self) -> Option<Frame<Bytes>> {
        if !self.trailers_emitted
            && let Some(trailers) = &self.output_trailers
        {
            self.trailers_emitted = true;
            self.output_complete = true;
            Some(Frame::trailers(trailers.clone()))
        } else {
            self.output_complete = true;
            None
        }
    }
}

impl<IO> ExtensionsRef for ClientResponse<'_, IO> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

impl<IO> fmt::Debug for ClientResponse<'_, IO>
where
    IO: Io + Unpin,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientResponse")
            .field("icap", &self.inner.response())
            .field("encapsulated", &self.encapsulated)
            .field("body_end", &self.inner.body_end())
            .finish_non_exhaustive()
    }
}

fn build_client_request(
    line: RequestLine<'_>,
    headers: &[Header<'_>],
    encapsulated: EncapsulatedParts,
    preview: Option<Preview>,
) -> Result<IcapRequest, Error> {
    Ok(if let Some(preview) = preview {
        IcapRequest::with_preview(line, headers, encapsulated, preview)?
    } else {
        IcapRequest::new(line, headers, Some(encapsulated))?
    })
}

impl OutgoingBody {
    /// Stream an HTTP body as ICAP data and trailer frames.
    pub fn from_http<B>(body: B) -> Self
    where
        B: StreamingBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError> + 'static,
    {
        Self::from_frames(
            BodyStream::new(body)
                .map(|result| result.map_err(Into::into).and_then(http_frame_to_icap)),
        )
    }
}

fn http_frame_to_icap(frame: Frame<Bytes>) -> Result<crate::server::BodyFrame, BoxError> {
    match frame.into_data() {
        Ok(data) => Ok(crate::server::BodyFrame::data(data)),
        Err(frame) => {
            let trailers = frame
                .into_trailers()
                .map_err(|_frame| BoxError::from_static_str("unsupported HTTP body frame"))?;
            let mut encoded =
                BytesMut::with_capacity(trailers.len().saturating_mul(32).saturating_add(2));
            head::encode_header_fields(&trailers, &mut encoded);
            encoded.extend_from_slice(b"\r\n");
            let trailers = TrailerBlock::from_bytes(encoded.freeze())?;
            Ok(crate::server::BodyFrame::trailers(trailers))
        }
    }
}

impl OutgoingResponse {
    /// Build a REQMOD response carrying an adapted HTTP request.
    pub fn from_http_request<B>(
        line: ResponseLine<'_>,
        headers: &[Header<'_>],
        request: HttpRequest<B>,
    ) -> Result<Self, Error>
    where
        B: StreamingBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError> + 'static,
    {
        let (parts, body) = request.into_parts();
        let request = HttpRequest::from_parts(parts, ());
        let body_kind = if body.is_end_stream() {
            EncapsulatedKind::NullBody
        } else {
            EncapsulatedKind::RequestBody
        };
        let encapsulated = Encapsulated::from_request(&request, body_kind)?;
        let response = IcapResponse::new(MethodKind::Reqmod, line, headers, Some(encapsulated))?;
        Ok(Self::new(response, OutgoingBody::from_http(body)))
    }

    /// Build a REQMOD or RESPMOD response carrying an HTTP response.
    pub fn from_http_response<B>(
        method: MethodKind,
        line: ResponseLine<'_>,
        headers: &[Header<'_>],
        response: HttpResponse<B>,
    ) -> Result<Self, Error>
    where
        B: StreamingBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError> + 'static,
    {
        if !matches!(method, MethodKind::Reqmod | MethodKind::Respmod) {
            return Err(Error::invalid_method());
        }
        let (parts, body) = response.into_parts();
        let response = HttpResponse::from_parts(parts, ());
        let body_kind = if body.is_end_stream() {
            EncapsulatedKind::NullBody
        } else {
            EncapsulatedKind::ResponseBody
        };
        let encapsulated = Encapsulated::from_response(&response, body_kind)?;
        let response = IcapResponse::new(method, line, headers, Some(encapsulated))?;
        Ok(Self::new(response, OutgoingBody::from_http(body)))
    }
}

/// Typed ICAP/HTTP adaptation failure.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<BoxError>,
}

impl Error {
    const fn invalid_method() -> Self {
        Self {
            kind: ErrorKind::InvalidMethod,
            source: None,
        }
    }

    const fn invalid_body_kind() -> Self {
        Self {
            kind: ErrorKind::InvalidBodyKind,
            source: None,
        }
    }

    fn http_body(source: BoxError) -> Self {
        Self {
            kind: ErrorKind::HttpBody,
            source: Some(source),
        }
    }

    const fn invalid_frame(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::InvalidFrame(message),
            source: None,
        }
    }

    const fn invalid_sequence(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::InvalidSequence(message),
            source: None,
        }
    }

    /// Return the broad source category.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ErrorKind::HttpHead => "invalid encapsulated HTTP head",
            ErrorKind::HttpBody => "encapsulated HTTP body failed",
            ErrorKind::IcapMessage => "invalid ICAP message metadata",
            ErrorKind::IcapTransaction => "ICAP transaction failed",
            ErrorKind::InvalidMethod => "invalid ICAP method for HTTP adaptation",
            ErrorKind::InvalidBodyKind => "invalid ICAP body kind for HTTP message",
            ErrorKind::InvalidFrame(message) | ErrorKind::InvalidSequence(message) => message,
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

impl From<HeadError> for Error {
    fn from(error: HeadError) -> Self {
        Self {
            kind: ErrorKind::HttpHead,
            source: Some(error.into()),
        }
    }
}

impl From<BuildError> for Error {
    fn from(error: BuildError) -> Self {
        Self {
            kind: ErrorKind::IcapMessage,
            source: Some(error.into()),
        }
    }
}

impl From<IcapParseError> for Error {
    fn from(error: IcapParseError) -> Self {
        Self {
            kind: ErrorKind::IcapMessage,
            source: Some(error.into()),
        }
    }
}

impl From<TransactionError> for Error {
    fn from(error: TransactionError) -> Self {
        Self {
            kind: ErrorKind::IcapTransaction,
            source: Some(error.into()),
        }
    }
}

/// Classification for typed ICAP/HTTP adaptation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An encapsulated HTTP head was malformed.
    HttpHead,
    /// The streaming HTTP body returned an error.
    HttpBody,
    /// The resulting ICAP metadata was invalid.
    IcapMessage,
    /// The underlying ICAP transaction failed.
    IcapTransaction,
    /// The ICAP method cannot carry the requested HTTP message.
    InvalidMethod,
    /// The encapsulated body role does not match the HTTP message.
    InvalidBodyKind,
    /// The HTTP body produced an invalid frame sequence.
    InvalidFrame(&'static str),
    /// The peer produced an invalid HTTP/ICAP sequence.
    InvalidSequence(&'static str),
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use crate::{
        codec::{HeaderSlot, ResponseLine},
        proto::{Method, StatusCode},
    };
    use rama_core::{bytes::Bytes, extensions::Extension, futures::stream};

    #[derive(Debug, Extension)]
    struct ConnectionMarker;

    #[test]
    fn typed_heads_round_trip_without_copying_values() {
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/scan")
            .header("Host", "example.test")
            .header("X-Test", "value")
            .body(())
            .unwrap();
        let parts = Encapsulated::from_request(&request, EncapsulatedKind::RequestBody).unwrap();
        let wire = parts.request_header().unwrap().clone();
        let parsed = Encapsulated::parse(&parts).unwrap();
        let value = parsed.request().unwrap().headers()["x-test"].as_bytes();

        assert_eq!(parsed.body_kind(), EncapsulatedKind::RequestBody);
        assert!(value.as_ptr() as usize >= wire.as_ptr() as usize);
        assert!((value.as_ptr() as usize) < wire.as_ptr() as usize + wire.len());
    }

    #[tokio::test]
    async fn outgoing_http_body_preserves_data_and_trailers() {
        let mut trailers = rama_http_types::HeaderMap::new();
        trailers.insert("x-end", "yes".parse().unwrap());
        let body = rama_http_types::Body::from_frame_stream(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"adapted"))),
            Ok(Frame::trailers(trailers)),
        ]));
        let mut body = OutgoingBody::from_http(body);

        assert!(matches!(
            body.next().await.unwrap().unwrap(),
            crate::server::BodyFrame::Data(data) if data == "adapted"
        ));
        let crate::server::BodyFrame::Trailers(trailers) = body.next().await.unwrap().unwrap()
        else {
            panic!("expected trailers");
        };
        let fields = HeadParser::new().parse_fields(trailers.as_bytes()).unwrap();
        assert_eq!(fields["x-end"], "yes");
    }

    #[test]
    fn client_reqmod_builds_typed_encapsulation() {
        let line = RequestLine::new(Method::Reqmod, "icap://icap.test/request").unwrap();
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/upload")
            .header("Host", "example.test")
            .body(Body::from("body"))
            .unwrap();
        let request = ClientRequest::reqmod(line, &[], request, Some(Preview::new(4))).unwrap();

        assert_eq!(request.icap().method(), MethodKind::Reqmod);
        assert_eq!(request.icap().preview(), Some(Preview::new(4)));
        assert_eq!(request.icap().original_body_len(), Some(4));
        let parts = request.icap().encapsulated().unwrap();
        assert_eq!(parts.body_kind(), EncapsulatedKind::RequestBody);
        assert_eq!(
            Encapsulated::parse(parts)
                .unwrap()
                .request()
                .unwrap()
                .uri()
                .as_str(),
            "/upload",
        );
    }

    #[test]
    fn typed_client_represents_an_empty_http_body_as_null_body() {
        let line = RequestLine::new(Method::Reqmod, "icap://icap.test/request").unwrap();
        let request = HttpRequest::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let request = ClientRequest::reqmod(line, &[], request, None).unwrap();

        let parts = request.icap().encapsulated().unwrap();
        assert_eq!(parts.body_kind(), EncapsulatedKind::NullBody);
        assert_eq!(request.icap().original_body_len(), None);
    }

    #[test]
    fn outgoing_response_builds_http_prefix() {
        let istag = Header::new("ISTag", b"\"rama-test\"").unwrap();
        let response = HttpResponse::builder()
            .status(201)
            .header("X-Adapted", "yes")
            .body(Body::from("adapted"))
            .unwrap();
        let outgoing = OutgoingResponse::from_http_response(
            MethodKind::Respmod,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &[istag],
            response,
        )
        .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 4];
        let head = outgoing.response().parse_head(&mut slots).unwrap();

        assert_eq!(head.line().status(), StatusCode::OK);
        let parsed = Encapsulated::parse(outgoing.response().encapsulated().unwrap()).unwrap();
        assert_eq!(parsed.response().unwrap().status().as_u16(), 201);
        assert_eq!(parsed.response().unwrap().headers()["x-adapted"], "yes");
    }

    #[test]
    fn parsed_head_extensions_layer_over_connection() {
        let base = Extensions::new();
        base.insert(ConnectionMarker);
        let parts = EncapsulatedParts::new(
            Some(Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n")),
            None,
            EncapsulatedKind::NullBody,
        )
        .unwrap();
        let parsed = Encapsulated::parse(&parts)
            .unwrap()
            .with_base_extensions(&base);

        assert!(
            parsed
                .request()
                .unwrap()
                .extensions()
                .contains::<ConnectionMarker>()
        );
    }
}
