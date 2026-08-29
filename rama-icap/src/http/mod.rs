//! Typed HTTP integration for ICAP messages and streaming bodies.

use core::{fmt, future::poll_fn, pin::Pin};
use std::collections::VecDeque;

use rama_core::{
    Service as RamaService,
    bytes::{Bytes, BytesMut},
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
    futures::{StreamExt as _, stream},
    io::Io,
};
use rama_http_types::{
    Body, HeaderMap, Request as HttpRequest, Response as HttpResponse,
    body::{Frame, StreamingBody, util::BodyStream},
    header::HeaderName,
    proto::h1::head::{self, HeadError, HeadParser},
};
use rama_net::uri::Uri;

use crate::{
    client::{
        ClientConnection as RawClientConnection, ClientResponse as RawClientResponse,
        ClientResponseState as RawClientResponseState, ClientTransaction, PreviewOutcome,
        SourceOutcome, WriteOutcome,
    },
    codec::{Header, ParseError as IcapParseError, RequestLine, RequestLineSource, ResponseLine},
    io::{BodyEnd, Error as TransactionError},
    message::{
        BuildError, EncapsulatedParts, Request as IcapRequest, Response as IcapResponse,
        TrailerBlock,
    },
    proto::{EncapsulatedKind, Method, MethodKind, Preview, StatusCode},
    server::{IncomingRequest as RawIncomingRequest, OutgoingBody, OutgoingResponse},
};

use self::headers::{
    ForwardedIcapHeader, connection_nominated_headers, response_proxy_headers,
    sanitize_http_headers_with_nominated, validate_http_trailers,
};

mod headers;
pub mod layer;
mod server;
pub use server::UnchangedRequest;

/// Default maximum body and trailer bytes retained for ICAP replay.
pub const DEFAULT_MAX_REPLAY_BYTES: usize = rama_utils::octets::mib(8);

/// Default maximum frames retained for ICAP replay.
pub const DEFAULT_MAX_REPLAY_FRAMES: usize = 1024;

/// Bounds for original HTTP frames retained for 204/206 replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayLimits {
    max_bytes: usize,
    max_frames: usize,
}

impl ReplayLimits {
    /// Construct the default finite in-memory replay bounds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_REPLAY_BYTES,
            max_frames: DEFAULT_MAX_REPLAY_FRAMES,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the aggregate retained data and trailer byte limit.
        pub const fn max_bytes(mut self, max_bytes: usize) -> Self {
            self.max_bytes = max_bytes;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the retained frame-count limit.
        pub const fn max_frames(mut self, max_frames: usize) -> Self {
            self.max_frames = max_frames;
            self
        }
    }

    /// Return the aggregate retained byte limit.
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Return the retained frame-count limit.
    #[must_use]
    pub const fn max_frames(&self) -> usize {
        self.max_frames
    }
}

impl Default for ReplayLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed HTTP heads and body role from an ICAP `Encapsulated` value.
#[derive(Debug)]
pub struct Encapsulated {
    request: Option<HttpRequest<()>>,
    response: Option<HttpResponse<()>>,
    body_kind: EncapsulatedKind,
}

/// Owned components of parsed encapsulated HTTP metadata.
#[non_exhaustive]
#[derive(Debug)]
pub struct ParsedEncapsulatedParts {
    /// Encapsulated HTTP request head, when present.
    pub request: Option<HttpRequest<()>>,
    /// Encapsulated HTTP response head, when present.
    pub response: Option<HttpResponse<()>>,
    /// Kind of entity body following the HTTP heads.
    pub body_kind: EncapsulatedKind,
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
    ///
    /// Connection-specific fields are omitted as required by ICAP. If the
    /// head contains HTTP proxy credentials, a complete ICAP message must
    /// carry them as ICAP headers instead.
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
        let (request, _promoted, _trailer_forbidden) = prepare_request_head(request);
        Self::from_prepared_request(&request, body_kind)
    }

    /// Encode an encapsulated HTTP response head.
    ///
    /// Connection-specific fields are omitted as required by ICAP. If the
    /// head contains an HTTP proxy challenge, a complete ICAP message must
    /// carry it as an ICAP header instead.
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
        let (response, _promoted, _trailer_forbidden) = prepare_response_head(response);
        Self::from_prepared_response(&response, body_kind)
    }

    /// Encode original request and response heads around a response body.
    ///
    /// Connection-specific fields are omitted as required by ICAP. If the
    /// request contains HTTP proxy credentials or the response contains a
    /// proxy challenge, a complete ICAP message must carry them as ICAP
    /// headers instead. This helper returns only the encapsulated message and
    /// therefore does not preserve those fields itself.
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
        let (request, _request_promoted, _request_trailer_forbidden) =
            prepare_request_head(request);
        let (response, _response_promoted, _response_trailer_forbidden) =
            prepare_response_head(response);
        Self::from_prepared_request_response(&request, &response, body_kind)
    }

    fn from_prepared_request<T>(
        request: &HttpRequest<T>,
        body_kind: EncapsulatedKind,
    ) -> Result<EncapsulatedParts, Error> {
        Ok(EncapsulatedParts::new(
            Some(head::encode_request(request)?),
            None,
            body_kind,
        )?)
    }

    fn from_prepared_response<T>(
        response: &HttpResponse<T>,
        body_kind: EncapsulatedKind,
    ) -> Result<EncapsulatedParts, Error> {
        Ok(EncapsulatedParts::new(
            None,
            Some(head::encode_response(response)?),
            body_kind,
        )?)
    }

    fn from_prepared_request_response<R, S>(
        request: &HttpRequest<R>,
        response: &HttpResponse<S>,
        body_kind: EncapsulatedKind,
    ) -> Result<EncapsulatedParts, Error> {
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

    /// Return the mutable encapsulated HTTP request head, when present.
    pub const fn request_mut(&mut self) -> Option<&mut HttpRequest<()>> {
        self.request.as_mut()
    }

    /// Return the encapsulated HTTP response head, when present.
    #[must_use]
    pub const fn response(&self) -> Option<&HttpResponse<()>> {
        self.response.as_ref()
    }

    /// Return the mutable encapsulated HTTP response head, when present.
    pub const fn response_mut(&mut self) -> Option<&mut HttpResponse<()>> {
        self.response.as_mut()
    }

    /// Return which entity body follows the HTTP heads.
    #[must_use]
    pub const fn body_kind(&self) -> EncapsulatedKind {
        self.body_kind
    }

    /// Split the parsed HTTP metadata into its parts.
    pub fn into_parts(self) -> ParsedEncapsulatedParts {
        ParsedEncapsulatedParts {
            request: self.request,
            response: self.response,
            body_kind: self.body_kind,
        }
    }

    fn inherit_base_extensions(self, base: &Extensions) -> Self {
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

    fn inherit_original_context(self, original: &OriginalHead) -> Self {
        let empty = Extensions::new();
        let request_version = original.request().map(HttpRequest::version);
        let response_version = original
            .response()
            .map(HttpResponse::version)
            .or(request_version);
        let request_base = original
            .request()
            .map(ExtensionsRef::extensions)
            .unwrap_or(&empty);
        let response_base = original
            .response()
            .map(ExtensionsRef::extensions)
            .or_else(|| original.request().map(ExtensionsRef::extensions))
            .unwrap_or(&empty);

        Self {
            request: self.request.map(|mut request| {
                if let Some(version) = request_version {
                    *request.version_mut() = version;
                }
                let extensions = request.extensions().with_base(request_base);
                request.with_extensions(extensions)
            }),
            response: self.response.map(|mut response| {
                if let Some(version) = response_version {
                    *response.version_mut() = version;
                }
                let extensions = response.extensions().with_base(response_base);
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
    encapsulated_exposed_mutably: bool,
    body_exposed_mutably: bool,
}

/// Owned components of a typed ICAP service request.
#[non_exhaustive]
#[derive(Debug)]
pub struct IncomingRequestParts {
    /// ICAP request metadata.
    pub icap: IcapRequest,
    /// Parsed encapsulated HTTP metadata, when present.
    pub encapsulated: Option<Encapsulated>,
    /// Rama context associated with the request.
    pub extensions: Extensions,
}

impl IncomingRequest {
    /// Convert the protocol service input without buffering its entity body.
    pub fn from_icap(request: RawIncomingRequest) -> Result<Self, Error> {
        Self::from_icap_with(request, &HeadParser::new())
    }

    /// Convert the protocol input with explicit HTTP head parser bounds.
    pub fn from_icap_with(request: RawIncomingRequest, parser: &HeadParser) -> Result<Self, Error> {
        let (parts, body) = request.into_parts();
        let crate::server::IncomingRequestParts {
            request: icap,
            extensions,
        } = parts;
        let encapsulated = icap
            .encapsulated()
            .map(|parts| Encapsulated::parse_with(parts, parser))
            .transpose()?
            .map(|parts| parts.inherit_base_extensions(&extensions));
        Ok(Self {
            icap,
            encapsulated,
            body: Body::from_frame_stream(body),
            extensions,
            encapsulated_exposed_mutably: false,
            body_exposed_mutably: false,
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

    /// Return the mutable typed HTTP metadata, when present.
    ///
    /// This conservatively makes a later streaming unchanged echo unavailable,
    /// even when the caller only reads through the returned reference. Use
    /// [`Self::encapsulated`] for read-only inspection.
    pub fn encapsulated_mut(&mut self) -> Option<&mut Encapsulated> {
        self.encapsulated_exposed_mutably = true;
        self.encapsulated.as_mut()
    }

    /// Return the streaming encapsulated entity body.
    pub const fn body(&self) -> &Body {
        &self.body
    }

    /// Return the mutable streaming encapsulated entity body.
    ///
    /// This conservatively records the body as exposed because polling through
    /// the returned handle may consume bytes. A later [`Self::try_into_unchanged`]
    /// can then neither use Preview's 204 shortcut nor stream an unchanged
    /// body echo; an independently negotiated outside-Preview 204 remains
    /// available. Use [`Self::body`] for read-only inspection.
    pub fn body_mut(&mut self) -> &mut Body {
        self.body_exposed_mutably = true;
        &mut self.body
    }

    /// Turn a REQMOD service input into its streaming HTTP request.
    pub fn into_request(self) -> Result<HttpRequest<Body>, Error> {
        if self.icap.method() != MethodKind::Reqmod {
            return Err(Error::invalid_method());
        }
        let encapsulated = self
            .encapsulated
            .ok_or_else(|| Error::invalid_sequence("REQMOD request has no HTTP metadata"))?;
        if !matches!(
            encapsulated.body_kind,
            EncapsulatedKind::RequestBody | EncapsulatedKind::NullBody
        ) {
            return Err(Error::invalid_body_kind());
        }
        let request = encapsulated
            .request
            .ok_or_else(|| Error::invalid_sequence("REQMOD request has no HTTP request"))?;
        Ok(request.map(|()| self.body))
    }

    /// Turn a RESPMOD service input into its streaming HTTP response.
    pub fn into_response(self) -> Result<HttpResponse<Body>, Error> {
        if self.icap.method() != MethodKind::Respmod {
            return Err(Error::invalid_method());
        }
        let encapsulated = self
            .encapsulated
            .ok_or_else(|| Error::invalid_sequence("RESPMOD request has no HTTP metadata"))?;
        if !matches!(
            encapsulated.body_kind,
            EncapsulatedKind::ResponseBody | EncapsulatedKind::NullBody
        ) {
            return Err(Error::invalid_body_kind());
        }
        let response = encapsulated
            .response
            .ok_or_else(|| Error::invalid_sequence("RESPMOD request has no HTTP response"))?;
        Ok(response.map(|()| self.body))
    }

    /// Split the typed service request into named metadata and its body.
    pub fn into_parts(self) -> (IncomingRequestParts, Body) {
        (
            IncomingRequestParts {
                icap: self.icap,
                encapsulated: self.encapsulated,
                extensions: self.extensions,
            },
            self.body,
        )
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
}

/// A typed HTTP request prepared for a streaming ICAP client transaction.
///
/// Preview bytes are retained as cheap `Bytes`/header-map clones so a 204 or
/// 206 result can replay the original message. Advertising `Allow: 204`
/// outside Preview retains streamed original frames until the ICAP decision,
/// within finite configurable [`ReplayLimits`].
pub struct ClientRequest {
    icap: IcapRequest,
    original: OriginalHead,
    body: Body,
    trailer_forbidden: Vec<HeaderName>,
    replay_limits: ReplayLimits,
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
        Self::reqmod_with_line(line.into(), headers, request, preview)
    }

    pub(crate) fn reqmod_for_uri<B>(
        uri: &Uri,
        headers: &[Header<'_>],
        request: HttpRequest<B>,
        preview: Option<Preview>,
    ) -> Result<Self, Error>
    where
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        Self::reqmod_with_line(
            RequestLineSource::prepared(Method::Reqmod, uri),
            headers,
            request,
            preview,
        )
    }

    fn reqmod_with_line<B>(
        line: RequestLineSource<'_>,
        headers: &[Header<'_>],
        request: HttpRequest<B>,
        preview: Option<Preview>,
    ) -> Result<Self, Error>
    where
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        let (parts, body) = request.into_parts();
        let original_body_len = body.size_hint().exact();
        let body_kind = if body.is_end_stream() {
            EncapsulatedKind::NullBody
        } else {
            EncapsulatedKind::RequestBody
        };
        let original = HttpRequest::from_parts(parts, ());
        let (prepared, promoted, trailer_forbidden) = prepare_request_head(&original);
        let encapsulated = Encapsulated::from_prepared_request(&prepared, body_kind)?;
        let headers = with_promoted_headers(headers, &promoted)?;
        let mut icap = build_client_request(line, &headers, encapsulated, preview)?;
        if body_kind != EncapsulatedKind::NullBody
            && let Some(len) = original_body_len
        {
            icap = icap.try_with_original_body_len(len)?;
        }
        Ok(Self {
            icap,
            original: OriginalHead::Request(original),
            body: Body::new(body),
            trailer_forbidden,
            replay_limits: ReplayLimits::new(),
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
        Self::respmod_with_line(line.into(), headers, request, response, preview)
    }

    pub(crate) fn respmod_for_uri<R, B>(
        uri: &Uri,
        headers: &[Header<'_>],
        request: &HttpRequest<R>,
        response: HttpResponse<B>,
        preview: Option<Preview>,
    ) -> Result<Self, Error>
    where
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        Self::respmod_with_line(
            RequestLineSource::prepared(Method::Respmod, uri),
            headers,
            request,
            response,
            preview,
        )
    }

    fn respmod_with_line<R, B>(
        line: RequestLineSource<'_>,
        headers: &[Header<'_>],
        request: &HttpRequest<R>,
        response: HttpResponse<B>,
        preview: Option<Preview>,
    ) -> Result<Self, Error>
    where
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        let (parts, body) = response.into_parts();
        let original_body_len = body.size_hint().exact();
        let body_kind = if body.is_end_stream() {
            EncapsulatedKind::NullBody
        } else {
            EncapsulatedKind::ResponseBody
        };
        let original = HttpResponse::from_parts(parts, ());
        let (prepared_request, request_promoted, _request_trailer_forbidden) =
            prepare_request_head(request);
        let (prepared_response, response_promoted, trailer_forbidden) =
            prepare_response_head(&original);
        let encapsulated = Encapsulated::from_prepared_request_response(
            &prepared_request,
            &prepared_response,
            body_kind,
        )?;
        let mut promoted = request_promoted;
        promoted.extend(response_promoted);
        let headers = with_promoted_headers(headers, &promoted)?;
        let mut icap = build_client_request(line, &headers, encapsulated, preview)?;
        if body_kind != EncapsulatedKind::NullBody
            && let Some(len) = original_body_len
        {
            icap = icap.try_with_original_body_len(len)?;
        }
        Ok(Self {
            icap,
            original: OriginalHead::Response(original),
            body: Body::new(body),
            trailer_forbidden,
            replay_limits: ReplayLimits::new(),
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

    rama_utils::macros::generate_set_and_with! {
        /// Set the finite bounds used while retaining original body frames.
        pub const fn replay_limits(mut self, limits: ReplayLimits) -> Self {
            self.replay_limits = limits;
            self
        }
    }

    /// Return the original-body replay bounds.
    #[must_use]
    pub const fn replay_limits(&self) -> ReplayLimits {
        self.replay_limits
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
    IO: Io + Unpin + ExtensionsRef,
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

    /// Consume this connection and send one owned HTTP adaptation request.
    ///
    /// The returned response owns the connection, so it can be moved into a
    /// Rama HTTP body or across a service boundary without a task or channel.
    pub async fn send_http_owned(
        self,
        request: ClientRequest,
    ) -> Result<OwnedClientResponse<IO>, Error> {
        self.send_http_owned_with(request, HeadParser::new()).await
    }

    /// Consume this connection and send one owned HTTP adaptation request
    /// with explicit parser bounds.
    pub async fn send_http_owned_with(
        mut self,
        request: ClientRequest,
        parser: HeadParser,
    ) -> Result<OwnedClientResponse<IO>, Error> {
        let response = self.send_http_with(request, parser).await?;
        let ClientResponse { inner, state } = response;
        let inner = inner.into_state();
        let extensions = self.extensions().fork();
        let mut response = OwnedClientResponse {
            connection: Some(self),
            extensions,
            inner,
            state,
        };
        response.release_connection_if_complete();
        Ok(response)
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
    source: Body,
    buffered: VecDeque<Frame<Bytes>>,
    pending_data: Option<PendingData>,
    trailer_forbidden: Vec<HeaderName>,
    limits: ReplayLimits,
    retained_bytes: usize,
    retained_frames: usize,
    retain: bool,
    eof: bool,
}

struct PendingData {
    data: Bytes,
    frame_counted: bool,
}

impl OriginalBody {
    fn new(
        body: Body,
        retain: bool,
        limits: ReplayLimits,
        trailer_forbidden: Vec<HeaderName>,
    ) -> Self {
        let eof = body.is_end_stream();
        Self {
            source: body,
            buffered: VecDeque::new(),
            pending_data: None,
            trailer_forbidden,
            limits,
            retained_bytes: 0,
            retained_frames: 0,
            retain,
            eof,
        }
    }

    fn stop_retaining(&mut self) {
        self.retain = false;
        self.buffered.clear();
        self.retained_bytes = 0;
        self.retained_frames = 0;
    }

    fn discard(&mut self) {
        self.stop_retaining();
        self.pending_data = None;
        self.source = Body::empty();
        self.eof = true;
    }

    async fn next_source(&mut self) -> Result<Option<Frame<Bytes>>, Error> {
        if self.eof {
            return Ok(None);
        }
        let frame = poll_fn(|context| Pin::new(&mut self.source).poll_frame(context))
            .await
            .transpose()
            .map_err(Error::http_body)?;
        self.eof = frame.is_none() || self.source.is_end_stream();
        if let Some(frame) = &frame {
            self.validate_frame(frame)?;
        }
        Ok(frame)
    }

    fn validate_frame(&self, frame: &Frame<Bytes>) -> Result<(), Error> {
        if let Some(trailers) = frame.trailers_ref() {
            validate_http_trailers(trailers, &self.trailer_forbidden)
                .map_err(Error::invalid_frame)?;
        }
        Ok(())
    }

    fn retain_frame(&mut self, frame: &Frame<Bytes>) -> Result<(), Error> {
        self.retain_frame_part(frame, true)
    }

    fn retain_frame_part(&mut self, frame: &Frame<Bytes>, count_frame: bool) -> Result<(), Error> {
        if !self.retain {
            return Ok(());
        }
        let bytes = if let Some(data) = frame.data_ref() {
            if data.is_empty() {
                return Ok(());
            }
            data.len()
        } else if let Some(trailers) = frame.trailers_ref() {
            trailers
                .iter()
                .try_fold(2_usize, |len, (name, value)| {
                    len.checked_add(name.as_str().len())
                        .and_then(|len| len.checked_add(value.as_bytes().len()))
                        .and_then(|len| len.checked_add(4))
                })
                .ok_or_else(Error::replay_limit_exceeded)?
        } else {
            return Ok(());
        };
        let retained_bytes = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or_else(Error::replay_limit_exceeded)?;
        let retained_frames = self
            .retained_frames
            .checked_add(usize::from(count_frame))
            .ok_or_else(Error::replay_limit_exceeded)?;
        if retained_bytes > self.limits.max_bytes || retained_frames > self.limits.max_frames {
            return Err(Error::replay_limit_exceeded());
        }
        self.retained_bytes = retained_bytes;
        self.retained_frames = retained_frames;
        self.buffered.push_back(frame.clone());
        Ok(())
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
            } else if let Some(pending) = self.pending_data.take() {
                Some(Frame::data(pending.data))
            } else if self.eof {
                None
            } else {
                let frame = poll_fn(|context| Pin::new(&mut self.source).poll_frame(context))
                    .await
                    .transpose()
                    .map_err(Error::http_body)?;
                self.eof = frame.is_none() || self.source.is_end_stream();
                if let Some(frame) = &frame {
                    self.validate_frame(frame)?;
                }
                frame
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
    IO: Io + Unpin + ExtensionsRef,
{
    let ClientRequest {
        icap,
        original: original_head,
        body,
        trailer_forbidden,
        replay_limits,
    } = request;
    let preview = icap.preview();
    let retain_original = preview.is_some() || icap.allows_204() || icap.allows_206();
    let retain_after_preview = icap.allows_204() || icap.allows_206();
    if retain_after_preview
        && body
            .size_hint()
            .exact()
            .is_some_and(|len| len > u64::try_from(replay_limits.max_bytes).unwrap_or(u64::MAX))
    {
        return Err(Error::replay_limit_exceeded());
    }
    let mut transaction = Some(connection.start(icap).await?);
    let mut original_body =
        OriginalBody::new(body, retain_original, replay_limits, trailer_forbidden);
    let mut phase = preview.map_or(ClientSendPhase::Body, |limit| ClientSendPhase::Preview {
        remaining: limit.as_u64(),
    });
    let mut trailers = None;
    let mut saw_trailers = false;

    loop {
        if matches!(phase, ClientSendPhase::Preview { remaining: 0 }) {
            let outcome = take_transaction(&mut transaction)?
                .finish_preview(original_body.eof)
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

        let (frame, pending_frame_counted) = if let Some(pending) =
            original_body.pending_data.take()
        {
            (Some(Frame::data(pending.data)), pending.frame_counted)
        } else {
            let outcome = transaction
                .as_mut()
                .ok_or_else(|| Error::invalid_sequence("ICAP client transaction disappeared"))?
                .next_source_or_response(original_body.next_source())
                .await?;
            (
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
                },
                false,
            )
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
                            original_body.pending_data = Some(PendingData {
                                data,
                                frame_counted: false,
                            });
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
                            original_body.pending_data = Some(PendingData {
                                data: data.split_off(take),
                                frame_counted: true,
                            });
                        }
                        data
                    }
                    ClientSendPhase::Body => data,
                };

                // Retain only the bytes selected for this send. A source body
                // may yield one frame larger than Preview; buffering that
                // unsplit frame would reject an otherwise bounded replay.
                original_body
                    .retain_frame_part(&Frame::data(send.clone()), !pending_frame_counted)?;

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

                if original_body.pending_data.is_some() {
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
                original_body.retain_frame(&Frame::trailers(fields.clone()))?;
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
    IO: Io + Unpin + ExtensionsRef,
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
    state: ClientResponseState,
}

struct ClientResponseState {
    encapsulated: Option<Encapsulated>,
    original_head: OriginalHead,
    result_head: Option<ResultHead>,
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

#[derive(Debug)]
enum ResultHead {
    OriginalRequest,
    OriginalResponse,
    EncapsulatedRequest,
    EncapsulatedResponse,
    Request(HttpRequest<()>),
    Response(HttpResponse<()>),
}

enum ClientFrame {
    Ready(Option<Frame<Bytes>>),
    TransportComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseBodyMode {
    Adapted,
    Partial,
    Original,
}

impl<'a, IO> ClientResponse<'a, IO>
where
    IO: Io + Unpin + ExtensionsRef,
{
    fn from_icap(driven: DrivenClientResponse<'a, IO>, parser: HeadParser) -> Result<Self, Error> {
        let DrivenClientResponse {
            response: mut inner,
            original_head,
            mut original_body,
        } = driven;
        let encapsulated = match inner
            .response()
            .encapsulated()
            .map(|parts| Encapsulated::parse_with(parts, &parser))
            .transpose()
        {
            Ok(encapsulated) => encapsulated,
            Err(error) => {
                inner.connection_and_state().0.mark_broken();
                return Err(error);
            }
        }
        .map(|parts| parts.inherit_original_context(&original_head));
        if inner.response().method() == MethodKind::Reqmod
            && let Some(status) = encapsulated
                .as_ref()
                .and_then(Encapsulated::response)
                .map(HttpResponse::status)
            && !status.is_client_error()
            && !status.is_server_error()
        {
            inner.connection_and_state().0.mark_broken();
            return Err(Error::invalid_sequence(
                "REQMOD may only return an HTTP error response",
            ));
        }
        let returned_proxy_headers = match response_proxy_headers(inner.response()) {
            Ok(headers) => headers,
            Err(source) => {
                inner.connection_and_state().0.mark_broken();
                return Err(Error::icap_message(source));
            }
        };
        let result_head = match resolve_result_head(
            inner.response().method(),
            inner.response().status(),
            encapsulated.as_ref(),
            &original_head,
            &returned_proxy_headers,
        ) {
            Ok(result) => result,
            Err(error) => {
                inner.connection_and_state().0.mark_broken();
                return Err(error);
            }
        };
        let mode = match inner.response().status() {
            StatusCode::NO_MODIFICATION_NEEDED => ResponseBodyMode::Original,
            StatusCode::PARTIAL_CONTENT => ResponseBodyMode::Partial,
            _ => ResponseBodyMode::Adapted,
        };
        if matches!(mode, ResponseBodyMode::Original | ResponseBodyMode::Partial)
            && !original_body.retain
        {
            inner.connection_and_state().0.mark_broken();
            return Err(Error::invalid_sequence(
                "ICAP response requires unavailable original HTTP body data",
            ));
        }
        if mode == ResponseBodyMode::Adapted {
            original_body.discard();
        }
        let state = ClientResponseState {
            encapsulated,
            original_head,
            result_head,
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
        };
        Ok(Self { inner, state })
    }

    /// Return the ICAP response metadata.
    #[must_use]
    pub const fn icap(&self) -> &IcapResponse {
        self.inner.response()
    }

    /// Return the typed encapsulated HTTP metadata, when present.
    #[must_use]
    pub const fn encapsulated(&self) -> Option<&Encapsulated> {
        self.state.encapsulated.as_ref()
    }

    /// Return the original HTTP request head for a REQMOD transaction.
    #[must_use]
    pub fn original_request(&self) -> Option<&HttpRequest<()>> {
        self.state.original_head.request()
    }

    /// Return the original HTTP response head for a RESPMOD transaction.
    #[must_use]
    pub fn original_response(&self) -> Option<&HttpResponse<()>> {
        self.state.original_head.response()
    }

    /// Return the resulting HTTP request head for a REQMOD transaction.
    ///
    /// A 204 response reuses the retained original head. A body-only adapted
    /// result copies that head without its original `Content-Length`, while a
    /// headed result uses the encapsulated head. Proxy credentials promoted to
    /// the outer ICAP response are restored on the resulting HTTP request.
    #[must_use]
    pub fn request(&self) -> Option<&HttpRequest<()>> {
        self.state.request()
    }

    /// Return the resulting HTTP response head for a RESPMOD transaction.
    ///
    /// A 204 response reuses the retained original head. A body-only adapted
    /// result copies that head without its original `Content-Length`. Proxy
    /// challenges promoted to the outer ICAP response are restored on the
    /// resulting HTTP response.
    #[must_use]
    pub fn response(&self) -> Option<&HttpResponse<()>> {
        self.state.response()
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
        loop {
            let (connection, inner) = self.inner.connection_and_state();
            match self.state.next_frame(Some(connection), inner).await {
                Ok(ClientFrame::Ready(frame)) => return Ok(frame),
                Ok(ClientFrame::TransportComplete) => {}
                Err(error) => {
                    if !self.state.original_replay_transport_is_reusable(inner) {
                        connection.mark_broken();
                    }
                    return Err(error);
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
        self.state.output_trailers.as_ref()
    }

    /// Return negotiated outer ICAP trailers after the ICAP body completes.
    ///
    /// These fields are ICAP metadata and are never emitted as HTTP trailer
    /// frames by [`next_frame`](Self::next_frame).
    #[must_use]
    pub fn icap_trailers(&self) -> Option<&TrailerBlock> {
        self.inner.icap_trailers()
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
        self.state
            .original_body_offset_is_verified(self.inner.original_body_offset_is_verified())
    }

    /// Drain and discard the resulting HTTP entity body.
    pub async fn drain(&mut self) -> Result<(), Error> {
        while self.next_frame().await?.is_some() {}
        Ok(())
    }

    /// Return the ICAP response after its body has completed.
    pub fn into_icap(self) -> Result<IcapResponse, Error> {
        if !self.state.output_complete {
            return Err(Error::invalid_sequence(
                "resulting HTTP body has not completed",
            ));
        }
        Ok(self.inner.into_response()?)
    }
}

fn resolve_result_head(
    method: MethodKind,
    status: StatusCode,
    encapsulated: Option<&Encapsulated>,
    original: &OriginalHead,
    returned: &[ForwardedIcapHeader],
) -> Result<Option<ResultHead>, Error> {
    let selected = if status == StatusCode::NO_MODIFICATION_NEEDED {
        match method {
            MethodKind::Reqmod => Some(ResultHead::OriginalRequest),
            MethodKind::Respmod => Some(ResultHead::OriginalResponse),
            _ => None,
        }
    } else if encapsulated.and_then(Encapsulated::request).is_some() {
        Some(ResultHead::EncapsulatedRequest)
    } else if encapsulated.and_then(Encapsulated::response).is_some() {
        Some(ResultHead::EncapsulatedResponse)
    } else if matches!(
        status,
        StatusCode::OK | StatusCode::CREATED | StatusCode::PARTIAL_CONTENT
    ) {
        match (method, encapsulated.map(Encapsulated::body_kind)) {
            (MethodKind::Reqmod, Some(EncapsulatedKind::RequestBody)) => {
                Some(ResultHead::Request(adapted_original_request(original)?))
            }
            (
                MethodKind::Respmod,
                Some(EncapsulatedKind::ResponseBody | EncapsulatedKind::NullBody),
            ) => Some(ResultHead::Response(adapted_original_response(original)?)),
            (MethodKind::Reqmod, Some(EncapsulatedKind::ResponseBody)) => {
                return Err(Error::invalid_sequence(
                    "headless REQMOD response body has no HTTP response head",
                ));
            }
            (MethodKind::Reqmod, Some(EncapsulatedKind::NullBody)) => {
                return Err(Error::invalid_sequence(
                    "headless REQMOD null body has an ambiguous HTTP result",
                ));
            }
            _ => None,
        }
    } else {
        None
    };

    selected
        .map(|head| head.with_proxy_context(encapsulated, original, returned))
        .transpose()
}

fn adapted_original_request(original: &OriginalHead) -> Result<HttpRequest<()>, Error> {
    let mut request = original
        .request()
        .cloned()
        .ok_or_else(|| Error::invalid_sequence("REQMOD result lost its original HTTP request"))?;
    request
        .headers_mut()
        .remove(rama_http_types::header::CONTENT_LENGTH);
    Ok(request)
}

fn adapted_original_response(original: &OriginalHead) -> Result<HttpResponse<()>, Error> {
    let mut response = original
        .response()
        .cloned()
        .ok_or_else(|| Error::invalid_sequence("RESPMOD result lost its original HTTP response"))?;
    response
        .headers_mut()
        .remove(rama_http_types::header::CONTENT_LENGTH);
    Ok(response)
}

impl ResultHead {
    fn with_proxy_context(
        self,
        encapsulated: Option<&Encapsulated>,
        original: &OriginalHead,
        returned: &[ForwardedIcapHeader],
    ) -> Result<Self, Error> {
        Ok(match self {
            Self::OriginalRequest => {
                if returned.iter().any(|field| {
                    field
                        .name
                        .eq_ignore_ascii_case(crate::proto::header::PROXY_AUTHORIZATION)
                }) {
                    let original = original.request().ok_or_else(|| {
                        Error::invalid_sequence("REQMOD result lost its original HTTP request")
                    })?;
                    Self::Request(request_with_proxy_context(original, None, returned))
                } else {
                    self
                }
            }
            Self::OriginalResponse => {
                if returned.iter().any(|field| {
                    field
                        .name
                        .eq_ignore_ascii_case(crate::proto::header::PROXY_AUTHENTICATE)
                }) {
                    let original = original.response().ok_or_else(|| {
                        Error::invalid_sequence("RESPMOD result lost its original HTTP response")
                    })?;
                    Self::Response(response_with_proxy_context(original, None, returned))
                } else {
                    self
                }
            }
            Self::EncapsulatedRequest => {
                let request = encapsulated
                    .and_then(Encapsulated::request)
                    .ok_or_else(|| {
                        Error::invalid_sequence("selected ICAP result has no HTTP request head")
                    })?;
                let original = original.request();
                let needs_update = request
                    .headers()
                    .contains_key(rama_http_types::header::PROXY_AUTHORIZATION)
                    || original.is_some_and(|head| {
                        head.headers()
                            .contains_key(rama_http_types::header::PROXY_AUTHORIZATION)
                    })
                    || returned.iter().any(|field| {
                        field
                            .name
                            .eq_ignore_ascii_case(crate::proto::header::PROXY_AUTHORIZATION)
                    });
                if needs_update {
                    Self::Request(request_with_proxy_context(request, original, returned))
                } else {
                    self
                }
            }
            Self::EncapsulatedResponse => {
                let response = encapsulated
                    .and_then(Encapsulated::response)
                    .ok_or_else(|| {
                        Error::invalid_sequence("selected ICAP result has no HTTP response head")
                    })?;
                let original = original.response();
                let needs_update = response
                    .headers()
                    .contains_key(rama_http_types::header::PROXY_AUTHENTICATE)
                    || original.is_some_and(|head| {
                        head.headers()
                            .contains_key(rama_http_types::header::PROXY_AUTHENTICATE)
                    })
                    || returned.iter().any(|field| {
                        field
                            .name
                            .eq_ignore_ascii_case(crate::proto::header::PROXY_AUTHENTICATE)
                    });
                if needs_update {
                    Self::Response(response_with_proxy_context(response, original, returned))
                } else {
                    self
                }
            }
            Self::Request(request) => Self::Request(request_with_proxy_context(
                &request,
                original.request(),
                returned,
            )),
            Self::Response(response) => Self::Response(response_with_proxy_context(
                &response,
                original.response(),
                returned,
            )),
        })
    }
}

// The original, encapsulated, and effective result heads are distinct public
// views. Materialize the effective head only when proxy-field restoration makes
// it differ from the stored original or encapsulated view.
fn request_with_proxy_context(
    request: &HttpRequest<()>,
    original: Option<&HttpRequest<()>>,
    returned: &[ForwardedIcapHeader],
) -> HttpRequest<()> {
    let mut request = HttpRequest::from_parts(request.clone_parts(), ());
    restore_result_proxy_header(
        request.headers_mut(),
        &rama_http_types::header::PROXY_AUTHORIZATION,
        crate::proto::header::PROXY_AUTHORIZATION,
        original.map(HttpRequest::headers),
        returned,
    );
    request
}

fn response_with_proxy_context(
    response: &HttpResponse<()>,
    original: Option<&HttpResponse<()>>,
    returned: &[ForwardedIcapHeader],
) -> HttpResponse<()> {
    let mut response = HttpResponse::from_parts(response.clone_parts(), ());
    restore_result_proxy_header(
        response.headers_mut(),
        &rama_http_types::header::PROXY_AUTHENTICATE,
        crate::proto::header::PROXY_AUTHENTICATE,
        original.map(HttpResponse::headers),
        returned,
    );
    response
}

fn restore_result_proxy_header(
    headers: &mut HeaderMap,
    http_name: &HeaderName,
    icap_name: &str,
    original: Option<&HeaderMap>,
    returned: &[ForwardedIcapHeader],
) {
    headers.remove(http_name);
    if returned
        .iter()
        .any(|field| field.name.eq_ignore_ascii_case(icap_name))
    {
        for field in returned
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case(icap_name))
        {
            headers.append(http_name.clone(), field.value.clone());
        }
    } else if let Some(original) = original {
        for mut value in original.get_all(http_name).iter().cloned() {
            if http_name.is_sensitive() {
                value.set_sensitive(true);
            }
            headers.append(http_name.clone(), value);
        }
    }
}

impl ClientResponseState {
    fn request(&self) -> Option<&HttpRequest<()>> {
        match self.result_head.as_ref()? {
            ResultHead::OriginalRequest => self.original_head.request(),
            ResultHead::EncapsulatedRequest => {
                self.encapsulated.as_ref().and_then(Encapsulated::request)
            }
            ResultHead::Request(request) => Some(request),
            ResultHead::OriginalResponse
            | ResultHead::EncapsulatedResponse
            | ResultHead::Response(_) => None,
        }
    }

    fn response(&self) -> Option<&HttpResponse<()>> {
        match self.result_head.as_ref()? {
            ResultHead::OriginalResponse => self.original_head.response(),
            ResultHead::EncapsulatedResponse => {
                self.encapsulated.as_ref().and_then(Encapsulated::response)
            }
            ResultHead::Response(response) => Some(response),
            ResultHead::OriginalRequest
            | ResultHead::EncapsulatedRequest
            | ResultHead::Request(_) => None,
        }
    }

    fn original_replay_transport_is_reusable(&self, inner: &RawClientResponseState) -> bool {
        self.mode == ResponseBodyMode::Original
            && inner.body_end().is_some()
            && (!self.replay_requires_octet
                || self.replay_selected_octet
                || inner.original_body_offset_is_verified() == Some(true))
    }

    const fn original_body_offset_is_verified(&self, protocol: Option<bool>) -> Option<bool> {
        match protocol {
            Some(false) if self.replay_selected_octet => Some(true),
            result => result,
        }
    }

    async fn next_frame<IO>(
        &mut self,
        connection: Option<&mut RawClientConnection<IO>>,
        inner: &mut RawClientResponseState,
    ) -> Result<ClientFrame, Error>
    where
        IO: Io + Unpin + ExtensionsRef,
    {
        if self.output_complete {
            return Ok(ClientFrame::Ready(None));
        }
        match self.mode {
            ResponseBodyMode::Adapted => {
                if inner.body_end().is_none() {
                    let connection = connection.ok_or_else(|| {
                        Error::invalid_sequence("ICAP response transport was released too early")
                    })?;
                    if let Some(data) = inner.next_data(connection).await? {
                        return Ok(ClientFrame::Ready(Some(Frame::data(data))));
                    }
                }
                self.parse_adapted_trailers(inner)?;
                self.output_trailers = self.adapted_trailers.clone();
                Ok(ClientFrame::Ready(self.finish_output()))
            }
            ResponseBodyMode::Partial => {
                if inner.body_end().is_none() {
                    let connection = connection.ok_or_else(|| {
                        Error::invalid_sequence("ICAP response transport was released too early")
                    })?;
                    if let Some(data) = inner.next_data(connection).await? {
                        return Ok(ClientFrame::Ready(Some(Frame::data(data))));
                    }
                }
                self.parse_adapted_trailers(inner)?;
                match inner.body_end() {
                    Some(BodyEnd::PartialContent { use_original_body }) => {
                        self.replay_skip = use_original_body;
                        self.replay_requires_octet = true;
                        self.replay_selected_octet = false;
                        self.mode = ResponseBodyMode::Original;
                        Ok(ClientFrame::TransportComplete)
                    }
                    Some(BodyEnd::Complete) => {
                        self.original_body.discard();
                        self.output_trailers = self.adapted_trailers.clone();
                        Ok(ClientFrame::Ready(self.finish_output()))
                    }
                    _ => Err(Error::invalid_sequence(
                        "206 response ended without a valid body terminal",
                    )),
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
                        Ok(data) => Ok(ClientFrame::Ready(Some(Frame::data(data)))),
                        Err(frame) => {
                            let original = frame.into_trailers().map_err(|_frame| {
                                Error::invalid_frame(
                                    "original HTTP body produced an unsupported frame",
                                )
                            })?;
                            self.output_trailers = self.adapted_trailers.clone().or(Some(original));
                            Ok(ClientFrame::Ready(self.finish_output()))
                        }
                    }
                } else {
                    self.output_trailers = self.adapted_trailers.clone();
                    Ok(ClientFrame::Ready(self.finish_output()))
                }
            }
        }
    }

    fn parse_adapted_trailers(&mut self, inner: &RawClientResponseState) -> Result<(), Error> {
        if !self.adapted_trailers_parsed {
            let trailers = inner
                .trailers()
                .filter(|trailers| !trailers.is_empty())
                .map(|trailers| self.parser.parse_fields(trailers.as_bytes()))
                .transpose()?;
            if let Some(trailers) = &trailers {
                let nominated = self
                    .request()
                    .map(|request| connection_nominated_headers(request.headers()))
                    .or_else(|| {
                        self.response()
                            .map(|response| connection_nominated_headers(response.headers()))
                    })
                    .unwrap_or_default();
                validate_http_trailers(trailers, &nominated).map_err(Error::invalid_frame)?;
            }
            self.adapted_trailers = trailers;
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
    IO: Io + Unpin + ExtensionsRef,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientResponse")
            .field("icap", &self.inner.response())
            .field("encapsulated", &self.state.encapsulated)
            .field("body_end", &self.inner.body_end())
            .finish_non_exhaustive()
    }
}

/// An owned, typed streaming response to an HTTP adaptation request.
///
/// Unlike [`ClientResponse`], this value owns its ICAP connection. It is
/// suitable for request-level services and can turn its remaining stream into
/// a Rama [`Body`] without spawning a task or copying payload bytes.
#[must_use]
pub struct OwnedClientResponse<IO> {
    connection: Option<RawClientConnection<IO>>,
    extensions: Extensions,
    inner: RawClientResponseState,
    state: ClientResponseState,
}

impl<IO> OwnedClientResponse<IO>
where
    IO: Io + Unpin + ExtensionsRef,
{
    /// Return the ICAP response metadata.
    #[must_use]
    pub const fn icap(&self) -> &IcapResponse {
        self.inner.response()
    }

    /// Return the typed encapsulated HTTP metadata, when present.
    #[must_use]
    pub const fn encapsulated(&self) -> Option<&Encapsulated> {
        self.state.encapsulated.as_ref()
    }

    /// Return the original HTTP request head for a REQMOD transaction.
    #[must_use]
    pub fn original_request(&self) -> Option<&HttpRequest<()>> {
        self.state.original_head.request()
    }

    /// Return the original HTTP response head for a RESPMOD transaction.
    #[must_use]
    pub fn original_response(&self) -> Option<&HttpResponse<()>> {
        self.state.original_head.response()
    }

    /// Return the resulting HTTP request head for a REQMOD transaction.
    ///
    /// This applies the same body-only fallback and proxy-field restoration
    /// as [`ClientResponse::request`].
    #[must_use]
    pub fn request(&self) -> Option<&HttpRequest<()>> {
        self.state.request()
    }

    /// Return the resulting HTTP response head for a RESPMOD transaction.
    ///
    /// This applies the same body-only fallback and proxy-field restoration
    /// as [`ClientResponse::response`].
    #[must_use]
    pub fn response(&self) -> Option<&HttpResponse<()>> {
        self.state.response()
    }

    /// Read the next zero-copy data or trailer frame.
    pub async fn next_frame(&mut self) -> Result<Option<Frame<Bytes>>, Error> {
        loop {
            self.release_connection_if_complete();
            match self
                .state
                .next_frame(self.connection.as_mut(), &mut self.inner)
                .await
            {
                Ok(ClientFrame::Ready(frame)) => {
                    self.release_connection_if_complete();
                    return Ok(frame);
                }
                Ok(ClientFrame::TransportComplete) => {}
                Err(error) => {
                    if let Some(connection) = &mut self.connection {
                        connection.mark_broken();
                    }
                    return Err(error);
                }
            }
        }
    }

    /// Read the next zero-copy data segment.
    pub async fn next_data(&mut self) -> Result<Option<Bytes>, Error> {
        let Some(frame) = self.next_frame().await? else {
            return Ok(None);
        };
        match frame.into_data() {
            Ok(data) => Ok(Some(data)),
            Err(_trailers) => Ok(None),
        }
    }

    /// Return the terminal ICAP body state after the stream completes.
    #[must_use]
    pub const fn body_end(&self) -> Option<BodyEnd> {
        self.inner.body_end()
    }

    /// Return trailers after the resulting HTTP stream completes.
    #[must_use]
    pub const fn trailers(&self) -> Option<&HeaderMap> {
        self.state.output_trailers.as_ref()
    }

    /// Return negotiated outer ICAP trailers after the ICAP body completes.
    ///
    /// These fields remain outside the resulting HTTP body stream.
    #[must_use]
    pub fn icap_trailers(&self) -> Option<&TrailerBlock> {
        self.inner.icap_trailers()
    }

    /// Return whether a 206 original-body offset was locally verified.
    #[must_use]
    pub const fn original_body_offset_is_verified(&self) -> Option<bool> {
        self.state
            .original_body_offset_is_verified(self.inner.original_body_offset_is_verified())
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

    /// Drain and discard the resulting HTTP entity body.
    pub async fn drain(&mut self) -> Result<(), Error> {
        while self.next_frame().await?.is_some() {}
        Ok(())
    }

    /// Turn the remaining resulting HTTP stream into a Rama body.
    pub fn into_body(self) -> Body {
        Body::from_frame_stream(stream::try_unfold(self, |mut response| async move {
            match response.next_frame().await? {
                Some(frame) => Ok::<_, Error>(Some((frame, response))),
                None => Ok::<_, Error>(None),
            }
        }))
    }

    /// Turn a successful REQMOD result into a streaming HTTP request.
    pub fn into_request(self) -> Result<HttpRequest<Body>, Error> {
        let head = self.request().cloned().ok_or_else(|| {
            Error::invalid_sequence("ICAP response has no resulting HTTP request")
        })?;
        let (parts, ()) = head.into_parts();
        Ok(HttpRequest::from_parts(parts, self.into_body()))
    }

    /// Turn a successful RESPMOD result into a streaming HTTP response.
    pub fn into_response(self) -> Result<HttpResponse<Body>, Error> {
        let head = self.response().cloned().ok_or_else(|| {
            Error::invalid_sequence("ICAP response has no resulting HTTP response")
        })?;
        let (parts, ()) = head.into_parts();
        Ok(HttpResponse::from_parts(parts, self.into_body()))
    }

    /// Return the ICAP response after its body has completed.
    pub fn into_icap(self) -> Result<IcapResponse, Error> {
        if !self.state.output_complete {
            return Err(Error::invalid_sequence(
                "resulting HTTP body has not completed",
            ));
        }
        Ok(self.inner.into_response()?)
    }

    fn release_connection_if_complete(&mut self) {
        if self.inner.body_end().is_none() || self.connection.is_none() {
            return;
        }
        let replay_is_verified = !self.state.replay_requires_octet
            || self.state.replay_selected_octet
            || self.state.output_complete
            || self.inner.original_body_offset_is_verified() == Some(true);
        if replay_is_verified {
            drop(self.connection.take());
        }
    }
}

impl<IO> ExtensionsRef for OwnedClientResponse<IO> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<IO> fmt::Debug for OwnedClientResponse<IO>
where
    IO: Io + Unpin + ExtensionsRef,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedClientResponse")
            .field("icap", &self.inner.response())
            .field("encapsulated", &self.state.encapsulated)
            .field("body_end", &self.inner.body_end())
            .finish_non_exhaustive()
    }
}

fn prepare_request_head<T>(
    request: &HttpRequest<T>,
) -> (HttpRequest<()>, Vec<ForwardedIcapHeader>, Vec<HeaderName>) {
    let mut request = HttpRequest::from_parts(request.clone_parts(), ());
    let (promoted, trailer_forbidden) = sanitize_http_headers_with_nominated(request.headers_mut());
    (request, promoted, trailer_forbidden)
}

fn prepare_response_head<T>(
    response: &HttpResponse<T>,
) -> (HttpResponse<()>, Vec<ForwardedIcapHeader>, Vec<HeaderName>) {
    let mut response = HttpResponse::from_parts(response.clone_parts(), ());
    let (promoted, trailer_forbidden) =
        sanitize_http_headers_with_nominated(response.headers_mut());
    (response, promoted, trailer_forbidden)
}

fn with_promoted_headers<'a>(
    headers: &'a [Header<'a>],
    promoted: &'a [ForwardedIcapHeader],
) -> Result<Vec<Header<'a>>, Error> {
    let mut fields = Vec::with_capacity(headers.len().saturating_add(promoted.len()));
    fields.extend_from_slice(headers);
    for field in promoted {
        if headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(field.name))
        {
            continue;
        }
        fields.push(Header::new(field.name, field.value.as_bytes()).map_err(BuildError::from)?);
    }
    Ok(fields)
}

fn build_client_request(
    line: RequestLineSource<'_>,
    headers: &[Header<'_>],
    encapsulated: EncapsulatedParts,
    preview: Option<Preview>,
) -> Result<IcapRequest, Error> {
    Ok(if let Some(preview) = preview {
        IcapRequest::with_preview_from_source(line, headers, encapsulated, preview)?
    } else {
        IcapRequest::new_from_source(line, headers, Some(encapsulated))?
    })
}

impl OutgoingBody {
    /// Stream an HTTP body as ICAP data and trailer frames.
    pub fn from_http<B>(body: B) -> Self
    where
        B: StreamingBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError> + 'static,
    {
        Self::from_http_with_forbidden(body, Vec::new())
    }

    fn from_http_with_forbidden<B>(body: B, head_nominated: Vec<HeaderName>) -> Self
    where
        B: StreamingBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError> + 'static,
    {
        Self::from_frames(BodyStream::new(body).map(move |result| {
            result
                .map_err(Into::into)
                .and_then(|frame| http_frame_to_icap(frame, &head_nominated))
        }))
    }
}

fn http_frame_to_icap(
    frame: Frame<Bytes>,
    head_nominated: &[HeaderName],
) -> Result<crate::server::BodyFrame, BoxError> {
    match frame.into_data() {
        Ok(data) => Ok(crate::server::BodyFrame::data(data)),
        Err(frame) => {
            let trailers = frame
                .into_trailers()
                .map_err(|_frame| BoxError::from_static_str("unsupported HTTP body frame"))?;
            validate_http_trailers(&trailers, head_nominated).map_err(BoxError::from_static_str)?;
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
        let (prepared, promoted, trailer_forbidden) = prepare_request_head(&request);
        let encapsulated = Encapsulated::from_prepared_request(&prepared, body_kind)?;
        let headers = with_promoted_headers(headers, &promoted)?;
        let response = IcapResponse::new(MethodKind::Reqmod, line, &headers, Some(encapsulated))?;
        Ok(Self::new(
            response,
            OutgoingBody::from_http_with_forbidden(body, trailer_forbidden),
        ))
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
        if method == MethodKind::Reqmod
            && !response.status().is_client_error()
            && !response.status().is_server_error()
        {
            return Err(Error::invalid_response_status(response.status().as_u16()));
        }
        let (parts, body) = response.into_parts();
        let response = HttpResponse::from_parts(parts, ());
        let body_kind = if body.is_end_stream() {
            EncapsulatedKind::NullBody
        } else {
            EncapsulatedKind::ResponseBody
        };
        let (prepared, promoted, trailer_forbidden) = prepare_response_head(&response);
        let encapsulated = Encapsulated::from_prepared_response(&prepared, body_kind)?;
        let headers = with_promoted_headers(headers, &promoted)?;
        let response = IcapResponse::new(method, line, &headers, Some(encapsulated))?;
        Ok(Self::new(
            response,
            OutgoingBody::from_http_with_forbidden(body, trailer_forbidden),
        ))
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

    const fn invalid_response_status(status: u16) -> Self {
        Self {
            kind: ErrorKind::InvalidResponseStatus(status),
            source: None,
        }
    }

    fn http_head(source: BoxError) -> Self {
        Self {
            kind: ErrorKind::HttpHead,
            source: Some(source),
        }
    }

    fn icap_message(source: BoxError) -> Self {
        Self {
            kind: ErrorKind::IcapMessage,
            source: Some(source),
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

    const fn replay_limit_exceeded() -> Self {
        Self {
            kind: ErrorKind::ReplayLimitExceeded,
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
        match self.kind {
            ErrorKind::InvalidResponseStatus(status) => write!(
                formatter,
                "HTTP status {status} is not an error response valid for REQMOD"
            ),
            ErrorKind::HttpHead => formatter.write_str("invalid encapsulated HTTP head"),
            ErrorKind::HttpBody => formatter.write_str("encapsulated HTTP body failed"),
            ErrorKind::IcapMessage => formatter.write_str("invalid ICAP message metadata"),
            ErrorKind::IcapTransaction => formatter.write_str("ICAP transaction failed"),
            ErrorKind::InvalidMethod => {
                formatter.write_str("invalid ICAP method for HTTP adaptation")
            }
            ErrorKind::InvalidBodyKind => {
                formatter.write_str("invalid ICAP body kind for HTTP message")
            }
            ErrorKind::ReplayLimitExceeded => {
                formatter.write_str("original HTTP body exceeds the ICAP replay bounds")
            }
            ErrorKind::InvalidFrame(message) | ErrorKind::InvalidSequence(message) => {
                formatter.write_str(message)
            }
        }
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
    /// A REQMOD result tried to carry a non-error HTTP response status.
    InvalidResponseStatus(u16),
    /// Original HTTP frames exceeded the configured in-memory replay bounds.
    ReplayLimitExceeded,
    /// The HTTP body produced an invalid frame sequence.
    InvalidFrame(&'static str),
    /// The peer produced an invalid HTTP/ICAP sequence.
    InvalidSequence(&'static str),
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use super::*;
    use crate::{
        codec::{HeaderSlot, ResponseLine},
        proto::{Method, ServiceTag, StatusCode, header},
    };

    const TEST_SERVICE_TAG: ServiceTag = ServiceTag::from_static("rama-test");
    const OPAQUE_SERVICE_TAG: ServiceTag = ServiceTag::from_static(r#"rama "test"\http"#);
    use rama_core::{bytes::Bytes, extensions::Extension, futures::stream};
    use rama_http_types::{HeaderValue, body::util::BodyExt as _};

    #[derive(Debug, Extension)]
    struct ConnectionMarker;

    #[test]
    fn original_body_stops_retaining_all_replay_state() {
        let mut body = OriginalBody::new(Body::empty(), true, ReplayLimits::new(), Vec::new());
        body.retain_frame(&Frame::data(Bytes::from_static(b"preview")))
            .unwrap();

        body.stop_retaining();

        assert!(!body.retain);
        assert!(body.buffered.is_empty());
        assert_eq!(body.retained_bytes, 0);
        assert_eq!(body.retained_frames, 0);
    }

    #[test]
    fn original_body_accepts_frames_up_to_each_replay_limit() {
        let limits = ReplayLimits::new().with_max_bytes(7).with_max_frames(2);
        let mut body = OriginalBody::new(Body::empty(), true, limits, Vec::new());

        body.retain_frame(&Frame::data(Bytes::from_static(b"abc")))
            .unwrap();
        body.retain_frame(&Frame::data(Bytes::from_static(b"defg")))
            .unwrap();

        assert_eq!(body.retained_bytes, 7);
        assert_eq!(body.retained_frames, 2);
        assert_eq!(body.buffered.len(), 2);
    }

    #[tokio::test]
    async fn original_body_does_not_poll_again_after_source_eof() {
        struct UnfusedEof {
            polls: Arc<AtomicUsize>,
        }

        impl StreamingBody for UnfusedEof {
            type Data = Bytes;
            type Error = Infallible;

            fn poll_frame(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                assert_eq!(self.polls.fetch_add(1, Ordering::Relaxed), 0);
                Poll::Ready(None)
            }
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let mut body = OriginalBody::new(
            Body::new(UnfusedEof {
                polls: Arc::clone(&polls),
            }),
            false,
            ReplayLimits::new(),
            Vec::new(),
        );
        let mut skip = 0;
        let mut selected_octet = false;

        assert!(
            body.next_replay(&mut skip, false, &mut selected_octet)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            body.next_replay(&mut skip, false, &mut selected_octet)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(polls.load(Ordering::Relaxed), 1);
    }

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
        trailers.insert(
            rama_http_types::header::ETAG,
            HeaderValue::from_static("\"generated-after-body\""),
        );
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
        assert_eq!(fields["etag"], "\"generated-after-body\"");
    }

    #[tokio::test]
    async fn outgoing_http_body_rejects_late_head_and_connection_fields() {
        for (name, value) in [
            ("authorization", "secret"),
            ("www-authenticate", "Basic realm=test"),
            ("retry-after", "120"),
            ("vary", "Accept-Encoding"),
        ] {
            let mut trailers = HeaderMap::new();
            trailers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
            let body = Body::from_frame_stream(stream::iter([Ok::<_, Infallible>(
                Frame::trailers(trailers),
            )]));
            let mut body = OutgoingBody::from_http(body);
            body.next().await.unwrap().unwrap_err();
        }

        let mut trailers = HeaderMap::new();
        trailers.insert("x-hop", "late".parse().unwrap());
        let body = Body::from_frame_stream(stream::iter([Ok::<_, Infallible>(Frame::trailers(
            trailers,
        ))]));
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/")
            .header("Connection", "x-hop")
            .body(body)
            .unwrap();
        let mut response = OutgoingResponse::from_http_request(
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &[Header::new(header::ISTAG, b"\"rama-test\"").unwrap()],
            request,
        )
        .unwrap();
        response.body_mut().next().await.unwrap().unwrap_err();
    }

    #[test]
    fn reqmod_http_response_requires_an_error_status() {
        for status in [100, 200, 302] {
            let response = HttpResponse::builder()
                .status(status)
                .body(Body::empty())
                .unwrap();
            let error = OutgoingResponse::from_http_response(
                MethodKind::Reqmod,
                ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
                &[Header::new(header::ISTAG, b"\"rama-test\"").unwrap()],
                response,
            )
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidResponseStatus(status));
        }

        for status in [400, 407, 500] {
            let response = HttpResponse::builder()
                .status(status)
                .body(Body::empty())
                .unwrap();
            OutgoingResponse::from_http_response(
                MethodKind::Reqmod,
                ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
                &[Header::new(header::ISTAG, b"\"rama-test\"").unwrap()],
                response,
            )
            .unwrap();
        }

        let response = HttpResponse::builder()
            .status(200)
            .body(Body::empty())
            .unwrap();
        OutgoingResponse::from_http_response(
            MethodKind::Respmod,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &[Header::new(header::ISTAG, b"\"rama-test\"").unwrap()],
            response,
        )
        .unwrap();
    }

    #[test]
    fn body_only_result_copies_original_without_content_length() {
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/scan")
            .header("Content-Length", "100")
            .header("Proxy-Authorization", "Basic original")
            .body(())
            .unwrap();
        let original = OriginalHead::Request(request);
        let encapsulated = Encapsulated {
            request: None,
            response: None,
            body_kind: EncapsulatedKind::RequestBody,
        };
        let result = resolve_result_head(
            MethodKind::Reqmod,
            StatusCode::OK,
            Some(&encapsulated),
            &original,
            &[],
        )
        .unwrap();
        let state = ClientResponseState {
            encapsulated: Some(encapsulated),
            original_head: original,
            result_head: result,
            original_body: OriginalBody::new(Body::empty(), false, ReplayLimits::new(), Vec::new()),
            parser: HeadParser::new(),
            mode: ResponseBodyMode::Adapted,
            replay_skip: 0,
            replay_requires_octet: false,
            replay_selected_octet: false,
            adapted_trailers: None,
            output_trailers: None,
            adapted_trailers_parsed: false,
            trailers_emitted: false,
            output_complete: false,
        };
        assert_eq!(state.request().unwrap().uri().as_str(), "/scan");
        assert!(
            !state
                .request()
                .unwrap()
                .headers()
                .contains_key("content-length")
        );
        assert_eq!(
            state.request().unwrap().headers()["proxy-authorization"],
            "Basic original"
        );
        assert!(state.response().is_none());

        let original = OriginalHead::Response(
            HttpResponse::builder()
                .status(200)
                .header("Content-Length", "100")
                .body(())
                .unwrap(),
        );
        let encapsulated = Encapsulated {
            request: None,
            response: None,
            body_kind: EncapsulatedKind::ResponseBody,
        };
        let result = resolve_result_head(
            MethodKind::Respmod,
            StatusCode::PARTIAL_CONTENT,
            Some(&encapsulated),
            &original,
            &[],
        )
        .unwrap();
        let Some(ResultHead::Response(response)) = result else {
            panic!("copied response expected");
        };
        assert!(!response.headers().contains_key("content-length"));
    }

    #[test]
    fn result_head_restores_returned_proxy_challenge() {
        let original = OriginalHead::Request(HttpRequest::builder().uri("/").body(()).unwrap());
        let encapsulated = Encapsulated {
            request: None,
            response: Some(HttpResponse::builder().status(407).body(()).unwrap()),
            body_kind: EncapsulatedKind::NullBody,
        };
        let returned = [ForwardedIcapHeader {
            name: header::PROXY_AUTHENTICATE,
            value: HeaderValue::from_static("Basic realm=icap"),
        }];
        let result = resolve_result_head(
            MethodKind::Reqmod,
            StatusCode::OK,
            Some(&encapsulated),
            &original,
            &returned,
        )
        .unwrap();
        let state = ClientResponseState {
            encapsulated: Some(encapsulated),
            original_head: original,
            result_head: result,
            original_body: OriginalBody::new(Body::empty(), false, ReplayLimits::new(), Vec::new()),
            parser: HeadParser::new(),
            mode: ResponseBodyMode::Adapted,
            replay_skip: 0,
            replay_requires_octet: false,
            replay_selected_octet: false,
            adapted_trailers: None,
            output_trailers: None,
            adapted_trailers_parsed: false,
            trailers_emitted: false,
            output_complete: false,
        };
        assert_eq!(
            state.response().unwrap().headers()["proxy-authenticate"],
            "Basic realm=icap"
        );
        assert!(
            !state
                .encapsulated
                .as_ref()
                .unwrap()
                .response()
                .unwrap()
                .headers()
                .contains_key("proxy-authenticate")
        );
    }

    #[test]
    fn result_head_restores_original_proxy_credentials_on_encapsulated_heads() {
        let original_request = HttpRequest::builder()
            .uri("/")
            .header("Proxy-Authorization", "Basic original")
            .body(())
            .unwrap();
        let original = OriginalHead::Request(original_request);
        let encapsulated = Encapsulated {
            request: Some(HttpRequest::builder().uri("/adapted").body(()).unwrap()),
            response: None,
            body_kind: EncapsulatedKind::NullBody,
        };
        let result = resolve_result_head(
            MethodKind::Reqmod,
            StatusCode::OK,
            Some(&encapsulated),
            &original,
            &[],
        )
        .unwrap();
        let Some(ResultHead::Request(request)) = result else {
            panic!("adapted request expected");
        };
        assert_eq!(request.uri().as_str(), "/adapted");
        assert_eq!(request.headers()["proxy-authorization"], "Basic original");
        assert!(request.headers()["proxy-authorization"].is_sensitive());

        let original_response = HttpResponse::builder()
            .status(407)
            .header("Proxy-Authenticate", "Basic realm=original")
            .body(())
            .unwrap();
        let original = OriginalHead::Response(original_response);
        let encapsulated = Encapsulated {
            request: None,
            response: Some(HttpResponse::builder().status(407).body(()).unwrap()),
            body_kind: EncapsulatedKind::NullBody,
        };
        let result = resolve_result_head(
            MethodKind::Respmod,
            StatusCode::OK,
            Some(&encapsulated),
            &original,
            &[],
        )
        .unwrap();
        let Some(ResultHead::Response(response)) = result else {
            panic!("adapted response expected");
        };
        assert_eq!(
            response.headers()["proxy-authenticate"],
            "Basic realm=original"
        );
    }

    #[test]
    fn result_head_rejects_headless_reqmod_response_or_null_body() {
        let original = OriginalHead::Request(HttpRequest::builder().uri("/").body(()).unwrap());
        for body_kind in [EncapsulatedKind::ResponseBody, EncapsulatedKind::NullBody] {
            let encapsulated = Encapsulated {
                request: None,
                response: None,
                body_kind,
            };
            let error = resolve_result_head(
                MethodKind::Reqmod,
                StatusCode::OK,
                Some(&encapsulated),
                &original,
                &[],
            )
            .unwrap_err();
            assert!(matches!(error.kind(), ErrorKind::InvalidSequence(_)));
        }
    }

    #[tokio::test]
    async fn response_head_adaptation_uses_streaming_206_replay() {
        let body = Body::from_frame_stream(
            stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                b"preview",
            )))])
            .chain(stream::pending()),
        );
        let mut request = incoming_respmod(
            body,
            EncapsulatedKind::ResponseBody,
            Some(Preview::new(1024)),
            b"204, 206",
        );
        request
            .encapsulated_mut()
            .unwrap()
            .response_mut()
            .unwrap()
            .headers_mut()
            .insert("x-adapted", HeaderValue::from_static("yes"));

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            request.adapt_response_head(OPAQUE_SERVICE_TAG),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(response.response().status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.response().service_tag(),
            Some(br#""rama \"test\"\\http""#.as_slice())
        );
        assert_eq!(
            response.body_end(),
            crate::server::OutgoingBodyEnd::UseOriginalBody(0)
        );
        let parsed = Encapsulated::parse(response.response().encapsulated().unwrap()).unwrap();
        assert_eq!(parsed.response().unwrap().headers()["x-adapted"], "yes");
    }

    #[tokio::test]
    async fn response_head_adaptation_streams_trailers_without_hop_headers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-end", HeaderValue::from_static("kept"));
        trailers.insert(
            rama_http_types::header::ETAG,
            HeaderValue::from_static("\"generated-after-body\""),
        );
        let body = Body::from_frame_stream(stream::iter([Ok::<_, Infallible>(Frame::trailers(
            trailers,
        ))]));
        let request = incoming_respmod(
            body,
            EncapsulatedKind::ResponseBody,
            Some(Preview::new(1024)),
            b"204, 206",
        );

        let mut response = request.adapt_response_head(TEST_SERVICE_TAG).await.unwrap();

        assert_eq!(response.response().status(), StatusCode::OK);
        let parsed = Encapsulated::parse(response.response().encapsulated().unwrap()).unwrap();
        assert!(!parsed.response().unwrap().headers().contains_key("trailer"));
        let crate::server::BodyFrame::Trailers(trailers) =
            response.body_mut().next().await.unwrap().unwrap()
        else {
            panic!("expected trailers");
        };
        let fields = HeadParser::new().parse_fields(trailers.as_bytes()).unwrap();
        assert_eq!(fields["x-end"], "kept");
        assert_eq!(fields["etag"], "\"generated-after-body\"");
    }

    #[tokio::test]
    async fn response_head_adaptation_preserves_a_null_body() {
        let request = incoming_respmod(Body::empty(), EncapsulatedKind::NullBody, None, b"");

        let response = request
            .adapt_response_head(OPAQUE_SERVICE_TAG)
            .await
            .unwrap();

        assert_eq!(response.response().status(), StatusCode::OK);
        let parsed = Encapsulated::parse(response.response().encapsulated().unwrap()).unwrap();
        assert_eq!(parsed.body_kind(), EncapsulatedKind::NullBody);
        assert_eq!(
            response.response().service_tag(),
            Some(br#""rama \"test\"\\http""#.as_slice())
        );
    }

    #[tokio::test]
    async fn response_head_adaptation_rejects_unnegotiated_replay() {
        let request = incoming_respmod(
            Body::from("body"),
            EncapsulatedKind::ResponseBody,
            None,
            b"206",
        );

        let error = request
            .adapt_response_head(TEST_SERVICE_TAG)
            .await
            .unwrap_err();

        assert_eq!(
            error.kind(),
            ErrorKind::InvalidSequence(
                "response-head adaptation requires Allow: 204 and Allow: 206",
            )
        );
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
        let host = Header::new("Host", b"icap.test").unwrap();
        let request = ClientRequest::reqmod(line, &[host], request, Some(Preview::new(4))).unwrap();

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
        let host = Header::new("Host", b"icap.test").unwrap();
        let request = ClientRequest::reqmod(line, &[host], request, None).unwrap();

        let parts = request.icap().encapsulated().unwrap();
        assert_eq!(parts.body_kind(), EncapsulatedKind::NullBody);
        assert_eq!(request.icap().original_body_len(), None);
    }

    #[tokio::test]
    async fn incoming_reqmod_converts_directly_to_http_request() {
        let head = HttpRequest::builder()
            .method("POST")
            .uri("/scan")
            .body(())
            .unwrap();
        let encoded = Encapsulated::from_request(&head, EncapsulatedKind::RequestBody).unwrap();
        let icap = IcapRequest::new(
            RequestLine::new(Method::Reqmod, "icap://icap.test/echo").unwrap(),
            &[Header::new("Host", b"icap.test").unwrap()],
            Some(encoded.clone()),
        )
        .unwrap();
        let request = IncomingRequest {
            icap,
            encapsulated: Some(Encapsulated::parse(&encoded).unwrap()),
            body: Body::from("request body"),
            extensions: Extensions::new(),
            encapsulated_exposed_mutably: false,
            body_exposed_mutably: false,
        }
        .into_request()
        .unwrap();

        assert_eq!(request.method(), "POST");
        assert_eq!(request.uri().as_str(), "/scan");
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "request body"
        );
    }

    #[tokio::test]
    async fn incoming_respmod_converts_directly_to_http_response() {
        let head = HttpResponse::builder().status(201).body(()).unwrap();
        let encoded = Encapsulated::from_response(&head, EncapsulatedKind::ResponseBody).unwrap();
        let icap = IcapRequest::new(
            RequestLine::new(Method::Respmod, "icap://icap.test/echo").unwrap(),
            &[Header::new("Host", b"icap.test").unwrap()],
            Some(encoded.clone()),
        )
        .unwrap();
        let response = IncomingRequest {
            icap,
            encapsulated: Some(Encapsulated::parse(&encoded).unwrap()),
            body: Body::from("response body"),
            extensions: Extensions::new(),
            encapsulated_exposed_mutably: false,
            body_exposed_mutably: false,
        }
        .into_response()
        .unwrap();

        assert_eq!(response.status(), 201);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "response body"
        );
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
    fn typed_messages_promote_proxy_fields_and_strip_hop_by_hop_fields() {
        let request = HttpRequest::builder()
            .method("GET")
            .uri("/")
            .header("Connection", "x-hop")
            .header("X-Hop", "remove")
            .header("Keep-Alive", "timeout=5")
            .header("Proxy-Authorization", "Basic request-secret")
            .body(Body::empty())
            .unwrap();
        let request = ClientRequest::reqmod(
            RequestLine::new(Method::Reqmod, "icap://icap.test/request").unwrap(),
            &[Header::new("Host", b"icap.test").unwrap()],
            request,
            None,
        )
        .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 8];
        let icap = request.icap().parse_head(&mut slots).unwrap();
        assert_eq!(
            icap.header(header::PROXY_AUTHORIZATION).unwrap().as_bytes(),
            Some(b"Basic request-secret".as_slice()),
        );
        let encapsulated = Encapsulated::parse(request.icap().encapsulated().unwrap()).unwrap();
        let headers = encapsulated.request().unwrap().headers();
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("x-hop"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("proxy-authorization"));

        let response = HttpResponse::builder()
            .status(407)
            .header("Connection", "x-hop")
            .header("X-Hop", "remove")
            .header("Proxy-Authenticate", "Basic realm=icap")
            .body(Body::empty())
            .unwrap();
        let response = OutgoingResponse::from_http_response(
            MethodKind::Respmod,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &[Header::new(header::ISTAG, b"\"rama-test\"").unwrap()],
            response,
        )
        .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 8];
        let icap = response.response().parse_head(&mut slots).unwrap();
        assert_eq!(
            icap.header(header::PROXY_AUTHENTICATE).unwrap().as_bytes(),
            Some(b"Basic realm=icap".as_slice()),
        );
        let encapsulated =
            Encapsulated::parse(response.response().encapsulated().unwrap()).unwrap();
        let headers = encapsulated.response().unwrap().headers();
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("x-hop"));
        assert!(!headers.contains_key("proxy-authenticate"));
    }

    #[test]
    fn paired_encapsulation_strips_proxy_fields() {
        let request = HttpRequest::builder()
            .uri("/")
            .header("Proxy-Authorization", "Basic request-secret")
            .body(())
            .unwrap();
        let response = HttpResponse::builder()
            .status(407)
            .header("Proxy-Authenticate", "Basic realm=icap")
            .body(())
            .unwrap();

        let parts =
            Encapsulated::from_request_response(&request, &response, EncapsulatedKind::NullBody)
                .unwrap();
        let encapsulated = Encapsulated::parse(&parts).unwrap();

        assert!(
            !encapsulated
                .request()
                .unwrap()
                .headers()
                .contains_key("proxy-authorization")
        );
        assert!(
            !encapsulated
                .response()
                .unwrap()
                .headers()
                .contains_key("proxy-authenticate")
        );
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
            .inherit_base_extensions(&base);

        assert!(
            parsed
                .request()
                .unwrap()
                .extensions()
                .contains::<ConnectionMarker>()
        );
    }

    #[test]
    fn adapted_heads_retain_the_original_http_version() {
        let original = HttpRequest::builder()
            .version(rama_http_types::Version::HTTP_2)
            .body(())
            .unwrap();
        original.extensions().insert(ConnectionMarker);
        let parsed = Encapsulated {
            request: Some(HttpRequest::new(())),
            response: Some(HttpResponse::new(())),
            body_kind: EncapsulatedKind::NullBody,
        }
        .inherit_original_context(&OriginalHead::Request(original));

        assert_eq!(
            parsed.request().unwrap().version(),
            rama_http_types::Version::HTTP_2
        );
        assert_eq!(
            parsed.response().unwrap().version(),
            rama_http_types::Version::HTTP_2
        );
        assert!(
            parsed
                .response()
                .unwrap()
                .extensions()
                .contains::<ConnectionMarker>()
        );
    }

    #[tokio::test]
    async fn unchanged_request_echoes_an_unread_reqmod_message() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-end", HeaderValue::from_static("yes"));
        let request = incoming_reqmod(
            Body::from_frame_stream(stream::iter([
                Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"request body"))),
                Ok(Frame::trailers(trailers)),
            ])),
            EncapsulatedKind::RequestBody,
            None,
            b"",
        );
        let mut response = request
            .try_into_unchanged()
            .unwrap()
            .respond(TEST_SERVICE_TAG)
            .unwrap();

        assert_eq!(response.response().status(), StatusCode::OK);
        let parsed = Encapsulated::parse(response.response().encapsulated().unwrap()).unwrap();
        assert_eq!(parsed.request().unwrap().method(), "POST");
        assert_eq!(parsed.request().unwrap().headers()["x-original"], "yes");
        assert!(matches!(
            response.body_mut().next().await.unwrap().unwrap(),
            crate::server::BodyFrame::Data(data) if data == "request body"
        ));
        let crate::server::BodyFrame::Trailers(trailers) =
            response.body_mut().next().await.unwrap().unwrap()
        else {
            panic!("expected echoed HTTP trailers");
        };
        let trailers = HeadParser::new().parse_fields(trailers.as_bytes()).unwrap();
        assert_eq!(trailers["x-end"], "yes");
        assert!(response.body_mut().next().await.is_none());
    }

    #[test]
    fn unchanged_request_uses_preview_time_204() {
        let request = incoming_respmod(
            Body::from("response body"),
            EncapsulatedKind::ResponseBody,
            Some(Preview::new(4)),
            b"",
        );
        let response = request
            .try_into_unchanged()
            .unwrap()
            .respond(OPAQUE_SERVICE_TAG)
            .unwrap();

        assert_eq!(
            response.response().status(),
            StatusCode::NO_MODIFICATION_NEEDED
        );
        assert_eq!(
            response.response().service_tag(),
            Some(br#""rama \"test\"\\http""#.as_slice())
        );
    }

    #[test]
    fn direct_responses_encode_the_logical_service_tag() {
        let no_modification =
            incoming_respmod(Body::empty(), EncapsulatedKind::NullBody, None, b"204")
                .respond_no_modification(OPAQUE_SERVICE_TAG)
                .unwrap();
        assert_eq!(
            no_modification.response().service_tag(),
            Some(br#""rama \"test\"\\http""#.as_slice())
        );

        let method_not_allowed =
            incoming_respmod(Body::empty(), EncapsulatedKind::NullBody, None, b"")
                .respond_method_not_allowed(OPAQUE_SERVICE_TAG)
                .unwrap();
        assert_eq!(
            method_not_allowed.response().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            method_not_allowed.response().service_tag(),
            Some(br#""rama \"test\"\\http""#.as_slice())
        );
    }

    #[test]
    fn unchanged_request_uses_negotiated_204_after_mutable_access() {
        let mut request = incoming_respmod(
            Body::from("response body"),
            EncapsulatedKind::ResponseBody,
            None,
            b"204",
        );
        let _body = request.body_mut();
        let response = request
            .try_into_unchanged()
            .unwrap()
            .respond(TEST_SERVICE_TAG)
            .unwrap();

        assert_eq!(
            response.response().status(),
            StatusCode::NO_MODIFICATION_NEEDED
        );
    }

    #[tokio::test]
    async fn unavailable_unchanged_conversion_returns_the_request() {
        let mut request = incoming_respmod(
            Body::from("response body"),
            EncapsulatedKind::ResponseBody,
            None,
            b"",
        );
        let _body = request.body_mut();
        let request = request.try_into_unchanged().unwrap_err();
        let response = request.into_response().unwrap();

        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "response body"
        );
    }

    #[test]
    fn unchanged_null_body_can_echo_after_body_access() {
        let mut request = incoming_respmod(Body::empty(), EncapsulatedKind::NullBody, None, b"");
        let _body = request.body_mut();
        let response = request
            .try_into_unchanged()
            .unwrap()
            .respond(TEST_SERVICE_TAG)
            .unwrap();

        assert_eq!(response.response().status(), StatusCode::OK);
        let parsed = Encapsulated::parse(response.response().encapsulated().unwrap()).unwrap();
        assert_eq!(parsed.response().unwrap().status(), 200);
        assert!(!response.response().encapsulated().unwrap().has_body());
    }

    fn incoming_reqmod(
        body: Body,
        body_kind: EncapsulatedKind,
        preview: Option<Preview>,
        allow: &[u8],
    ) -> IncomingRequest {
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/upload")
            .header("host", "example.test")
            .header("x-original", "yes")
            .body(())
            .unwrap();
        let parts = Encapsulated::from_request(&request, body_kind).unwrap();
        let line = RequestLine::new(Method::Reqmod, "icap://icap.test/adapt").unwrap();
        let headers = [
            Header::new(header::HOST, b"icap.test").unwrap(),
            Header::new(header::ALLOW, allow).unwrap(),
        ];
        let icap = match preview {
            Some(preview) => IcapRequest::with_preview(line, &headers, parts, preview).unwrap(),
            None => IcapRequest::new(line, &headers, Some(parts)).unwrap(),
        };
        IncomingRequest {
            icap,
            encapsulated: Some(Encapsulated {
                request: Some(request),
                response: None,
                body_kind,
            }),
            body,
            extensions: Extensions::new(),
            encapsulated_exposed_mutably: false,
            body_exposed_mutably: false,
        }
    }

    fn incoming_respmod(
        body: Body,
        body_kind: EncapsulatedKind,
        preview: Option<Preview>,
        allow: &[u8],
    ) -> IncomingRequest {
        let request = HttpRequest::builder()
            .uri("/")
            .header("host", "example.test")
            .body(())
            .unwrap();
        let response = HttpResponse::builder().status(200).body(()).unwrap();
        let parts = Encapsulated::from_request_response(&request, &response, body_kind).unwrap();
        let line = RequestLine::new(Method::Respmod, "icap://icap.test/adapt").unwrap();
        let headers = [
            Header::new(header::HOST, b"icap.test").unwrap(),
            Header::new(header::ALLOW, allow).unwrap(),
        ];
        let icap = match preview {
            Some(preview) => IcapRequest::with_preview(line, &headers, parts, preview).unwrap(),
            None => IcapRequest::new(line, &headers, Some(parts)).unwrap(),
        };
        IncomingRequest {
            icap,
            encapsulated: Some(Encapsulated {
                request: Some(request),
                response: Some(response),
                body_kind,
            }),
            body,
            extensions: Extensions::new(),
            encapsulated_exposed_mutably: false,
            body_exposed_mutably: false,
        }
    }
}
