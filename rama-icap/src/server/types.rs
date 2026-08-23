use core::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};
use std::{io, sync::Arc};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef},
    futures::{Stream, StreamExt as _, stream},
};
use rama_utils::collections::smallvec::SmallVec;
use tokio::sync::{mpsc, oneshot};
#[cfg(feature = "http")]
use tokio_util::sync::PollSender;

use crate::{
    codec::{EncodeError, Header, ResponseLine},
    io::{BodyEnd, Error},
    message::{BuildError, EncapsulatedParts, Request, Response, TrailerBlock},
    proto::{MethodKind, Preview, StatusCode, header},
};

type BodyResult<T> = Result<T, BodyError>;
type BodyReplySender = oneshot::Sender<BodyResult<BodyReply>>;

pub(super) enum BodyCommand {
    Next(BodyReplySender),
    Continue(BodyReplySender),
}

impl BodyCommand {
    pub(super) fn is_abandoned(&self) -> bool {
        match self {
            Self::Next(reply) | Self::Continue(reply) => reply.is_closed(),
        }
    }
}

pub(super) enum BodyReply {
    Data {
        data: Option<Bytes>,
        end: Option<BodyEnd>,
        trailers: Option<TrailerBlock>,
    },
    Continued,
}

enum PendingCommand {
    Next(oneshot::Receiver<BodyResult<BodyReply>>),
    Continue(oneshot::Receiver<BodyResult<BodyReply>>),
}

#[cfg(feature = "http")]
type CommandSender = PollSender<BodyCommand>;
#[cfg(not(feature = "http"))]
type CommandSender = mpsc::Sender<BodyCommand>;

/// An owned ICAP request dispatched by [`Server`](super::Server).
///
/// Its metadata and body handle are lifetime-independent so ordinary Rama
/// [`Service`](rama_core::Service) layers can wrap the request service. Entity
/// bytes remain bounded, backpressured, and streaming through [`IncomingBody`].
pub struct IncomingRequest {
    request: Request,
    body: IncomingBody,
    extensions: Extensions,
}

impl IncomingRequest {
    pub(super) fn new(request: Request, body: IncomingBody, extensions: Extensions) -> Self {
        Self {
            request,
            body,
            extensions,
        }
    }

    /// Return the owned ICAP request metadata and encapsulated HTTP heads.
    #[must_use]
    pub const fn request(&self) -> &Request {
        &self.request
    }

    /// Return the streaming request body.
    #[must_use]
    pub const fn body(&self) -> &IncomingBody {
        &self.body
    }

    /// Return the mutable streaming request body.
    #[must_use]
    pub const fn body_mut(&mut self) -> &mut IncomingBody {
        &mut self.body
    }

    /// Split the request into its protocol parts.
    pub fn into_parts(self) -> (Request, IncomingBody, Extensions) {
        (self.request, self.body, self.extensions)
    }
}

impl ExtensionsRef for IncomingRequest {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl fmt::Debug for IncomingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingRequest")
            .field("request", &self.request)
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

/// Backpressured, zero-copy stream of one inbound ICAP entity body.
///
/// [`next_data`](Self::next_data) yields ref-counted [`Bytes`] chunks. A
/// Preview boundary returns `None` with [`body_end`](Self::body_end) equal to
/// [`BodyEnd::Preview`]; call [`continue_preview`](Self::continue_preview) to
/// resume the same body. Cancelled reads and continuation decisions remain
/// resumable on the next call of the same method.
pub struct IncomingBody {
    commands: CommandSender,
    pending: Option<PendingCommand>,
    end: Option<BodyEnd>,
    trailers: Option<TrailerBlock>,
    #[cfg(feature = "http")]
    trailers_emitted: bool,
}

impl IncomingBody {
    pub(super) fn new(commands: mpsc::Sender<BodyCommand>, has_body: bool) -> Self {
        Self {
            #[cfg(feature = "http")]
            commands: PollSender::new(commands),
            #[cfg(not(feature = "http"))]
            commands,
            pending: None,
            end: (!has_body).then_some(BodyEnd::Complete),
            trailers: None,
            #[cfg(feature = "http")]
            trailers_emitted: false,
        }
    }

    /// Read the next zero-copy request-body data segment.
    pub async fn next_data(&mut self) -> BodyResult<Option<Bytes>> {
        if matches!(self.pending, Some(PendingCommand::Continue(_))) {
            return Err(BodyError::invalid_state(
                "a cancelled Preview continuation must be resumed first",
            ));
        }
        if self.pending.is_none() && self.end.is_some() {
            return Ok(None);
        }
        if self.pending.is_none() {
            #[cfg(feature = "http")]
            std::future::poll_fn(|cx| self.commands.poll_reserve(cx))
                .await
                .map_err(|_error| BodyError::driver_closed())?;
            #[cfg(not(feature = "http"))]
            let permit = self
                .commands
                .reserve()
                .await
                .map_err(|_error| BodyError::driver_closed())?;
            let (sender, receiver) = oneshot::channel();
            #[cfg(feature = "http")]
            self.commands
                .send_item(BodyCommand::Next(sender))
                .map_err(|_error| BodyError::driver_closed())?;
            #[cfg(not(feature = "http"))]
            permit.send(BodyCommand::Next(sender));
            self.pending = Some(PendingCommand::Next(receiver));
        }
        let result = if let Some(PendingCommand::Next(receiver)) = self.pending.as_mut() {
            receiver.await.map_err(|_error| BodyError::driver_closed())
        } else {
            return Err(BodyError::invalid_state(
                "request driver lost its pending body read",
            ));
        };
        self.pending = None;
        match result?? {
            BodyReply::Data {
                data,
                end,
                trailers,
            } => {
                self.end = end;
                self.trailers = trailers;
                Ok(data)
            }
            BodyReply::Continued => Err(BodyError::invalid_state(
                "request driver returned an invalid body reply",
            )),
        }
    }

    /// Send 100 Continue after reaching an incomplete Preview boundary.
    pub async fn continue_preview(&mut self) -> BodyResult<()> {
        if matches!(self.pending, Some(PendingCommand::Next(_))) {
            return Err(BodyError::invalid_state(
                "a cancelled body read must be resumed first",
            ));
        }
        if self.pending.is_none() && self.end != Some(BodyEnd::Preview) {
            return Err(BodyError::invalid_state(
                "the ICAP request is not awaiting a Preview decision",
            ));
        }
        if self.pending.is_none() {
            #[cfg(feature = "http")]
            std::future::poll_fn(|cx| self.commands.poll_reserve(cx))
                .await
                .map_err(|_error| BodyError::driver_closed())?;
            #[cfg(not(feature = "http"))]
            let permit = self
                .commands
                .reserve()
                .await
                .map_err(|_error| BodyError::driver_closed())?;
            let (sender, receiver) = oneshot::channel();
            #[cfg(feature = "http")]
            self.commands
                .send_item(BodyCommand::Continue(sender))
                .map_err(|_error| BodyError::driver_closed())?;
            #[cfg(not(feature = "http"))]
            permit.send(BodyCommand::Continue(sender));
            self.pending = Some(PendingCommand::Continue(receiver));
        }
        let result = if let Some(PendingCommand::Continue(receiver)) = self.pending.as_mut() {
            receiver.await.map_err(|_error| BodyError::driver_closed())
        } else {
            return Err(BodyError::invalid_state(
                "request driver lost its pending Preview continuation",
            ));
        };
        self.pending = None;
        match result?? {
            BodyReply::Continued => {
                self.end = None;
                self.trailers = None;
                #[cfg(feature = "http")]
                {
                    self.trailers_emitted = false;
                }
                Ok(())
            }
            BodyReply::Data { .. } => Err(BodyError::invalid_state(
                "request driver returned an invalid Preview reply",
            )),
        }
    }

    /// Return the current terminal state of the body stream.
    #[must_use]
    pub const fn body_end(&self) -> Option<BodyEnd> {
        self.end
    }

    /// Return trailers from the completed body segment.
    #[must_use]
    pub const fn trailers(&self) -> Option<&TrailerBlock> {
        self.trailers.as_ref()
    }
}

#[cfg(feature = "http")]
impl Stream for IncomingBody {
    type Item = Result<rama_http_types::body::Frame<Bytes>, BodyError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(pending) = self.pending.as_mut() {
                let reading = matches!(pending, PendingCommand::Next(_));
                let reply = match pending {
                    PendingCommand::Next(receiver) | PendingCommand::Continue(receiver) => {
                        match Pin::new(receiver).poll(cx) {
                            Poll::Ready(Ok(result)) => result,
                            Poll::Ready(Err(_error)) => Err(BodyError::driver_closed()),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                };
                self.pending = None;
                match (reading, reply) {
                    (
                        true,
                        Ok(BodyReply::Data {
                            data,
                            end,
                            trailers,
                        }),
                    ) => {
                        self.end = end;
                        self.trailers = trailers;
                        if let Some(data) = data {
                            return Poll::Ready(Some(Ok(rama_http_types::body::Frame::data(data))));
                        }
                    }
                    (false, Ok(BodyReply::Continued)) => {
                        self.end = None;
                        self.trailers = None;
                        self.trailers_emitted = false;
                    }
                    (_, Ok(BodyReply::Data { .. } | BodyReply::Continued)) => {
                        return Poll::Ready(Some(Err(BodyError::invalid_state(
                            "request driver returned an invalid body reply",
                        ))));
                    }
                    (_, Err(error)) => return Poll::Ready(Some(Err(error))),
                }
                continue;
            }

            match self.end {
                Some(BodyEnd::Complete) => {
                    if self.trailers_emitted {
                        return Poll::Ready(None);
                    }
                    self.trailers_emitted = true;
                    let Some(trailers) = self.trailers.take() else {
                        return Poll::Ready(None);
                    };
                    let headers = match rama_http_types::proto::h1::head::HeadParser::new()
                        .parse_fields(trailers.as_bytes())
                    {
                        Ok(headers) => headers,
                        Err(error) => {
                            return Poll::Ready(Some(Err(BodyError(Arc::new(error)))));
                        }
                    };
                    if headers.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(rama_http_types::body::Frame::trailers(headers))));
                }
                Some(BodyEnd::PartialContent { .. }) => {
                    self.end = Some(BodyEnd::Complete);
                    self.trailers_emitted = true;
                    return Poll::Ready(Some(Err(BodyError::invalid_state(
                        "an ICAP request body cannot end with Partial Content",
                    ))));
                }
                Some(BodyEnd::Preview) => {
                    match self.commands.poll_reserve(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(_error)) => {
                            return Poll::Ready(Some(Err(BodyError::driver_closed())));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                    let (sender, receiver) = oneshot::channel();
                    if self
                        .commands
                        .send_item(BodyCommand::Continue(sender))
                        .is_err()
                    {
                        return Poll::Ready(Some(Err(BodyError::driver_closed())));
                    }
                    self.pending = Some(PendingCommand::Continue(receiver));
                }
                None => {
                    match self.commands.poll_reserve(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(_error)) => {
                            return Poll::Ready(Some(Err(BodyError::driver_closed())));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                    let (sender, receiver) = oneshot::channel();
                    if self.commands.send_item(BodyCommand::Next(sender)).is_err() {
                        return Poll::Ready(Some(Err(BodyError::driver_closed())));
                    }
                    self.pending = Some(PendingCommand::Next(receiver));
                }
            }
        }
    }
}

impl fmt::Debug for IncomingBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingBody")
            .field("read_pending", &self.pending.is_some())
            .field("end", &self.end)
            .field("has_trailers", &self.trailers.is_some())
            .finish()
    }
}

/// Cloneable error returned by an owned streaming request body.
#[derive(Clone)]
pub struct BodyError(Arc<dyn std::error::Error + Send + Sync>);

impl BodyError {
    pub(super) fn connection(error: Error) -> Self {
        Self(Arc::new(error))
    }

    fn driver_closed() -> Self {
        Self(Arc::new(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "ICAP request body driver closed",
        )))
    }

    pub(super) fn invalid_state(message: &'static str) -> Self {
        Self(Arc::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            message,
        )))
    }
}

impl fmt::Debug for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BodyError").field(&self.0).finish()
    }
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for BodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// One frame produced by an [`OutgoingBody`].
pub enum BodyFrame {
    /// Ref-counted entity-body data.
    Data(Bytes),
    /// A complete encapsulated HTTP trailer block.
    Trailers(TrailerBlock),
}

impl BodyFrame {
    /// Construct a data frame.
    #[must_use]
    pub fn data(data: impl Into<Bytes>) -> Self {
        Self::Data(data.into())
    }

    /// Construct a trailers frame.
    #[must_use]
    pub const fn trailers(trailers: TrailerBlock) -> Self {
        Self::Trailers(trailers)
    }
}

impl fmt::Debug for BodyFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(data) => f.debug_struct("Data").field("len", &data.len()).finish(),
            Self::Trailers(trailers) => f.debug_tuple("Trailers").field(trailers).finish(),
        }
    }
}

/// Type-erased streaming ICAP response body.
pub struct OutgoingBody(Pin<Box<dyn Stream<Item = Result<BodyFrame, BoxError>> + Send + 'static>>);

impl OutgoingBody {
    /// Construct an empty response body.
    #[must_use]
    pub fn empty() -> Self {
        Self::from_frames(stream::empty::<Result<BodyFrame, BoxError>>())
    }

    /// Construct one response-body data frame.
    #[must_use]
    pub fn from_bytes(data: Bytes) -> Self {
        if data.is_empty() {
            Self::empty()
        } else {
            Self::from_frames(stream::iter([Ok::<_, BoxError>(BodyFrame::Data(data))]))
        }
    }

    /// Wrap a stream of data and trailer frames.
    pub fn from_frames<S, E>(frames: S) -> Self
    where
        S: Stream<Item = Result<BodyFrame, E>> + Send + 'static,
        E: Into<BoxError> + 'static,
    {
        Self(Box::pin(frames.map(|result| result.map_err(Into::into))))
    }

    /// Wrap a stream of response-body data chunks.
    pub fn from_data_stream<S, E>(data: S) -> Self
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
        E: Into<BoxError> + 'static,
    {
        Self::from_frames(data.map(|result| result.map(BodyFrame::Data)))
    }
}

impl Default for OutgoingBody {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for OutgoingBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingBody").finish_non_exhaustive()
    }
}

impl Stream for OutgoingBody {
    type Item = Result<BodyFrame, BoxError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

impl From<Bytes> for OutgoingBody {
    fn from(value: Bytes) -> Self {
        Self::from_bytes(value)
    }
}

impl From<Vec<u8>> for OutgoingBody {
    fn from(value: Vec<u8>) -> Self {
        Self::from_bytes(value.into())
    }
}

impl From<&'static [u8]> for OutgoingBody {
    fn from(value: &'static [u8]) -> Self {
        Self::from_bytes(Bytes::from_static(value))
    }
}

impl From<String> for OutgoingBody {
    fn from(value: String) -> Self {
        Self::from_bytes(value.into())
    }
}

/// Terminal behavior after an [`OutgoingBody`] reaches the end of its stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutgoingBodyEnd {
    /// Finish the complete adapted body.
    Complete,
    /// Resume the original body at the supplied offset for a 206 response.
    UseOriginalBody(u64),
}

/// Builder for a standard ICAP OPTIONS response.
#[derive(Clone, Copy, Debug)]
pub struct OptionsResponse<'a> {
    service_tag: &'a [u8],
    methods: &'a [u8],
    service: Option<&'a [u8]>,
    preview: Option<Preview>,
    allow_204: bool,
    allow_206: bool,
    transfer_preview_all: bool,
}

impl<'a> OptionsResponse<'a> {
    /// Create an OPTIONS response with its required fields.
    ///
    /// Both fields are borrowed and may be supplied as text or bytes.
    #[must_use]
    pub fn new<ServiceTag, Methods>(service_tag: &'a ServiceTag, methods: &'a Methods) -> Self
    where
        ServiceTag: AsRef<[u8]> + ?Sized,
        Methods: AsRef<[u8]> + ?Sized,
    {
        Self {
            service_tag: service_tag.as_ref(),
            methods: methods.as_ref(),
            service: None,
            preview: None,
            allow_204: false,
            allow_206: false,
            transfer_preview_all: false,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the optional service description.
        pub fn service(
            mut self,
            service: &'a (impl AsRef<[u8]> + ?Sized),
        ) -> Self {
            self.service = Some(service.as_ref());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Advertise the maximum supported Preview size.
        pub const fn preview(mut self, preview: Preview) -> Self {
            self.preview = Some(preview);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Advertise support for 204 responses outside Preview.
        pub const fn allow_204(mut self, allow: bool) -> Self {
            self.allow_204 = allow;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Advertise support for the 206 Partial Content extension.
        pub const fn allow_206(mut self, allow: bool) -> Self {
            self.allow_206 = allow;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Advertise Preview as the default for every transfer type.
        ///
        /// This encodes `Transfer-Preview: *`. RFC 3507 defines `*` as the
        /// default for file extensions not named by another `Transfer-*`
        /// field.
        pub const fn transfer_preview_all(mut self, enabled: bool) -> Self {
            self.transfer_preview_all = enabled;
            self
        }
    }

    /// Build the complete OPTIONS response.
    pub fn build(self) -> Result<OutgoingResponse, BuildError> {
        let allow = match (self.allow_204, self.allow_206) {
            (true, true) => Some(b"204, 206".as_slice()),
            (true, false) => Some(b"204".as_slice()),
            (false, true) => Some(b"206".as_slice()),
            (false, false) => None,
        };
        let mut preview_buffer = itoa::Buffer::new();
        let mut fields = SmallVec::<[Header<'_>; 6]>::new();
        fields.push(Header::new(header::METHODS, self.methods)?);
        if let Some(service) = self.service {
            fields.push(Header::new(header::SERVICE, service)?);
        }
        fields.push(Header::new(header::ISTAG, self.service_tag)?);
        if let Some(preview) = self.preview {
            fields.push(Header::new(
                header::PREVIEW,
                preview_buffer.format(preview.as_u64()).as_bytes(),
            )?);
        }
        if let Some(allow) = allow {
            fields.push(Header::new(header::ALLOW, allow)?);
        }
        if self.transfer_preview_all {
            fields.push(Header::new(header::TRANSFER_PREVIEW, b"*")?);
        }
        let response = Response::new(
            MethodKind::Options,
            ResponseLine::new(StatusCode::OK, b"OK")
                .map_err(|_error| BuildError::from(EncodeError::InvalidInput))?,
            &fields,
            Some(EncapsulatedParts::null()),
        )?;
        Ok(OutgoingResponse::without_body(response))
    }
}

/// Owned streaming response returned by an ICAP request service.
pub struct OutgoingResponse {
    response: Response,
    body: OutgoingBody,
    body_end: OutgoingBodyEnd,
    extensions: Extensions,
}

impl OutgoingResponse {
    /// Construct a response with its streaming entity body.
    #[must_use]
    pub fn new(response: Response, body: impl Into<OutgoingBody>) -> Self {
        Self {
            response,
            body: body.into(),
            body_end: OutgoingBodyEnd::Complete,
            extensions: Extensions::new(),
        }
    }

    /// Construct a response without entity-body data.
    #[must_use]
    pub fn without_body(response: Response) -> Self {
        Self::new(response, OutgoingBody::empty())
    }

    rama_utils::macros::generate_set_and_with! {
        /// Finish a 206 response by resuming the original body at `offset`.
        pub fn use_original_body(mut self, offset: u64) -> Self {
            self.body_end = OutgoingBodyEnd::UseOriginalBody(offset);
            self
        }
    }

    /// Return the ICAP response metadata and encapsulated HTTP heads.
    #[must_use]
    pub const fn response(&self) -> &Response {
        &self.response
    }

    /// Return the streaming adapted response body.
    #[must_use]
    pub const fn body(&self) -> &OutgoingBody {
        &self.body
    }

    /// Return the mutable streaming adapted response body.
    #[must_use]
    pub const fn body_mut(&mut self) -> &mut OutgoingBody {
        &mut self.body
    }

    /// Return the configured response-body terminal behavior.
    #[must_use]
    pub const fn body_end(&self) -> OutgoingBodyEnd {
        self.body_end
    }

    /// Split the response into its protocol parts.
    pub fn into_parts(self) -> (Response, OutgoingBody, OutgoingBodyEnd, Extensions) {
        (self.response, self.body, self.body_end, self.extensions)
    }
}

impl ExtensionsRef for OutgoingResponse {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl fmt::Debug for OutgoingResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingResponse")
            .field("response", &self.response)
            .field("body", &self.body)
            .field("body_end", &self.body_end)
            .finish_non_exhaustive()
    }
}

impl From<Response> for OutgoingResponse {
    fn from(value: Response) -> Self {
        Self::without_body(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::codec::HeaderSlot;

    use super::*;

    #[test]
    fn options_response_builds_standard_fields() {
        let service_tag = String::from("\"rama-test\"");
        let methods = b"REQMOD, RESPMOD".to_vec();
        let service = String::from("Rama test service");
        let response = OptionsResponse::new(&service_tag, &methods)
            .with_service(&service)
            .with_preview(Preview::new(1024))
            .with_allow_204(true)
            .with_allow_206(true)
            .with_transfer_preview_all(true)
            .build()
            .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 8];
        let head = response.response().parse_head(&mut slots).unwrap();

        assert_eq!(head.line().status(), StatusCode::OK);
        assert_eq!(
            head.header(header::METHODS).unwrap().as_bytes(),
            Some(b"REQMOD, RESPMOD".as_slice())
        );
        assert_eq!(
            head.header(header::SERVICE).unwrap().as_bytes(),
            Some(b"Rama test service".as_slice())
        );
        assert_eq!(head.preview(), Some(Preview::new(1024)));
        assert_eq!(
            head.header(header::ALLOW).unwrap().as_bytes(),
            Some(b"204, 206".as_slice())
        );
        assert_eq!(
            head.header(header::TRANSFER_PREVIEW).unwrap().as_bytes(),
            Some(b"*".as_slice())
        );
    }
}
