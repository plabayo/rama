use core::{
    fmt,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use std::{io, sync::Arc};

use parking_lot::Mutex;
use rama_core::{
    bytes::Bytes,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef},
    futures::{Stream, StreamExt as _, stream, task::AtomicWaker},
};
use rama_utils::{collections::smallvec::SmallVec, str::cmp_ignore_ascii_case};
use tokio::sync::mpsc;
#[cfg(feature = "http")]
use tokio_util::sync::PollSender;

use crate::{
    byte_sets::comma_separated_items,
    codec::{EncodeError, Header, ResponseLine},
    io::{BodyEnd, Error},
    message::{BuildError, EncapsulatedParts, Request, Response, TrailerBlock},
    proto::{MethodKind, Preview, StatusCode, header, is_token},
};

type BodyResult<T> = Result<T, BodyError>;

#[derive(Clone, Copy)]
pub(super) enum BodyCommand {
    Next,
    Continue,
}

pub(super) enum BodyReply {
    Data {
        data: Option<Bytes>,
        end: Option<BodyEnd>,
        trailers: Option<TrailerBlock>,
    },
    Continued,
}

// An incoming body permits one outstanding command. Reuse one reply slot for
// the transaction so each body frame does not allocate its own oneshot.
struct BodyReplyShared {
    reply: Mutex<Option<BodyResult<BodyReply>>>,
    waker: AtomicWaker,
    driver_closed: AtomicBool,
    receiver_closed: AtomicBool,
}

pub(super) struct BodyReplySender {
    shared: Arc<BodyReplyShared>,
}

pub(super) enum BodyReplySendError {
    ReceiverClosed,
    SlotOccupied,
}

impl BodyReplySender {
    pub(super) fn send(&self, reply: BodyResult<BodyReply>) -> Result<(), BodyReplySendError> {
        if self.is_closed() {
            return Err(BodyReplySendError::ReceiverClosed);
        }
        let mut slot = self.shared.reply.lock();
        if self.shared.receiver_closed.load(Ordering::Acquire) {
            return Err(BodyReplySendError::ReceiverClosed);
        }
        debug_assert!(slot.is_none(), "body reply slot is still occupied");
        if slot.is_some() {
            return Err(BodyReplySendError::SlotOccupied);
        }
        *slot = Some(reply);
        drop(slot);
        self.shared.waker.wake();
        Ok(())
    }

    pub(super) fn is_closed(&self) -> bool {
        self.shared.receiver_closed.load(Ordering::Acquire)
    }
}

impl Drop for BodyReplySender {
    fn drop(&mut self) {
        self.shared.driver_closed.store(true, Ordering::Release);
        self.shared.waker.wake();
    }
}

pub(super) struct BodyReplyReceiver {
    shared: Arc<BodyReplyShared>,
}

impl BodyReplyReceiver {
    async fn receive(&self) -> BodyResult<BodyReply> {
        std::future::poll_fn(|cx| self.poll_receive(cx)).await
    }

    fn poll_receive(&self, cx: &Context<'_>) -> Poll<BodyResult<BodyReply>> {
        if let Some(reply) = self.shared.reply.lock().take() {
            return Poll::Ready(reply);
        }
        if self.shared.driver_closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(BodyError::driver_closed()));
        }

        self.shared.waker.register(cx.waker());

        if let Some(reply) = self.shared.reply.lock().take() {
            Poll::Ready(reply)
        } else if self.shared.driver_closed.load(Ordering::Acquire) {
            Poll::Ready(Err(BodyError::driver_closed()))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for BodyReplyReceiver {
    fn drop(&mut self) {
        self.shared.receiver_closed.store(true, Ordering::Release);
        self.shared.reply.lock().take();
    }
}

pub(super) fn body_reply_channel() -> (BodyReplySender, BodyReplyReceiver) {
    let shared = Arc::new(BodyReplyShared {
        reply: Mutex::new(None),
        waker: AtomicWaker::new(),
        driver_closed: AtomicBool::new(false),
        receiver_closed: AtomicBool::new(false),
    });
    (
        BodyReplySender {
            shared: Arc::clone(&shared),
        },
        BodyReplyReceiver { shared },
    )
}

#[derive(Clone, Copy)]
enum PendingCommand {
    Next,
    Continue,
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
    replies: BodyReplyReceiver,
    pending: Option<PendingCommand>,
    end: Option<BodyEnd>,
    trailers: Option<TrailerBlock>,
    #[cfg(feature = "http")]
    trailers_emitted: bool,
}

impl IncomingBody {
    pub(super) fn new(
        commands: mpsc::Sender<BodyCommand>,
        replies: BodyReplyReceiver,
        has_body: bool,
    ) -> Self {
        Self {
            #[cfg(feature = "http")]
            commands: PollSender::new(commands),
            #[cfg(not(feature = "http"))]
            commands,
            replies,
            pending: None,
            end: (!has_body).then_some(BodyEnd::Complete),
            trailers: None,
            #[cfg(feature = "http")]
            trailers_emitted: false,
        }
    }

    /// Read the next zero-copy request-body data segment.
    pub async fn next_data(&mut self) -> BodyResult<Option<Bytes>> {
        if matches!(self.pending, Some(PendingCommand::Continue)) {
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
            #[cfg(feature = "http")]
            self.commands
                .send_item(BodyCommand::Next)
                .map_err(|_error| BodyError::driver_closed())?;
            #[cfg(not(feature = "http"))]
            permit.send(BodyCommand::Next);
            self.pending = Some(PendingCommand::Next);
        }
        let result = if matches!(self.pending, Some(PendingCommand::Next)) {
            self.replies.receive().await
        } else {
            return Err(BodyError::invalid_state(
                "request driver lost its pending body read",
            ));
        };
        self.pending = None;
        match result? {
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
        if matches!(self.pending, Some(PendingCommand::Next)) {
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
            #[cfg(feature = "http")]
            self.commands
                .send_item(BodyCommand::Continue)
                .map_err(|_error| BodyError::driver_closed())?;
            #[cfg(not(feature = "http"))]
            permit.send(BodyCommand::Continue);
            self.pending = Some(PendingCommand::Continue);
        }
        let result = if matches!(self.pending, Some(PendingCommand::Continue)) {
            self.replies.receive().await
        } else {
            return Err(BodyError::invalid_state(
                "request driver lost its pending Preview continuation",
            ));
        };
        self.pending = None;
        match result? {
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
            if let Some(pending) = self.pending {
                let reading = matches!(pending, PendingCommand::Next);
                let reply = match self.replies.poll_receive(cx) {
                    Poll::Ready(result) => result,
                    Poll::Pending => return Poll::Pending,
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
                    if self.commands.send_item(BodyCommand::Continue).is_err() {
                        return Poll::Ready(Some(Err(BodyError::driver_closed())));
                    }
                    self.pending = Some(PendingCommand::Continue);
                }
                None => {
                    match self.commands.poll_reserve(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(_error)) => {
                            return Poll::Ready(Some(Err(BodyError::driver_closed())));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                    if self.commands.send_item(BodyCommand::Next).is_err() {
                        return Poll::Ready(Some(Err(BodyError::driver_closed())));
                    }
                    self.pending = Some(PendingCommand::Next);
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
    /// A complete negotiated outer ICAP trailer block.
    IcapTrailers(TrailerBlock),
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

    /// Construct a negotiated outer ICAP trailers frame.
    #[must_use]
    pub const fn icap_trailers(trailers: TrailerBlock) -> Self {
        Self::IcapTrailers(trailers)
    }
}

impl fmt::Debug for BodyFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(data) => f.debug_struct("Data").field("len", &data.len()).finish(),
            Self::Trailers(trailers) => f.debug_tuple("Trailers").field(trailers).finish(),
            Self::IcapTrailers(trailers) => f.debug_tuple("IcapTrailers").field(trailers).finish(),
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
#[derive(Clone, Copy)]
pub struct OptionsResponse<'a> {
    service_tag: &'a [u8],
    methods: &'a [u8],
    service: Option<&'a [u8]>,
    service_id: Option<&'a [u8]>,
    preview: Option<Preview>,
    allow_204: bool,
    allow_206: bool,
    allow_extensions: Option<&'a [u8]>,
    transfer_preview: Option<&'a [u8]>,
    transfer_ignore: Option<&'a [u8]>,
    transfer_complete: Option<&'a [u8]>,
    options_ttl: Option<u64>,
    max_connections: Option<u64>,
    date: Option<&'a [u8]>,
    opt_body_type: Option<&'a [u8]>,
    opt_body: Option<&'a [u8]>,
}

impl fmt::Debug for OptionsResponse<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OptionsResponse")
            .field("has_service", &self.service.is_some())
            .field("has_service_id", &self.service_id.is_some())
            .field("preview", &self.preview)
            .field("allow_204", &self.allow_204)
            .field("allow_206", &self.allow_206)
            .field(
                "has_transfer_policy",
                &(self.transfer_preview.is_some()
                    || self.transfer_ignore.is_some()
                    || self.transfer_complete.is_some()),
            )
            .field("options_ttl", &self.options_ttl)
            .field("max_connections", &self.max_connections)
            .field("opt_body_len", &self.opt_body.map(<[u8]>::len))
            .finish_non_exhaustive()
    }
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
            service_id: None,
            preview: None,
            allow_204: false,
            allow_206: false,
            allow_extensions: None,
            transfer_preview: None,
            transfer_ignore: None,
            transfer_complete: None,
            options_ttl: None,
            max_connections: None,
            date: None,
            opt_body_type: None,
            opt_body: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the optional opaque service identifier.
        pub fn service_id(
            mut self,
            service_id: &'a (impl AsRef<[u8]> + ?Sized),
        ) -> Self {
            self.service_id = Some(service_id.as_ref());
            self
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
        ///
        /// RFC negotiation requires the OPTIONS request to offer 206. Pass
        /// `false` when the current request did not offer it.
        pub const fn allow_206(mut self, allow: bool) -> Self {
            self.allow_206 = allow;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set additional comma-separated `Allow` feature tokens.
        ///
        /// For example, `trailers` advertises the ICAP trailers extension.
        /// The managed `204` and `206` tokens are rejected; use their
        /// dedicated setters so negotiation cannot be bypassed.
        pub fn allow_extensions(
            mut self,
            extensions: &'a (impl AsRef<[u8]> + ?Sized),
        ) -> Self {
            self.allow_extensions = Some(extensions.as_ref());
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
            self.transfer_preview = if enabled { Some(b"*") } else { None };
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `Transfer-Preview` extension list.
        pub fn transfer_preview(
            mut self,
            extensions: &'a (impl AsRef<[u8]> + ?Sized),
        ) -> Self {
            self.transfer_preview = Some(extensions.as_ref());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `Transfer-Ignore` extension list.
        pub fn transfer_ignore(
            mut self,
            extensions: &'a (impl AsRef<[u8]> + ?Sized),
        ) -> Self {
            self.transfer_ignore = Some(extensions.as_ref());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `Transfer-Complete` extension list.
        pub fn transfer_complete(
            mut self,
            extensions: &'a (impl AsRef<[u8]> + ?Sized),
        ) -> Self {
            self.transfer_complete = Some(extensions.as_ref());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the OPTIONS freshness lifetime in seconds.
        pub const fn options_ttl(mut self, seconds: u64) -> Self {
            self.options_ttl = Some(seconds);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Advertise a maximum connection count.
        pub const fn max_connections(mut self, count: u64) -> Self {
            self.max_connections = Some(count);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the optional server `Date` field value.
        pub fn date(
            mut self,
            date: &'a (impl AsRef<[u8]> + ?Sized),
        ) -> Self {
            self.date = Some(date.as_ref());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set an opaque OPTIONS body and its required type token.
        pub fn opt_body(
            mut self,
            body_type: &'a (impl AsRef<[u8]> + ?Sized),
            body: &'a (impl AsRef<[u8]> + ?Sized),
        ) -> Self {
            self.opt_body_type = Some(body_type.as_ref());
            self.opt_body = Some(body.as_ref());
            self
        }
    }

    /// Build the complete OPTIONS response.
    pub fn build(self) -> Result<OutgoingResponse, BuildError> {
        let allow_extensions = sorted_token_list(self.allow_extensions)?;
        let transfer_preview = sorted_token_list(self.transfer_preview)?;
        let transfer_ignore = sorted_token_list(self.transfer_ignore)?;
        let transfer_complete = sorted_token_list(self.transfer_complete)?;
        let has_transfer_policy = self.transfer_preview.is_some()
            || self.transfer_ignore.is_some()
            || self.transfer_complete.is_some();
        let wildcard_count = [&transfer_preview, &transfer_ignore, &transfer_complete]
            .into_iter()
            .flatten()
            .filter(|token| **token == b"*")
            .count();
        if self.opt_body_type.is_some_and(|value| !is_token(value))
            || allow_extensions.iter().any(|token| {
                token.eq_ignore_ascii_case(b"204") || token.eq_ignore_ascii_case(b"206")
            })
            || (self.transfer_preview.is_some() && self.preview.is_none())
            || (has_transfer_policy && wildcard_count != 1)
            || sorted_token_lists_overlap(&transfer_preview, &transfer_ignore)
            || sorted_token_lists_overlap(&transfer_preview, &transfer_complete)
            || sorted_token_lists_overlap(&transfer_ignore, &transfer_complete)
        {
            return Err(BuildError::from(EncodeError::InvalidInput));
        }
        let mut allow = SmallVec::<[u8; 64]>::new();
        for feature in [
            self.allow_204.then_some(b"204".as_slice()),
            self.allow_206.then_some(b"206".as_slice()),
        ]
        .into_iter()
        .flatten()
        .chain(allow_extensions.iter().copied())
        {
            if !allow.is_empty() {
                allow.extend_from_slice(b", ");
            }
            allow.extend_from_slice(feature);
        }
        let mut preview_buffer = itoa::Buffer::new();
        let mut ttl_buffer = itoa::Buffer::new();
        let mut max_connections_buffer = itoa::Buffer::new();
        let mut fields = SmallVec::<[Header<'_>; 16]>::new();
        fields.push(Header::new(header::METHODS, self.methods)?);
        if let Some(service) = self.service {
            fields.push(Header::new(header::SERVICE, service)?);
        }
        if let Some(service_id) = self.service_id {
            fields.push(Header::new(header::SERVICE_ID, service_id)?);
        }
        fields.push(Header::new(header::ISTAG, self.service_tag)?);
        if let Some(preview) = self.preview {
            fields.push(Header::new(
                header::PREVIEW,
                preview_buffer.format(preview.as_u64()).as_bytes(),
            )?);
        }
        if !allow.is_empty() {
            fields.push(Header::new(header::ALLOW, allow.as_slice())?);
        }
        if let Some(value) = self.transfer_preview {
            fields.push(Header::new(header::TRANSFER_PREVIEW, value)?);
        }
        if let Some(value) = self.transfer_ignore {
            fields.push(Header::new(header::TRANSFER_IGNORE, value)?);
        }
        if let Some(value) = self.transfer_complete {
            fields.push(Header::new(header::TRANSFER_COMPLETE, value)?);
        }
        if let Some(ttl) = self.options_ttl {
            fields.push(Header::new(
                header::OPTIONS_TTL,
                ttl_buffer.format(ttl).as_bytes(),
            )?);
        }
        if let Some(max_connections) = self.max_connections {
            fields.push(Header::new(
                header::MAX_CONNECTIONS,
                max_connections_buffer.format(max_connections).as_bytes(),
            )?);
        }
        if let Some(date) = self.date {
            fields.push(Header::new(header::DATE, date)?);
        }
        if let Some(body_type) = self.opt_body_type {
            fields.push(Header::new(header::OPT_BODY_TYPE, body_type)?);
        }
        let encapsulated = if self.opt_body.is_some() {
            EncapsulatedParts::new(None, None, crate::proto::EncapsulatedKind::OptionsBody)?
        } else {
            EncapsulatedParts::null()
        };
        let response = Response::new(
            MethodKind::Options,
            ResponseLine::new(StatusCode::OK, b"OK")
                .map_err(|_error| BuildError::from(EncodeError::InvalidInput))?,
            &fields,
            Some(encapsulated),
        )?;
        Ok(match self.opt_body {
            Some(body) => OutgoingResponse::new(response, Bytes::copy_from_slice(body)),
            None => OutgoingResponse::without_body(response),
        })
    }
}

fn sorted_token_list(value: Option<&[u8]>) -> Result<SmallVec<[&[u8]; 8]>, BuildError> {
    let mut tokens = SmallVec::<[&[u8]; 8]>::new();
    if let Some(value) = value {
        for token in comma_separated_items(value) {
            if token.is_empty() || !is_token(token) {
                return Err(BuildError::from(EncodeError::InvalidInput));
            }
            tokens.push(token);
        }
    }
    tokens.sort_unstable_by(|left, right| {
        cmp_ignore_ascii_case(left, right).then_with(|| left.cmp(right))
    });
    tokens.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    Ok(tokens)
}

fn sorted_token_lists_overlap(first: &[&[u8]], second: &[&[u8]]) -> bool {
    let (mut first_index, mut second_index) = (0, 0);
    while let (Some(first), Some(second)) = (first.get(first_index), second.get(second_index)) {
        if *first == b"*" {
            first_index += 1;
            continue;
        }
        if *second == b"*" {
            second_index += 1;
            continue;
        }
        match cmp_ignore_ascii_case(first, second) {
            core::cmp::Ordering::Less => first_index += 1,
            core::cmp::Ordering::Greater => second_index += 1,
            core::cmp::Ordering::Equal => return true,
        }
    }
    false
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
            .with_service_id("rama")
            .with_preview(Preview::new(1024))
            .with_allow_204(true)
            .with_allow_206(true)
            .with_allow_extensions("trailers")
            .with_transfer_preview_all(true)
            .with_options_ttl(3600)
            .with_max_connections(64)
            .with_date("Wed, 20 Aug 2026 12:00:00 GMT")
            .build()
            .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 16];
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
            Some(b"204, 206, trailers".as_slice())
        );
        assert_eq!(
            head.header(header::TRANSFER_PREVIEW).unwrap().as_bytes(),
            Some(b"*".as_slice())
        );
        assert_eq!(
            head.header(header::SERVICE_ID).unwrap().as_bytes(),
            Some(b"rama".as_slice())
        );
        assert_eq!(
            head.header(header::OPTIONS_TTL).unwrap().as_bytes(),
            Some(b"3600".as_slice())
        );
        assert_eq!(
            head.header(header::MAX_CONNECTIONS).unwrap().as_bytes(),
            Some(b"64".as_slice())
        );
    }

    #[tokio::test]
    async fn options_response_streams_a_typed_opt_body() {
        use rama_core::futures::StreamExt as _;

        let builder = OptionsResponse::new("\"rama-test\"", "RESPMOD")
            .with_opt_body("opaque", "capabilities");
        assert!(!format!("{builder:?}").contains("capabilities"));
        let response = builder.build().unwrap();
        assert_eq!(
            response.response().encapsulated().unwrap().body_kind(),
            crate::proto::EncapsulatedKind::OptionsBody
        );
        let mut slots = [HeaderSlot::EMPTY; 8];
        let head = response.response().parse_head(&mut slots).unwrap();
        assert_eq!(
            head.header(header::OPT_BODY_TYPE).unwrap().as_bytes(),
            Some(b"opaque".as_slice())
        );
        let (_response, mut body, _end, _extensions) = response.into_parts();
        let BodyFrame::Data(data) = body.next().await.unwrap().unwrap() else {
            panic!("OPTIONS body data expected");
        };
        assert_eq!(data, Bytes::from_static(b"capabilities"));
        assert!(body.next().await.is_none());
    }

    #[test]
    fn options_response_rejects_ambiguous_capability_lists() {
        OptionsResponse::new("\"rama-test\"", "RESPMOD")
            .with_preview(Preview::new(1024))
            .with_transfer_preview("jpg, *")
            .with_transfer_ignore("JPG")
            .build()
            .unwrap_err();
        OptionsResponse::new("\"rama-test\"", "RESPMOD")
            .with_transfer_preview("*")
            .build()
            .unwrap_err();
        OptionsResponse::new("\"rama-test\"", "RESPMOD")
            .with_opt_body("not a token", "body")
            .build()
            .unwrap_err();
        for extensions in ["204", "trailers, 206"] {
            OptionsResponse::new("\"rama-test\"", "RESPMOD")
                .with_allow_extensions(extensions)
                .build()
                .unwrap_err();
        }
        OptionsResponse::new("\"rama-test\"", "RESPMOD")
            .with_transfer_complete("zip")
            .build()
            .unwrap_err();
    }

    #[test]
    fn options_response_canonicalizes_allow_extension_tokens() {
        let response = OptionsResponse::new("\"rama-test\"", "RESPMOD")
            .with_allow_204(true)
            .with_allow_extensions("trailers, X-TRACE, TRAILERS")
            .build()
            .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 8];
        let head = response.response().parse_head(&mut slots).unwrap();
        assert_eq!(
            head.header(header::ALLOW).unwrap().as_bytes(),
            Some(b"204, TRAILERS, X-TRACE".as_slice())
        );
    }
}
