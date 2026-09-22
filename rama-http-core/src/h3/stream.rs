//! Request-stream framing and message sequencing.

use super::{
    Error,
    client::ConnectionLifetime,
    connection::Shared,
    frame::{FrameDecoder, FrameEvent},
    quic::RecvStream,
};
use rama_core::bytes::Bytes;
use rama_http_types::proto::h3::{Code, FrameType, VarInt};
use rama_quic::StreamAbortHandle;
use std::{
    sync::Arc,
    task::{Context, Poll, ready},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Headers,
    Body,
    Trailers,
    Tunnel,
    Finished,
}

pub(crate) struct Reader<R: RecvStream> {
    pub(crate) stream: R,
    pub(crate) shared: Arc<Shared>,
    pub(crate) id: u64,
    pub(crate) phase: Phase,
    pub(crate) cancel_code: Code,
    pub(crate) abort: Option<StreamAbortHandle>,
    pub(crate) client_lifetime: Option<Arc<ConnectionLifetime>>,
    frames: FrameDecoder,
    pub(crate) push_id: Option<u64>,
    pub(crate) origin: Option<rama_net::uri::Uri>,
    push_cancelled: Option<std::pin::Pin<Box<dyn Future<Output = Error> + Send + Sync>>>,
    promise: Option<std::pin::Pin<Box<dyn Future<Output = Result<(), Error>> + Send + Sync>>>,
}

impl<R: RecvStream> Reader<R> {
    pub(crate) fn new(stream: R, shared: Arc<Shared>, id: u64) -> Self {
        let frames = FrameDecoder::with_input_limit(
            shared.config.max_frame_size,
            shared.config.read_chunk_size,
        )
        .with_header_events();
        Self {
            stream,
            shared,
            id,
            phase: Phase::Headers,
            cancel_code: Code::H3_REQUEST_CANCELLED,
            abort: None,
            client_lifetime: None,
            frames,
            origin: None,
            push_id: None,
            promise: None,
            push_cancelled: None,
        }
    }

    pub(crate) fn with_prefix(
        stream: R,
        shared: Arc<Shared>,
        id: u64,
        push_id: u64,
        mut prefix: Bytes,
    ) -> Result<Self, Error> {
        let cancel = shared.clone();
        let mut reader = Self::new(stream, shared, id);
        reader.push_id = Some(push_id);
        reader.push_cancelled = Some(Box::pin(
            async move { cancel.push_cancelled(push_id).await },
        ));
        reader.frames.feed_bytes(&mut prefix).map_err(|_error| {
            Error::connection(Code::H3_INTERNAL_ERROR, "invalid buffered stream prefix")
        })?;
        Ok(reader)
    }

    pub(crate) fn reject(&mut self, error: Error) -> Error {
        self.cancel_code = error.code();
        if let Some(abort) = &self.abort
            && let Ok(code) = VarInt::from_u64(error.code().value())
        {
            abort.abort(code);
        } else {
            self.stream.stop(error.code());
        }
        if error.scope() == super::qpack::ErrorScope::Connection {
            self.shared.fail(error);
        }
        error
    }

    pub(crate) fn poll_event(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<FrameEvent>, Error>> {
        match self.poll_event_inner(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.reject(error))),
            result => result,
        }
    }

    fn poll_event_inner(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<FrameEvent>, Error>> {
        if let Some(cancelled) = &mut self.push_cancelled
            && let Poll::Ready(error) = cancelled.as_mut().poll(cx)
        {
            return Poll::Ready(Err(error));
        }
        if self.phase == Phase::Finished {
            return Poll::Ready(Ok(None));
        }
        for _ in 0..super::cooperative::OPERATIONS_PER_QUANTUM {
            if let Some(promise) = &mut self.promise {
                ready!(promise.as_mut().poll(cx))?;
                self.promise = None;
            }
            if let Some(error) = self.shared.receive_error() {
                return Poll::Ready(Err(error));
            }
            let event = self.frames.poll().map_err(|e| {
                Error::from_frame(&e).unwrap_or(Error::connection(
                    Code::H3_INTERNAL_ERROR,
                    "frame input backpressure",
                ))
            })?;
            match event {
                Some(FrameEvent::Header(header)) => {
                    let ty = header.ty;
                    if ty.is_h2_reserved()
                        || matches!(
                            ty,
                            FrameType::PRIORITY_UPDATE_REQUEST
                                | FrameType::PRIORITY_UPDATE_PUSH
                                | FrameType::SETTINGS
                                | FrameType::GOAWAY
                                | FrameType::MAX_PUSH_ID
                                | FrameType::CANCEL_PUSH
                        )
                        || (ty == FrameType::DATA
                            && !matches!(self.phase, Phase::Body | Phase::Tunnel))
                        || (ty == FrameType::HEADERS
                            && matches!(self.phase, Phase::Trailers | Phase::Tunnel))
                        || (ty == FrameType::PUSH_PROMISE
                            && (self.phase == Phase::Tunnel
                                || self.shared.role == super::control::Role::Server
                                || !self.id.is_multiple_of(4)))
                    {
                        return Poll::Ready(Err(Error::connection(
                            Code::H3_FRAME_UNEXPECTED,
                            "frame forbidden in request stream phase",
                        )));
                    }
                }
                Some(FrameEvent::PushPromise {
                    push_id,
                    encoded_headers,
                }) => {
                    let shared = self.shared.clone();
                    let carrier = self.id;
                    let origin = self.origin.clone();
                    self.promise = Some(Box::pin(async move {
                        shared
                            .promise(carrier, push_id, encoded_headers, origin)
                            .await
                    }));
                }
                Some(FrameEvent::Ignored { .. }) => (),
                Some(event) => return Poll::Ready(Ok(Some(event))),
                None => {
                    if let Some(mut bytes) = ready!(
                        self.stream
                            .poll_chunk(cx, self.shared.config.read_chunk_size)
                    )? {
                        self.frames.feed_bytes(&mut bytes).map_err(|_error| {
                            Error::connection(Code::H3_INTERNAL_ERROR, "frame input not drained")
                        })?
                    } else {
                        if !self.frames.is_at_frame_boundary() {
                            return Poll::Ready(Err(Error::connection(
                                Code::H3_FRAME_ERROR,
                                "truncated frame",
                            )));
                        }
                        if self.phase == Phase::Headers {
                            return Poll::Ready(Err(Error::stream(
                                Code::H3_REQUEST_INCOMPLETE,
                                "stream ended before final headers",
                            )));
                        }
                        self.phase = Phase::Finished;
                        return Poll::Ready(Ok(None));
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    pub(crate) async fn headers(&mut self) -> Result<Vec<super::qpack::FieldPair>, Error> {
        let event = std::future::poll_fn(|cx| self.poll_event(cx)).await?;
        let Some(FrameEvent::Headers(bytes)) = event else {
            return Err(Error::connection(
                Code::H3_FRAME_UNEXPECTED,
                "expected field section",
            ));
        };
        let result = self
            .shared
            .decode_for_stream(self.id, self.push_id, bytes)
            .await;
        result.map_err(|error| self.reject(error))
    }
}

impl<R: RecvStream> Drop for Reader<R> {
    fn drop(&mut self) {
        if self.phase != Phase::Finished {
            self.stream.stop(self.cancel_code);
            self.shared.cancel(self.id);
        }
    }
}

/// Outbound field sections are generated from borrowed header values by QPACK.
pub(crate) fn encode_trailers(
    shared: &Shared,
    id: u64,
    headers: &rama_http_types::HeaderMap,
) -> Result<Bytes, Error> {
    super::headers::validate_regular(headers, true)?;
    shared.encode(
        id,
        headers
            .ordered_iter()
            .map(|(name, value)| super::qpack::EncodeField::from_header(name, value)),
    )
}
