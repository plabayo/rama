//! HTTP/3 server stream admission and response sending.

use super::{
    Error, body,
    connection::{Config, Driver, Shared},
    control::Role,
    headers,
    quic::Writer,
    stream::{Phase, Reader},
};
use rama_core::{bytes::BytesMut, error::BoxError, extensions::ExtensionsRef};
use rama_http::{
    headers::{HeaderMapExt as _, Priority},
    io::upgrade::{self, Pending},
};
use rama_http_types::{
    Method, Request, Response, StatusCode,
    body::StreamingBody,
    proto::h3::{Code, FrameType, StreamType},
};
use rama_net::uri::Uri;
use rama_quic_proto::{VarInt, coding::Codec as _};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Accepts request streams; the accompanying driver must run concurrently.
pub struct Connection {
    connection: rama_quic::Connection,
    shared: Arc<Shared>,
    admission: Arc<Semaphore>,
    next_id: u64,
    draining: bool,
}

/// Prepare the server side of an established QUIC connection.
pub fn handshake(
    connection: rama_quic::Connection,
    config: Config,
) -> Result<(Connection, Driver), Error> {
    if connection.side() != rama_quic_proto::Side::Server {
        return Err(Error::connection(
            Code::H3_INTERNAL_ERROR,
            "server requires server-side QUIC connection",
        ));
    }
    config.settings()?;
    let admission = Arc::new(Semaphore::new(config.max_requests));
    let shared = Shared::from_connection(config, Role::Server, &connection)?;
    let driver = Driver::new(connection.clone(), shared.clone(), Role::Server);
    Ok((
        Connection {
            connection,
            shared,
            admission,
            next_id: 0,
            draining: false,
        },
        driver,
    ))
}

impl Connection {
    /// Stop admitting requests and notify the peer while accepted streams finish.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.shared.send_goaway(self.next_id)?;
        self.draining = true;
        Ok(())
    }

    /// Wait for accepted bodies, push senders and upgraded tunnels to be released,
    /// and for the queued GOAWAY to be handed to QUIC. Run the driver concurrently.
    pub async fn drained(&self) -> Result<(), Error> {
        let _all = self
            .admission
            .clone()
            .acquire_many_owned(self.shared.config.max_requests as u32)
            .await
            .map_err(|_error| Error::connection(Code::H3_INTERNAL_ERROR, "admission closed"))?;
        self.shared.control_flushed().await
    }

    /// Accept the next stream without waiting for its headers. Resolve each returned
    /// stream independently so a blocked QPACK section cannot hold up other requests.
    pub async fn accept(&mut self) -> Result<RequestStream, Error> {
        if self.draining {
            return Err(Error::connection(Code::H3_NO_ERROR, "server draining"));
        }
        let permit = tokio::select! {
            error = self.shared.failed() => return Err(error),
            error = self.connection.closed() => return Err(Error::from_transport(&error)),
            permit = self.admission.clone().acquire_owned() => Arc::new(permit.map_err(|_error| Error::connection(Code::H3_NO_ERROR, "server draining"))?),
        };
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|error| Error::from_transport(&error))?;
        let id = u64::from(send.id());
        self.next_id = self.next_id.max(id.saturating_add(4));
        self.shared.schedule.register(id, Priority::default())?;
        let mut reader = Reader::new(recv, self.shared.clone(), id);
        reader.abort = Some(send.abort_handle());
        reader.cancel_code = Code::H3_REQUEST_REJECTED;
        let mut writer = Writer::new(send);
        writer.cancel_code = Code::H3_REQUEST_REJECTED;
        Ok(RequestStream {
            connection: self.connection.clone(),
            reader,
            writer,
            permit,
            priority: super::priority::Lease {
                shared: self.shared.clone(),
                id,
            },
        })
    }
}

/// A newly accepted request stream, including its bounded admission permit.
pub struct RequestStream {
    connection: rama_quic::Connection,
    reader: Reader<rama_quic::RecvStream>,
    writer: Writer<rama_quic::SendStream>,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    priority: super::priority::Lease,
}

impl RequestStream {
    /// Decode and validate the request head, returning the common Incoming body.
    pub async fn resolve(
        mut self,
    ) -> Result<(Request<crate::body::Incoming>, SendResponse), Error> {
        let request = match self.reader.headers().await.and_then(headers::request) {
            Ok(request) => request,
            Err(error) => return Err(self.reader.reject(error)),
        };
        let remaining = headers::content_length(request.headers())?;
        let method = request.method().clone();
        let priority = request
            .headers()
            .typed_get::<Priority>()
            .unwrap_or_default();
        self.reader
            .shared
            .schedule
            .initial_priority(self.reader.id, priority);
        self.reader.phase = Phase::Body;
        self.reader.cancel_code = Code::H3_REQUEST_CANCELLED;
        self.writer.cancel_code = Code::H3_REQUEST_CANCELLED;
        let mut response = SendResponse {
            connection: self.connection,
            origin: request.uri().clone(),
            outgoing_push: None,
            connect: None,
            shared: self.reader.shared.clone(),
            id: self.reader.id,
            writer: self.writer,
            permit: self.permit.clone(),
            method,
            _priority: self.priority,
        };
        if response.method == Method::CONNECT {
            let (pending, upgrade) = upgrade::pending();
            request.extensions().insert(upgrade);
            response.connect = Some((self.reader, pending));
            return Ok((request.map(|()| crate::body::Incoming::empty()), response));
        }
        // RFC 9114 section 4.1: discarding an otherwise valid request body
        // asks the client to stop its upload without invalidating the response.
        self.reader.cancel_code = Code::H3_NO_ERROR;
        let incoming = body::Body::new(self.reader, remaining, self.permit);
        Ok((
            request.map(|()| crate::body::Incoming::h3(incoming)),
            response,
        ))
    }
}

/// Sends informational responses and a final response on one request stream.
pub struct SendResponse {
    connection: rama_quic::Connection,
    origin: Uri,
    outgoing_push: Option<super::push::Lease>,
    connect: Option<(Reader<rama_quic::RecvStream>, Pending)>,
    shared: Arc<Shared>,
    id: u64,
    writer: Writer<rama_quic::SendStream>,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    method: Method,
    _priority: super::priority::Lease,
}

impl SendResponse {
    async fn flush(&mut self, finish: bool) -> Result<(), Error> {
        let push = self.outgoing_push.as_ref().map(super::push::Lease::id);
        let shared = self.shared.clone();
        let write = std::future::poll_fn(|cx| {
            if finish {
                self.writer.poll_finish(cx)
            } else {
                self.writer.poll_flush(cx)
            }
        });
        if let Some(id) = push {
            tokio::select! { error = shared.push_cancelled(id) => Err(error), result = write => result }
        } else {
            write.await
        }
    }

    /// Wait for the peer to grant a push ID. Applications can apply their own deadline.
    pub async fn ready_for_push(&self) -> Result<(), Error> {
        loop {
            let changed = self.shared.push_ready.notified();
            let mut changed = std::pin::pin!(changed);
            changed.as_mut().enable();
            if let Some(error) = self.shared.error() {
                return Err(error);
            }
            if self
                .shared
                .pushes
                .lock()
                .exhausted(self.shared.config.max_pushes)
                || self.shared.goaway().is_some()
            {
                return Err(Error::stream(
                    Code::H3_REQUEST_REJECTED,
                    "push disabled or connection draining",
                ));
            }
            if self
                .shared
                .pushes
                .lock()
                .capacity(self.shared.config.max_pushes)
            {
                return Ok(());
            }
            changed.await;
        }
    }

    /// Promise a same-origin GET/HEAD and open its independently framed response stream.
    /// Both peers must opt into push. The configured quota is a lifetime bound.
    pub async fn push(&mut self, request: Request<()>) -> Result<Self, Error> {
        if !self.id.is_multiple_of(4)
            || !matches!(*request.method(), Method::GET | Method::HEAD)
            || request.uri().authority() != self.origin.authority()
            || request.uri().scheme() != self.origin.scheme()
            || headers::content_length(request.headers())?.is_some_and(|length| length != 0)
        {
            return Err(Error::stream(
                Code::H3_MESSAGE_ERROR,
                "push requires a same-origin cacheable request without content",
            ));
        }
        self.flush(false).await?;
        let goaway = self.shared.goaway();
        let id = self
            .shared
            .pushes
            .lock()
            .allocate(self.shared.config.max_pushes, goaway)?;
        let lease = super::push::Lease::new(self.shared.clone(), id);
        let encoded = headers::encode_request(&self.shared, self.id, &request)?;
        let mut promise = BytesMut::with_capacity(8 + encoded.len());
        VarInt::from_u64(id)
            .map_err(|_error| Error::stream(Code::H3_INTERNAL_ERROR, "invalid push ID"))?
            .encode(&mut promise);
        promise.extend_from_slice(&encoded);
        self.writer
            .queue(FrameType::PUSH_PROMISE, promise.freeze())?;
        std::future::poll_fn(|cx| {
            let mut pushes = self.shared.pushes.lock();
            let result = self.writer.poll_flush(cx);
            if !matches!(result, std::task::Poll::Ready(Err(_))) && self.writer.is_drained() {
                pushes.mark_promised(id);
            }
            result
        })
        .await?;
        let stream = tokio::select! {
            error = self.shared.push_cancelled(id) => return Err(error),
            result = self.connection.open_uni() => result.map_err(|_error| Error::connection(Code::H3_STREAM_CREATION_ERROR, "cannot open push stream"))?,
        };
        let stream_id = u64::from(stream.id());
        let mut prefix = BytesMut::with_capacity(9);
        VarInt::from_u32(StreamType::PUSH.value() as u32).encode(&mut prefix);
        VarInt::from_u64(id)
            .map_err(|_error| Error::stream(Code::H3_INTERNAL_ERROR, "invalid push ID"))?
            .encode(&mut prefix);
        let mut writer = Writer::with_prefix(stream, prefix.freeze());
        tokio::select! {
            error = self.shared.push_cancelled(id) => return Err(error),
            result = std::future::poll_fn(|cx| writer.poll_flush(cx)) => result?,
        }
        let priority =
            self.shared
                .pushes
                .lock()
                .attach_stream(id, stream_id, writer.abort_handle());
        self.shared.schedule.register(stream_id, priority)?;
        Ok(Self {
            connection: self.connection.clone(),
            origin: request.uri().clone(),
            outgoing_push: Some(lease),
            connect: None,
            shared: self.shared.clone(),
            id: stream_id,
            writer,
            permit: self.permit.clone(),
            method: request.method().clone(),
            _priority: super::priority::Lease {
                shared: self.shared.clone(),
                id: stream_id,
            },
        })
    }

    /// Override peer priority using application knowledge.
    pub fn set_priority(&mut self, priority: Priority) {
        self.shared.schedule.override_priority(self.id, priority);
    }

    /// Send a non-101 informational response before the final response.
    pub async fn send_informational(&mut self, response: Response<()>) -> Result<(), Error> {
        if !response.status().is_informational()
            || response.status() == StatusCode::SWITCHING_PROTOCOLS
        {
            return Err(Error::stream(
                Code::H3_INTERNAL_ERROR,
                "expected informational response",
            ));
        }
        self.flush(false).await?;
        let bytes = headers::encode_response(&self.shared, self.id, &response)?;
        self.writer.queue(FrameType::HEADERS, bytes)?;
        self.flush(false).await
    }

    /// Send final headers followed by the streaming response body and trailers.
    pub async fn send_response<B>(mut self, mut response: Response<B>) -> Result<(), Error>
    where
        B: StreamingBody + Unpin,
        B::Error: Into<BoxError>,
    {
        if response.status().is_informational() {
            return Err(Error::stream(
                Code::H3_INTERNAL_ERROR,
                "final response cannot be informational",
            ));
        }
        self.flush(false).await?;
        if response.status().is_success()
            && let Some((reader, pending)) = self.connect.take()
        {
            response
                .headers_mut()
                .remove(rama_http_types::header::CONTENT_LENGTH);
            let bytes = headers::encode_response(&self.shared, self.id, &response)?;
            self.writer.queue(FrameType::HEADERS, bytes)?;
            self.flush(false).await?;
            pending.fulfill(super::upgrade::new(
                reader,
                self.writer,
                self.permit,
                Some(self._priority),
            ));
            return Ok(());
        }
        if let Some((mut reader, _pending)) = self.connect.take() {
            reader.cancel_code = Code::H3_NO_ERROR;
        }
        let bodyless = self.method == Method::HEAD
            || response.status() == StatusCode::NOT_MODIFIED
            || response.status() == StatusCode::NO_CONTENT;
        self.flush(false).await?;
        let bytes = headers::encode_response(&self.shared, self.id, &response)?;
        self.writer.queue(FrameType::HEADERS, bytes)?;
        if bodyless {
            self.flush(true).await?;
            if let Some(push) = &mut self.outgoing_push {
                push.finished = true;
            }
            return Ok(());
        }
        let _permit = self.permit;
        let remaining = headers::content_length(response.headers())?;
        let (_, response_body) = response.into_parts();
        let shared = self.shared.clone();
        let result = body::send(self.writer, response_body, self.shared, self.id, remaining);
        if let Some(mut push) = self.outgoing_push {
            tokio::select! {
                error = shared.push_cancelled(push.id()) => Err(error),
                result = result => { if result.is_ok() { push.finished = true; } result }
            }
        } else {
            result.await
        }
    }
}
