use std::io::{Cursor, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::h2::SendStream;
use pin_project_lite::pin_project;
use rama_core::bytes::Buf;
use rama_core::error::BoxError;
use rama_core::telemetry::tracing::{debug, trace};
use rama_http::StreamingBody;
use rama_http_types::header::{
    CONNECTION, KEEP_ALIVE, PROXY_CONNECTION, TE, TRANSFER_ENCODING, UPGRADE,
};
use rama_http_types::{HeaderMap, HeaderName};
use std::task::ready;

pub(crate) mod ping;
pub(crate) mod upgrade;

pub(crate) mod client;
pub(crate) use self::client::ClientTask;

pub(crate) mod server;
pub(crate) use self::server::Server;

/// Default initial stream window size defined in HTTP2 spec.
pub(crate) const SPEC_WINDOW_SIZE: u32 = 65_535;

// List of connection headers from RFC 9110 Section 7.6.1
//
// TE headers are allowed in HTTP/2 requests as long as the value is "trailers", so they're
// tested separately.
static CONNECTION_HEADERS: [&HeaderName; 4] =
    [&KEEP_ALIVE, &PROXY_CONNECTION, &TRANSFER_ENCODING, &UPGRADE];

#[derive(Clone, Copy)]
enum MessageKind {
    Request,
    Response,
}

fn strip_connection_headers(headers: &mut HeaderMap, kind: MessageKind) {
    for header in CONNECTION_HEADERS {
        if headers.remove(header).is_some() {
            debug!("Connection header illegal in HTTP/2: {}", header.as_str());
        }
    }

    if matches!(kind, MessageKind::Request) {
        if headers
            .get(TE)
            .is_some_and(|te_header| te_header != "trailers")
        {
            debug!("TE headers not set to \"trailers\" are illegal in HTTP/2 requests");
            headers.remove(TE);
        }
    } else if headers.remove(TE).is_some() {
        debug!("TE headers illegal in HTTP/2 responses");
    }

    if let Some(header) = headers.remove(CONNECTION) {
        debug!(
            "Connection header illegal in HTTP/2: {}",
            CONNECTION.as_str()
        );

        // A `Connection` header may have a comma-separated list of names of other headers that
        // are meant for only this specific connection.
        //
        // Iterate these names and remove them as headers. Connection-specific headers are
        // forbidden in HTTP2, as that information has been moved into frame types of the h2
        // protocol.
        for name in header.as_bytes().split(|b| b == &b',') {
            match std::str::from_utf8(name.trim_ascii()) {
                Ok(name_str) => {
                    if headers.remove(name_str).is_some() {
                        debug!(
                            "removed header {name_str} as it was mentioned in connection header"
                        );
                    }
                }
                Err(err) => {
                    debug!("ignore non-utf8 header '{name:x?}' in conn header value: {err}")
                }
            }
        }
    }
}

// body adapters used by both Client and Server

pin_project! {
    pub(crate) struct PipeToSendStream<S>
    where
        S: StreamingBody,
    {
        body_tx: SendStream<SendBuf<S::Data>>,
        data_done: bool,
        // A data chunk that has been polled from the body but is still waiting
        // for stream-level capacity before it can be shipped. Stored here so
        // it survives across `Poll::Pending` returns from `poll_capacity`; if
        // we left the chunk in a local, it would be dropped on every repoll.
        buffered_data: Option<Peeked<S::Data>>,
        #[pin]
        stream: S,
    }
}

struct Peeked<D> {
    data: D,
    is_eos: bool,
}

impl<S> PipeToSendStream<S>
where
    S: StreamingBody,
{
    fn new(stream: S, tx: SendStream<SendBuf<S::Data>>) -> Self {
        Self {
            body_tx: tx,
            data_done: false,
            buffered_data: None,
            stream,
        }
    }

    fn send_reset(self: Pin<&mut Self>, reason: crate::h2::Reason) {
        self.project().body_tx.send_reset(reason);
    }
}

impl<S> Future for PipeToSendStream<S>
where
    S: StreamingBody,
    S::Error: Into<BoxError>,
{
    type Output = crate::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        loop {
            // Register for RST_STREAM notification while we wait for the next
            // body chunk or for send capacity, so the task wakes up if the
            // peer resets the stream.
            if let Poll::Ready(reason) = me
                .body_tx
                .poll_reset(cx)
                .map_err(crate::Error::new_body_write)?
            {
                debug!("stream received RST_STREAM: {:?}", reason);
                return Poll::Ready(Err(crate::Error::new_body_write(crate::h2::Error::from(
                    reason,
                ))));
            }

            // If a previously-polled chunk is still waiting for stream-level
            // send capacity, drive that to completion before touching the
            // body again.
            if me.buffered_data.is_some() {
                while me.body_tx.capacity() == 0 {
                    match ready!(me.body_tx.poll_capacity(cx)) {
                        Some(Ok(0)) => {}
                        Some(Ok(_)) => break,
                        Some(Err(e)) => return Poll::Ready(Err(crate::Error::new_body_write(e))),
                        None => {
                            // None means the stream is no longer in a
                            // streaming state, we either finished it
                            // somehow, or the remote reset us.
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )));
                        }
                    }
                }

                #[expect(clippy::expect_used, reason = "checked is_some above")]
                let peeked = me.buffered_data.take().expect("checked is_some above");
                let buf = SendBuf::Buf(peeked.data);
                me.body_tx
                    .send_data(buf, peeked.is_eos)
                    .map_err(crate::Error::new_body_write)?;

                if peeked.is_eos {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            // flow-control capacity. Reserving capacity speculatively (even a
            // single byte) pins that capacity on the connection-level window,
            // which can deadlock a second stream when talking to peers that
            // only emit WINDOW_UPDATE once their receive window is fully
            // exhausted. See hyper#4003.
            match ready!(me.stream.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => {
                    // NOTE: should we ever fork http crate we can make a more convenient API here,
                    // or perhaps we can try to first fix it upstream...
                    match frame.into_data() {
                        Ok(chunk) => {
                            let is_eos = me.stream.is_end_stream();
                            let len = chunk.remaining();
                            trace!("send body chunk: {} bytes, eos={}", len, is_eos);

                            if len == 0 {
                                // Zero-length data frames need no capacity; send
                                // them straight through so trailing empty frames
                                // (e.g. an explicit end-of-stream marker) are
                                // delivered.
                                let buf = SendBuf::Buf(chunk);
                                me.body_tx
                                    .send_data(buf, is_eos)
                                    .map_err(crate::Error::new_body_write)?;

                                if is_eos {
                                    return Poll::Ready(Ok(()));
                                }
                                continue;
                            }

                            // Reserve a minimal claim on the connection-level
                            // flow-control window rather than the whole chunk. The
                            // chunk is already in hand, so this still cannot pin
                            // capacity against a body that never produces data
                            // (hyper#4003), and h2 raises the request to the buffered
                            // length inside `send_data`, so the demand eventually
                            // signalled to the peer is unchanged. Claiming the full
                            // length up front instead makes every in-flight stream a
                            // heavyweight claimant while it waits, which is costly
                            // once the streams on a connection collectively demand
                            // more than the window the peer advertises. Stash the
                            // chunk in `self` so it survives the upcoming
                            // `poll_capacity` wait even if it returns `Poll::Pending`.
                            me.body_tx.reserve_capacity(1);
                            *me.buffered_data = Some(Peeked {
                                data: chunk,
                                is_eos,
                            });
                        }
                        Err(frame) => match frame.into_trailers() {
                            Ok(trailers) => {
                                // no more DATA, so give any capacity back
                                me.body_tx.reserve_capacity(0);
                                let trailers = filter_allowed_trailers(trailers);
                                me.body_tx
                                    .send_trailers(trailers)
                                    .map_err(crate::Error::new_body_write)?;
                                return Poll::Ready(Ok(()));
                            }
                            Err(_) => {
                                trace!("discarding unknown frame");
                            }
                        },
                    }
                }
                Some(Err(e)) => return Poll::Ready(Err(me.body_tx.on_user_err(e))),
                None => {
                    // no more frames means we're done here
                    // but at this point, we haven't sent an EOS DATA, or
                    // any trailers, so send an empty EOS DATA.
                    return Poll::Ready(me.body_tx.send_eos_frame());
                }
            }
        }
    }
}

fn filter_allowed_trailers(trailers: HeaderMap) -> HeaderMap {
    if trailers.keys().all(|name| name.is_allowed_in_trailers()) {
        return trailers;
    }

    let mut filtered = HeaderMap::with_capacity(trailers.len());
    for (name, value) in trailers.into_ordered_iter() {
        if name.is_allowed_in_trailers() {
            filtered.append(name, value);
        } else {
            debug!("dropping disallowed HTTP/2 trailer field: {name:?}");
        }
    }
    filtered
}

trait SendStreamExt {
    fn on_user_err<E>(&mut self, err: E) -> crate::Error
    where
        E: Into<BoxError>;
    fn send_eos_frame(&mut self) -> crate::Result<()>;
}

impl<B: Buf> SendStreamExt for SendStream<SendBuf<B>> {
    fn on_user_err<E>(&mut self, err: E) -> crate::Error
    where
        E: Into<BoxError>,
    {
        let err = crate::Error::new_user_body(err);
        debug!("send body user stream error: {:?}", err);
        self.send_reset(err.h2_reason());
        err
    }

    fn send_eos_frame(&mut self) -> crate::Result<()> {
        trace!("send body eos");
        self.send_data(SendBuf::None, true)
            .map_err(crate::Error::new_body_write)
    }
}

#[repr(usize)]
enum SendBuf<B> {
    Buf(B),
    Cursor(Cursor<Box<[u8]>>),
    None,
}

impl<B: Buf> Buf for SendBuf<B> {
    #[inline]
    fn remaining(&self) -> usize {
        match self {
            Self::Buf(b) => b.remaining(),
            Self::Cursor(c) => Buf::remaining(c),
            Self::None => 0,
        }
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        match self {
            Self::Buf(b) => b.chunk(),
            Self::Cursor(c) => c.chunk(),
            Self::None => &[],
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        match self {
            Self::Buf(b) => b.advance(cnt),
            Self::Cursor(c) => c.advance(cnt),
            Self::None => {}
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        match self {
            Self::Buf(b) => b.chunks_vectored(dst),
            Self::Cursor(c) => c.chunks_vectored(dst),
            Self::None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::HeaderValue;

    #[test]
    fn filters_h2_trailers_with_the_shared_field_policy() {
        let mut trailers = HeaderMap::new();
        trailers.insert("content-type", HeaderValue::from_static("text/plain"));
        trailers.insert("etag", HeaderValue::from_static("\"v1\""));
        trailers.insert("grpc-status", HeaderValue::from_static("0"));

        let filtered = filter_allowed_trailers(trailers);

        assert!(!filtered.contains_key("content-type"));
        assert_eq!(filtered["etag"], "\"v1\"");
        assert_eq!(filtered["grpc-status"], "0");
    }

    #[test]
    fn keeps_allowed_h2_trailer_allocation() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let capacity = trailers.capacity();

        let filtered = filter_allowed_trailers(trailers);

        assert_eq!(filtered.capacity(), capacity);
        assert_eq!(filtered["grpc-status"], "0");
    }
}
