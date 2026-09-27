//! Ordinary CONNECT uses Rama's existing upgrade API and bounded DATA framing.

use super::{
    Error,
    control::Role,
    datagram::{Association, H3DatagramChannel, ReceiveEnd},
    frame::FrameEvent,
    quic::{RecvStream, SendStream, Writer},
    stream::{Phase, Reader},
};
use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
};
use rama_http::{
    datagram::NativeDatagrams,
    io::upgrade::{OnMalformedMessage, OnUpstreamError, Upgraded},
};
use rama_http_types::proto::h3::{Code, FrameType, VarInt};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A request's claimed datagram association and the connection carrying its datagrams.
pub(crate) type Datagrams = (Arc<Association>, rama_quic::Connection);

pub(crate) fn new(
    mut reader: Reader<rama_quic::RecvStream>,
    writer: Writer<rama_quic::SendStream>,
    permit: Arc<dyn Send + Sync>,
    priority: Option<super::priority::Lease>,
    datagrams: Option<Datagrams>,
) -> Upgraded {
    reader.phase = Phase::Tunnel;
    let extensions = reader.shared.transport_extensions.fork();
    // A local abort fails both directions at once, independent of any later I/O poll.
    let aborted = Arc::new(AtomicU64::new(0));
    let registration = reader.datagrams.as_ref().map(Arc::downgrade);
    for (code, malformed) in [
        (Code::H3_CONNECT_ERROR, false),
        (Code::H3_MESSAGE_ERROR, true),
    ] {
        let handle = writer.abort_handle();
        let aborted = aborted.clone();
        let registration = registration.clone();
        let abort = move || {
            _ = aborted.compare_exchange(0, code.value(), Ordering::AcqRel, Ordering::Acquire);
            if let Some(registration) = registration.as_ref().and_then(|weak| weak.upgrade()) {
                registration.receive_ended(ReceiveEnd::Aborted(code.value()));
            }
            handle.abort(VarInt::from_u32(code.value() as u32));
        };
        if malformed {
            extensions.insert(OnMalformedMessage::new(abort));
        } else {
            extensions.insert(OnUpstreamError::new(abort));
        }
    }
    let association = datagrams.and_then(|(association, connection)| {
        let channel = H3DatagramChannel::new(association.clone(), connection)?;
        extensions.insert(NativeDatagrams::new(channel));
        Some(association)
    });
    Upgraded::new(
        Tunnel {
            reader,
            writer,
            buffer: Bytes::new(),
            extensions,
            priority_lease: priority,
            permit: Some(permit),
            shutdown: None,
            acknowledged: None,
            association,
            aborted,
        },
        Bytes::new(),
    )
}

type Acknowledged = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + Sync>>;

struct Tunnel<R: RecvStream, S: SendStream> {
    reader: Reader<R>,
    writer: Writer<S>,
    buffer: Bytes,
    extensions: Extensions,
    permit: Option<Arc<dyn Send + Sync>>,
    shutdown: Option<Result<(), Error>>,
    acknowledged: Option<Acknowledged>,
    priority_lease: Option<super::priority::Lease>,
    association: Option<Arc<Association>>,
    // The code of a local abort through the tunnel's hooks, zero while open.
    aborted: Arc<AtomicU64>,
}

impl<R: RecvStream, S: SendStream> Drop for Tunnel<R, S> {
    fn drop(&mut self) {
        if let Some(association) = &self.association {
            association.close();
        }
    }
}

impl<R: RecvStream, S: SendStream> Tunnel<R, S> {
    /// Fail I/O, including still-buffered data, once a hook aborted the tunnel.
    fn check_aborted(&self) -> io::Result<()> {
        match self.aborted.load(Ordering::Acquire) {
            0 => Ok(()),
            code => Err(io::Error::other(Error::stream(
                Code::new(code),
                "tunnel aborted locally",
            ))),
        }
    }

    fn release_finished(&mut self) {
        if self.shutdown == Some(Ok(())) && self.reader.phase == Phase::Finished {
            self.priority_lease.take();
            self.permit.take();
        }
    }

    fn flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), super::Error>> {
        let shared = &self.reader.shared;
        let id = self.reader.id;
        let priority = ready!(shared.schedule.poll_turn(id, cx));
        let result = match self
            .writer
            .priority(super::priority::transport_priority(priority))
        {
            Ok(()) => self.writer.poll_flush(cx),
            Err(error) => Poll::Ready(Err(error)),
        };
        shared.schedule.release(id);
        result
    }
}

impl<R: RecvStream, S: SendStream> ExtensionsRef for Tunnel<R, S> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<R: RecvStream + Unpin, S: SendStream + Unpin> AsyncRead for Tunnel<R, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check_aborted()?;
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..super::cooperative::OPERATIONS_PER_QUANTUM {
            if !self.buffer.is_empty() {
                let count = dst.remaining().min(self.buffer.len());
                dst.put_slice(&self.buffer.split_to(count));
                return Poll::Ready(Ok(()));
            }
            match ready!(self.reader.poll_event(cx)).map_err(io::Error::other)? {
                Some(FrameEvent::DataChunk(bytes)) => self.buffer = bytes,
                Some(FrameEvent::DataHeader { .. }) => (),
                None => {
                    self.release_finished();
                    return Poll::Ready(Ok(()));
                }
                Some(_) => {
                    let error = super::Error::connection(
                        Code::H3_FRAME_UNEXPECTED,
                        "frame forbidden in CONNECT tunnel",
                    );
                    return Poll::Ready(Err(io::Error::other(self.reader.reject(error))));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<R: RecvStream + Unpin, S: SendStream + Unpin> AsyncWrite for Tunnel<R, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check_aborted()?;
        ready!(self.flush(cx)).map_err(io::Error::other)?;
        let count = src.len().min(self.reader.shared.config.read_chunk_size);
        if count != 0 {
            self.writer
                .queue(FrameType::DATA, Bytes::copy_from_slice(&src[..count]))
                .map_err(io::Error::other)?;
        }
        // Ownership has transferred: report acceptance before any subsequent Pending.
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_aborted()?;
        self.flush(cx).map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(result) = self.shutdown {
            return Poll::Ready(result.map_err(io::Error::other));
        }
        self.check_aborted()?;
        // RFC 9297 §2.1: no datagrams once the end of the send side is committed.
        if let Some(association) = &self.association {
            association.close_send();
        }
        ready!(self.flush(cx)).map_err(io::Error::other)?;
        ready!(self.writer.poll_finish(cx)).map_err(io::Error::other)?;
        let Self {
            writer,
            acknowledged,
            ..
        } = &mut *self;
        let wait = acknowledged.get_or_insert_with(|| Box::pin(writer.acknowledged()));
        let result = ready!(wait.as_mut().poll(cx));
        self.acknowledged = None;
        self.shutdown = Some(result);
        match result {
            Ok(()) => {
                self.writer.mark_acknowledged();
                // RFC 9114 §4.1.2: once a server's response is complete, not reading the
                // rest of the request is H3_NO_ERROR, not a cancellation.
                if self.reader.shared.role == Role::Server {
                    self.reader.cancel_code = Code::H3_NO_ERROR;
                }
            }
            Err(error) => self.writer.reset(error.code()),
        }
        self.release_finished();
        Poll::Ready(result.map_err(io::Error::other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3::{
        Error,
        connection::{Config, Shared},
        control::Role,
        priority::Lease,
    };
    use parking_lot::Mutex;
    use rama_http::headers::Priority;
    use std::{
        future::Future as _,
        pin::pin,
        sync::atomic::{AtomicBool, Ordering},
        task::Waker,
    };
    use tokio::io::AsyncWriteExt as _;
    use tokio::sync::Semaphore;

    struct IdleRecv;

    impl RecvStream for IdleRecv {
        fn poll_chunk(
            &mut self,
            _: &mut Context<'_>,
            _: usize,
        ) -> Poll<Result<Option<Bytes>, Error>> {
            Poll::Pending
        }

        fn stop(&mut self, _: Code) {}
    }

    struct ReadySend(Arc<Mutex<Vec<u8>>>, Arc<AtomicBool>, Option<Error>);

    impl SendStream for ReadySend {
        fn acknowledged(&self) -> impl Future<Output = Result<(), Error>> + Send + Sync + 'static {
            let acknowledged = self.1.clone();
            let error = self.2;
            async move {
                std::future::poll_fn(move |_| {
                    if acknowledged.load(Ordering::Relaxed) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                error.map_or(Ok(()), Err)
            }
        }

        fn poll_chunks(
            &mut self,
            _: &mut Context<'_>,
            chunks: &mut [Bytes],
        ) -> Poll<Result<(), Error>> {
            let mut written = self.0.lock();
            for chunk in chunks {
                written.extend_from_slice(chunk);
                *chunk = Bytes::new();
            }
            Poll::Ready(Ok(()))
        }

        fn finish(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn reset(&mut self, _: Code) {}
        fn priority(&mut self, _: i32) -> Result<(), Error> {
            Ok(())
        }
    }

    fn tunnel(
        shared: Arc<Shared>,
        id: u64,
        output: Arc<Mutex<Vec<u8>>>,
    ) -> Tunnel<IdleRecv, ReadySend> {
        Tunnel {
            reader: Reader::new(IdleRecv, shared, id),
            writer: Writer::new(ReadySend(output, Arc::new(AtomicBool::new(false)), None)),
            buffer: Bytes::new(),
            extensions: Extensions::new(),
            permit: None,
            shutdown: None,
            acknowledged: None,
            priority_lease: None,
            association: None,
            aborted: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn repeated_tunnel_shutdown_preserves_peer_stop_without_repolling_future() {
        let shared = Shared::new(Config::default(), Role::Server, Default::default()).unwrap();
        shared.schedule.register(0, Priority::default()).unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut tunnel = tunnel(shared, 0, output.clone());
        let error = Error::peer_stopped(Code::H3_REQUEST_CANCELLED);
        tunnel.writer = Writer::new(ReadySend(
            output,
            Arc::new(AtomicBool::new(true)),
            Some(error),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..3 {
            let Poll::Ready(Err(actual)) = Pin::new(&mut tunnel).poll_shutdown(&mut cx) else {
                panic!("shutdown must preserve its terminal error");
            };
            assert_eq!(
                actual.get_ref().unwrap().downcast_ref::<Error>(),
                Some(&error)
            );
        }
    }

    #[test]
    fn tunnel_shutdown_retains_admission_until_fin_acknowledgement() {
        let shared = Shared::new(
            Config {
                max_requests: 1,
                ..Config::default()
            },
            Role::Server,
            Default::default(),
        )
        .unwrap();
        shared.schedule.register(0, Priority::default()).unwrap();
        let admission = Arc::new(Semaphore::new(1));
        let permit = Arc::new(admission.clone().try_acquire_owned().unwrap());
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut tunnel = tunnel(shared.clone(), 0, output.clone());
        let acknowledged = Arc::new(AtomicBool::new(false));
        tunnel.writer = Writer::new(ReadySend(output, acknowledged.clone(), None));
        tunnel.reader.phase = Phase::Finished;
        tunnel.permit = Some(permit.clone());
        tunnel.priority_lease = Some(Lease {
            shared: shared.clone(),
            id: 0,
            permit,
        });
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut tunnel).poll_shutdown(&mut cx).is_pending());
        assert_eq!(admission.available_permits(), 0);
        acknowledged.store(true, Ordering::Relaxed);
        assert!(matches!(
            Pin::new(&mut tunnel).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(admission.available_permits(), 1);
        shared.schedule.register(4, Priority::default()).unwrap();
        assert!(matches!(
            Pin::new(&mut tunnel).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn cancelling_a_write_future_preserves_other_tunnel_progress() {
        let shared = Shared::new(Config::default(), Role::Server, Extensions::new()).unwrap();
        for (id, urgency) in [(0, 0), (4, 1), (8, 7)] {
            shared
                .schedule
                .register(id, Priority::new(urgency, true).unwrap())
                .unwrap();
        }
        let abandoned_output = Arc::new(Mutex::new(Vec::new()));
        let active_output = Arc::new(Mutex::new(Vec::new()));
        let mut abandoned = tunnel(shared.clone(), 4, abandoned_output.clone());
        let mut active = tunnel(shared.clone(), 8, active_output.clone());
        let mut cx = Context::from_waker(Waker::noop());
        // An in-progress writer initially owns the preferred turn.
        assert!(shared.schedule.poll_turn(0, &cx).is_ready());
        {
            let mut write = pin!(abandoned.write(b"cancelled"));
            assert!(write.as_mut().poll(&mut cx).is_pending());
        }
        shared.schedule.release(0);
        // Keep the abandoned tunnel alive, as after a timeout or select branch.
        // Its lower-priority peer must nevertheless send actual DATA promptly.
        {
            let mut write = pin!(active.write(b"progress"));
            assert!(write.as_mut().poll(&mut cx).is_pending());
            assert!(matches!(write.as_mut().poll(&mut cx), Poll::Ready(Ok(8))));
        }
        assert!(Pin::new(&mut active).poll_flush(&mut cx).is_ready());
        assert_eq!(*active_output.lock(), b"\x00\x08progress");
        assert!(abandoned_output.lock().is_empty());
        {
            let mut write = pin!(abandoned.write(b"retry"));
            assert!(matches!(write.as_mut().poll(&mut cx), Poll::Ready(Ok(5))));
        }
        assert!(Pin::new(&mut abandoned).poll_flush(&mut cx).is_ready());
        assert_eq!(*abandoned_output.lock(), b"\x00\x05retry");
    }
}
