//! Ordinary CONNECT uses Rama's existing upgrade API and bounded DATA framing.

use super::{
    Error,
    frame::FrameEvent,
    quic::{RecvStream, SendStream, Writer},
    stream::{Phase, Reader},
};
use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
};
use rama_http::io::upgrade::Upgraded;
use rama_http_types::proto::h3::{Code, FrameType};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::OwnedSemaphorePermit,
};

pub(crate) fn new(
    mut reader: Reader<rama_quic::RecvStream>,
    writer: Writer<rama_quic::SendStream>,
    permit: Arc<OwnedSemaphorePermit>,
    priority: Option<super::priority::Lease>,
) -> Upgraded {
    reader.phase = Phase::Tunnel;
    let extensions = reader.shared.transport_extensions.fork();
    let abort = writer.abort_handle();
    extensions.insert(rama_http::io::upgrade::OnUpstreamError::new(move || {
        abort.abort(rama_quic_proto::VarInt::from_u32(
            Code::H3_CONNECT_ERROR.value() as u32,
        ));
    }));
    Upgraded::new(
        Tunnel {
            reader,
            writer,
            buffer: Bytes::new(),
            extensions,
            _priority: priority,
            _permit: Some(permit),
            shutdown: None,
            acknowledged: None,
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
    _permit: Option<Arc<OwnedSemaphorePermit>>,
    shutdown: Option<Result<(), Error>>,
    acknowledged: Option<Acknowledged>,
    _priority: Option<super::priority::Lease>,
}

impl<R: RecvStream, S: SendStream> Tunnel<R, S> {
    fn release_finished(&mut self) {
        if self.shutdown == Some(Ok(())) && self.reader.phase == Phase::Finished {
            self._priority.take();
            self._permit.take();
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
        self.flush(cx).map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(result) = self.shutdown {
            return Poll::Ready(result.map_err(io::Error::other));
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
            Ok(()) => self.writer.mark_acknowledged(),
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
            _permit: None,
            shutdown: None,
            acknowledged: None,
            _priority: None,
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
        tunnel._permit = Some(permit.clone());
        tunnel._priority = Some(Lease {
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
