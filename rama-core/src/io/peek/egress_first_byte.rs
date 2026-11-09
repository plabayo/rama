use std::{
    io,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use parking_lot::Mutex;
use rama_utils::macros::define_inner_service_accessors;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{PeekInterrupt, PeekInterruptSource};
use crate::{
    Layer, Service,
    extensions::{Extensions, ExtensionsRef},
    io::{BridgeIo, Io},
};

/// A [`Layer`] that triggers the [`PeekInterrupt`] of a [`BridgeIo`] as soon
/// as its egress sends a first byte (or closes) while the ingress is peeked.
///
/// This lets ingress peekers stop waiting for a client that will not speak
/// first, e.g. for server-first protocols such as SMTP or SSH, instead of
/// relying on a timeout. See [`PeekEgressFirstByteService`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PeekEgressFirstByteLayer;

impl PeekEgressFirstByteLayer {
    /// Create a new [`PeekEgressFirstByteLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for PeekEgressFirstByteLayer {
    type Service = PeekEgressFirstByteService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PeekEgressFirstByteService { inner }
    }
}

/// The [`Service`] produced by [`PeekEgressFirstByteLayer`].
///
/// It reuses the [`PeekInterrupt`] found in the ingress extensions, or
/// inserts a new one, and wraps the egress in a [`PeekEgressFirstByteIo`]. The egress
/// is probed only while a peek waits on that interrupt, at most one byte is
/// read, and that byte is replayed as the first byte read from the egress.
#[derive(Debug, Clone, ExtensionsRef)]
pub struct PeekEgressFirstByteService<S> {
    inner: S,
}

impl<S> PeekEgressFirstByteService<S> {
    /// Create a new [`PeekEgressFirstByteService`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for PeekEgressFirstByteService<S>
where
    S: Service<BridgeIo<Ingress, PeekEgressFirstByteIo<Egress>>>,
    Ingress: Io + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: BridgeIo<Ingress, Egress>) -> Result<Self::Output, Self::Error> {
        let BridgeIo(ingress, egress) = input;
        let interrupt = ingress
            .extensions()
            .get_arc_or_insert(|| Arc::new(PeekInterrupt::new()));
        let egress = PeekEgressFirstByteIo::new(egress, &interrupt);
        self.inner.serve(BridgeIo(ingress, egress)).await
    }
}

/// Egress [`Io`] that can be probed for its first byte by a [`PeekInterrupt`].
///
/// Created by [`PeekEgressFirstByteService`]. The probe ends on the first use of this
/// [`Io`], after which it behaves as the wrapped [`Io`], replaying a probed
/// byte, EOF or error first.
pub struct PeekEgressFirstByteIo<S> {
    state: State<S>,
    extensions: Extensions,
}

enum State<S> {
    Shared(Arc<Mutex<Probe<S>>>),
    Owned { probed: Option<Probed>, io: S },
    Detached,
}

struct Probe<S> {
    io: Option<S>,
    probed: Option<Probed>,
}

enum Probed {
    Byte(u8),
    Eof,
    Error(io::Error),
}

impl<S: Io + Unpin + ExtensionsRef> PeekEgressFirstByteIo<S> {
    /// Wrap `io` and attach its first-byte probe to `interrupt`.
    pub fn new(io: S, interrupt: &PeekInterrupt) -> Self {
        let extensions = io.extensions().clone();
        let probe = Arc::new(Mutex::new(Probe {
            io: Some(io),
            probed: None,
        }));
        interrupt.attach(EgressProbe(Arc::downgrade(&probe)));
        Self {
            state: State::Shared(probe),
            extensions,
        }
    }
}

impl<S> PeekEgressFirstByteIo<S> {
    fn owned(&mut self) -> io::Result<(&mut Option<Probed>, &mut S)> {
        if let State::Shared(probe) = &self.state {
            let (io, probed) = {
                let mut probe = probe.lock();
                (probe.io.take(), probe.probed.take())
            };
            self.state = match io {
                Some(io) => State::Owned { probed, io },
                None => State::Detached,
            };
        }
        match &mut self.state {
            State::Owned { probed, io } => Ok((probed, io)),
            State::Shared(_) | State::Detached => {
                Err(io::Error::other("peek egress first-byte io detached"))
            }
        }
    }
}

impl<S> ExtensionsRef for PeekEgressFirstByteIo<S> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<S> std::fmt::Debug for PeekEgressFirstByteIo<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match &self.state {
            State::Shared(_) => "shared",
            State::Owned { .. } => "owned",
            State::Detached => "detached",
        };
        f.debug_struct("PeekEgressFirstByteIo")
            .field("state", &state)
            .finish()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekEgressFirstByteIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let (probed, io) = self.get_mut().owned()?;
        match probed.take() {
            Some(Probed::Byte(byte)) if buf.remaining() > 0 => {
                buf.put_slice(&[byte]);
                Poll::Ready(Ok(()))
            }
            Some(Probed::Byte(byte)) => {
                *probed = Some(Probed::Byte(byte));
                Poll::Ready(Ok(()))
            }
            Some(Probed::Eof) => Poll::Ready(Ok(())),
            Some(Probed::Error(err)) => Poll::Ready(Err(err)),
            None => Pin::new(io).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekEgressFirstByteIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let (_, io) = self.get_mut().owned()?;
        Pin::new(io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let (_, io) = self.get_mut().owned()?;
        Pin::new(io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        match &self.state {
            State::Owned { io, .. } => io.is_write_vectored(),
            State::Shared(probe) => probe
                .lock()
                .io
                .as_ref()
                .is_some_and(AsyncWrite::is_write_vectored),
            State::Detached => false,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (_, io) = self.get_mut().owned()?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (_, io) = self.get_mut().owned()?;
        Pin::new(io).poll_shutdown(cx)
    }
}

// Weak: the interrupt may outlive the egress, which must close once its wrapper is dropped.
struct EgressProbe<S>(Weak<Mutex<Probe<S>>>);

impl<S: AsyncRead + Unpin + Send + 'static> PeekInterruptSource for EgressProbe<S> {
    fn poll_interrupt(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(probe) = self.0.upgrade() else {
            return Poll::Pending;
        };
        let mut probe = probe.lock();
        let Probe { io, probed } = &mut *probe;
        if probed.is_some() {
            return Poll::Ready(());
        }
        // the egress was taken into use: it no longer counts as speaking first
        let Some(io) = io.as_mut() else {
            return Poll::Pending;
        };

        let mut byte = [0u8; 1];
        let mut buf = ReadBuf::new(&mut byte);
        let outcome = match Pin::new(io).poll_read(cx, &mut buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) if buf.filled().is_empty() => Probed::Eof,
            Poll::Ready(Ok(())) => Probed::Byte(byte[0]),
            Poll::Ready(Err(err)) => Probed::Error(err),
        };
        *probed = Some(outcome);
        Poll::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};

    use super::*;
    use crate::{
        ServiceInput,
        io::peek::{PeekPolicy, PeekPrefixedIo, PeekRouter},
        service::service_fn,
    };

    type Bridge = BridgeIo<ServiceInput<DuplexStream>, ServiceInput<DuplexStream>>;
    type Probed =
        BridgeIo<ServiceInput<DuplexStream>, PeekEgressFirstByteIo<ServiceInput<DuplexStream>>>;
    type Peeked = BridgeIo<
        PeekPrefixedIo<ServiceInput<DuplexStream>>,
        PeekEgressFirstByteIo<ServiceInput<DuplexStream>>,
    >;

    const HOUR: Duration = Duration::from_secs(3600);
    const SMTP_GREETING: &[u8] = b"220 mail.example.com ESMTP ready\r\n";

    fn bridge() -> (DuplexStream, DuplexStream, Bridge) {
        let (client, ingress) = duplex(1024);
        let (server, egress) = duplex(1024);
        let bridge = BridgeIo(ServiceInput::new(ingress), ServiceInput::new(egress));
        (client, server, bridge)
    }

    /// Routes `MAGIC` to "accept" and all else to "fallback", both reporting
    /// the first `ingress_len` ingress and `egress_len` egress bytes they read.
    fn magic_router(
        ingress_len: usize,
        egress_len: usize,
        policy: PeekPolicy,
    ) -> impl Service<Bridge, Output = (&'static str, Vec<u8>, Vec<u8>), Error: std::fmt::Debug>
    {
        let report = move |label: &'static str| {
            service_fn(
                move |BridgeIo(mut ingress, mut egress): Peeked| async move {
                    let mut client_bytes = vec![0; ingress_len];
                    ingress.read_exact(&mut client_bytes).await?;
                    let mut server_bytes = vec![0; egress_len];
                    egress.read_exact(&mut server_bytes).await?;
                    Ok::<_, io::Error>((label, client_bytes, server_bytes))
                },
            )
        };
        PeekEgressFirstByteLayer::new().into_layer(
            PeekRouter::from_prefix(b"MAGIC", report("accept"))
                .with_peek_policy(policy)
                .with_fallback(report("fallback")),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn server_first_greeting_ends_idle_peek_without_a_timeout() {
        let (_client, mut server, input) = bridge();
        server.write_all(SMTP_GREETING).await.unwrap();

        let router = magic_router(0, SMTP_GREETING.len(), PeekPolicy::FAIL_OPEN);
        let (label, _, greeting) = tokio::time::timeout(HOUR, router.serve(input))
            .await
            .expect("an egress greeting must end the idle peek")
            .unwrap();

        assert_eq!("fallback", label);
        assert_eq!(SMTP_GREETING, greeting);
    }

    #[tokio::test(start_paused = true)]
    async fn server_close_ends_idle_peek_and_is_replayed() {
        let (_client, server, input) = bridge();
        drop(server);

        let router = PeekEgressFirstByteLayer::new().into_layer(
            PeekRouter::from_prefix(
                b"MAGIC",
                service_fn(async |_: Peeked| Ok::<_, io::Error>(None)),
            )
            .with_fallback(service_fn(async |BridgeIo(_, mut egress): Peeked| {
                let mut rest = Vec::new();
                egress.read_to_end(&mut rest).await?;
                Ok::<_, io::Error>(Some(rest))
            })),
        );
        let replayed = tokio::time::timeout(HOUR, router.serve(input))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Some(Vec::new()), replayed);
    }

    #[tokio::test(start_paused = true)]
    async fn server_bytes_do_not_cut_off_a_started_client_message() {
        let (mut client, mut server, input) = bridge();
        client.write_all(b"MA").await.unwrap();
        let _client = tokio::spawn(async move {
            server.write_all(b"!").await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
            client.write_all(b"GIC").await.unwrap();
            (client, server)
        });

        let router = magic_router(5, 1, PeekPolicy::FAIL_OPEN);
        let (label, client_bytes, server_bytes) = tokio::time::timeout(HOUR, router.serve(input))
            .await
            .unwrap()
            .unwrap();

        assert_eq!("accept", label);
        assert_eq!(b"MAGIC", &client_bytes[..]);
        assert_eq!(b"!", &server_bytes[..]);
    }

    #[tokio::test(start_paused = true)]
    async fn client_first_protocol_is_not_affected() {
        let (mut client, _server, input) = bridge();
        client.write_all(b"MAGIC").await.unwrap();

        let router = magic_router(5, 0, PeekPolicy::FAIL_OPEN);
        let (label, client_bytes, _) = tokio::time::timeout(HOUR, router.serve(input))
            .await
            .unwrap()
            .unwrap();
        assert_eq!("accept", label);
        assert_eq!(b"MAGIC", &client_bytes[..]);
    }

    #[tokio::test]
    async fn egress_without_a_peek_relays_both_ways() {
        let (_client, mut server, input) = bridge();
        let service = PeekEgressFirstByteLayer::new().into_layer(service_fn(
            async |BridgeIo(_, mut egress): BridgeIo<_, PeekEgressFirstByteIo<_>>| {
                egress.write_all(b"ping").await?;
                let mut pong = [0u8; 4];
                egress.read_exact(&mut pong).await?;
                Ok::<_, io::Error>(pong)
            },
        ));
        let serving = tokio::spawn(async move { service.serve(input).await });

        let mut ping = [0u8; 4];
        server.read_exact(&mut ping).await.unwrap();
        assert_eq!(b"ping", &ping);
        server.write_all(b"pong").await.unwrap();
        assert_eq!(b"pong", &serving.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn existing_interrupt_is_reused() {
        let (_client, _server, input) = bridge();
        let existing = Arc::new(PeekInterrupt::new());
        input.extensions().insert_arc(existing.clone());

        let service =
            PeekEgressFirstByteLayer::new().into_layer(service_fn(async |input: Probed| {
                Ok::<_, io::Error>(input.extensions().get_arc::<PeekInterrupt>())
            }));
        let found = service.serve(input).await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&existing, &found));
    }

    #[tokio::test]
    async fn dropping_an_unused_wrapper_closes_the_egress() {
        let interrupt = PeekInterrupt::new();
        let (mut server, egress) = duplex(64);
        let io = PeekEgressFirstByteIo::new(ServiceInput::new(egress), &interrupt);
        drop(io);

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut buf))
            .await
            .expect("the dropped egress must close while the interrupt lives")
            .unwrap();
        assert_eq!(0, n);
        assert!(!interrupt.is_triggered());
    }

    #[tokio::test]
    async fn interrupt_held_by_the_egress_itself_does_not_keep_it_open() {
        let (mut server, egress) = duplex(64);
        let egress = ServiceInput::new(egress);
        let interrupt = egress
            .extensions()
            .get_arc_or_insert(|| Arc::new(PeekInterrupt::new()));
        let io = PeekEgressFirstByteIo::new(egress, &interrupt);
        drop(interrupt);
        drop(io);

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut buf))
            .await
            .expect("an interrupt reachable from the egress must not keep it open")
            .unwrap();
        assert_eq!(0, n);
    }
}
