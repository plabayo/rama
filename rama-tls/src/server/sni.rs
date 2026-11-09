use std::{
    fmt,
    io::{IoSlice, Read, Write},
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use rama_core::{
    Service,
    error::{BoxError, ErrorContext},
    extensions::{Extensions, ExtensionsRef},
    io::{
        HeapReader, PrefixedIo,
        peek::{PeekPolicy, PeekWaiter},
    },
    service::RejectService,
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use rama_net::address::Domain;

use super::{MalformedTlsPolicy, NoTlsRejectError, peek_client_hello_from_input_with_policies};
use crate::client::ClientHelloReassemblyConfig;

/// A [`Service`] router that can be used to support
/// routing of tls traffic as well as non-tls traffic.
///
/// The difference with [`TlsPeekRouter`] is that the [`SniRouter`]
/// continues to parse after the initial couple of bytes,
/// in order to learn more about underlying traffic. This allowing
/// you to route based on the SNI from the client hello,
/// among other capabilities.
///
/// By default non-tls traffic is rejected using [`RejectService`].
/// Use [`SniRouter::with_fallback`] to configure the fallback service.
/// Non-TLS traffic invokes that fallback. By default malformed, over-limit, or
/// EOF-truncated TLS also invokes it, with a [`super::ClientHelloPeekStatus`]
/// extension identifying the failure. Use [`SniRouter::with_malformed_tls_policy`]
/// to opt into rejection. With the default [`PeekPolicy::FAIL_OPEN`], a
/// timed-out prefix also invokes the fallback. Strict SNI routing should select
/// [`MalformedTlsPolicy::Reject`] and a [`PeekPolicy`] that never falls back on
/// partial input, see [`SniRouter::with_peek_policy`].
///
/// [`TlsPeekRouter`]: super::TlsPeekRouter
#[derive(Debug, Clone)]
pub struct SniRouter<S, F = RejectService<(), NoTlsRejectError>> {
    service: S,
    fallback: F,
    peek_timeout: Option<Duration>,
    peek_policy: PeekPolicy,
    reassembly_config: ClientHelloReassemblyConfig,
    malformed_tls_policy: MalformedTlsPolicy,
}

impl<S> SniRouter<S> {
    /// Create a new [`SniRouter`].
    pub fn new(service: S) -> Self {
        Self {
            service,
            fallback: RejectService::new(NoTlsRejectError),
            peek_timeout: None,
            peek_policy: PeekPolicy::FAIL_OPEN,
            reassembly_config: ClientHelloReassemblyConfig::default(),
            malformed_tls_policy: MalformedTlsPolicy::default(),
        }
    }

    /// Attach a fallback [`Service`] to this [`SniRouter`].
    ///
    /// Used for non-TLS traffic and whenever the configured peek policies select fallback.
    pub fn with_fallback<F>(self, fallback: F) -> SniRouter<S, F> {
        SniRouter {
            service: self.service,
            fallback,
            peek_timeout: self.peek_timeout,
            peek_policy: self.peek_policy,
            reassembly_config: self.reassembly_config,
            malformed_tls_policy: self.malformed_tls_policy,
        }
    }
}

impl<S, F> SniRouter<S, F> {
    rama_utils::macros::generate_set_and_with! {
        /// Choose whether unparseable, over-limit, or EOF-truncated TLS is
        /// sent to the fallback (the default) or rejected.
        /// Keep rejection when route policy depends on validated SNI. This does
        /// not change the reassembly bounds or peek policy.
        pub fn malformed_tls_policy(mut self, policy: MalformedTlsPolicy) -> Self {
            self.malformed_tls_policy = policy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Configure ClientHello size, record count, and legacy-version checks.
        /// Defaults to 256 KiB across 256 records with tolerant legacy versions.
        pub fn reassembly_config(mut self, config: ClientHelloReassemblyConfig) -> Self {
            self.reassembly_config = config;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set an optional timeout on the ClientHello peek.
        ///
        /// Defaults to `None` (no timeout). A valid-but-partial ClientHello from
        /// an idle peer otherwise blocks until EOF; set a timeout for untrusted
        /// ingress. Use [`SniRouter::with_peek_policy`] to choose whether an
        /// inconclusive timeout invokes the fallback, rejects the connection or
        /// keeps waiting.
        pub fn peek_timeout(mut self, peek_timeout: Option<Duration>) -> Self {
            self.peek_timeout = peek_timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set how a ClientHello peek timeout or [`PeekInterrupt`] is handled.
        ///
        /// Defaults to [`PeekPolicy::FAIL_OPEN`]. Non-TLS traffic invokes
        /// the fallback; malformed TLS follows the separate malformed-TLS policy.
        ///
        /// [`PeekInterrupt`]: rama_core::io::peek::PeekInterrupt
        pub fn peek_policy(mut self, peek_policy: PeekPolicy) -> Self {
            self.peek_policy = peek_policy;
            self
        }
    }
}

impl<Stream, Output, S, F> Service<Stream> for SniRouter<S, F>
where
    Stream: rama_core::io::Io + Unpin + ExtensionsRef,
    Output: Send + 'static,
    S: Service<SniRequest<Stream>, Output = Output, Error: Into<BoxError>>,
    F: Service<SniPrefixedIo<Stream>, Output = Output, Error: Into<BoxError>>,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, stream: Stream) -> Result<Self::Output, Self::Error> {
        // The shared peeker validates and reassembles TLS before SNI routing,
        // while preserving all original wire bytes for the selected service.
        let extensions = stream.extensions().clone();
        let waiter = PeekWaiter::new(self.peek_timeout)
            .with_policy(self.peek_policy)
            .maybe_with_interrupt(extensions.get_arc());
        let (peeked, maybe_client_hello, status) = peek_client_hello_from_input_with_policies(
            stream,
            waiter,
            self.malformed_tls_policy,
            self.reassembly_config,
        )
        .await
        .context("SNI router: peek TLS ClientHello")?;

        extensions.insert(status);
        match maybe_client_hello {
            Some(client_hello) => {
                let sni = client_hello.ext_server_name().cloned();
                self.service
                    .serve(SniRequest {
                        stream: peeked,
                        sni,
                    })
                    .await
                    .into_box_error()
            }
            None => self.fallback.serve(peeked).await.into_box_error(),
        }
    }
}

/// [`PrefixedIo`] alias used by [`SniRouter`].
pub type SniPrefixedIo<S> = PrefixedIo<HeapReader, S>;

pin_project! {
    /// A request ready for SNI routing,
    /// usually used in combination with [`SniRouter`].
    #[derive(Debug, Clone)]
    pub struct SniRequest<S> {
        #[pin]
        pub stream: SniPrefixedIo<S>,
        pub sni: Option<Domain>,
    }
}

impl<S: ExtensionsRef> ExtensionsRef for SniRequest<S> {
    fn extensions(&self) -> &Extensions {
        self.stream.extensions()
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S> AsyncRead for SniRequest<S>
where
    S: AsyncRead,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.project();
        me.stream.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S> AsyncBufRead for SniRequest<S>
where
    S: AsyncBufRead,
{
    #[inline]
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        let me = self.project();
        me.stream.poll_fill_buf(cx)
    }

    #[inline]
    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.project();
        me.stream.consume(amt)
    }
}

impl<S> Read for SniRequest<S>
where
    S: Read,
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.stream.read_exact(buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.stream.read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.stream.read_to_string(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [std::io::IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.stream.read_vectored(bufs)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S> AsyncWrite for SniRequest<S>
where
    S: AsyncWrite,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.project();
        me.stream.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let me = self.project();
        me.stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let me = self.project();
        me.stream.poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let me = self.project();
        me.stream.poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

impl<S> Write for SniRequest<S>
where
    S: Write,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(buf)
    }

    #[inline]
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> std::io::Result<()> {
        self.stream.write_fmt(args)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.stream.write_vectored(bufs)
    }
}

#[cfg(test)]
mod test {
    use rama_core::{
        ServiceInput,
        error::error_chain,
        io::peek::PeekTimeoutError,
        service::{RejectError, service_fn},
    };
    use std::{
        collections::VecDeque,
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::io::AsyncReadExt as _;

    use rama_core::io::Io;

    use super::*;

    const CH_ONE_ONE_ONE_ONE: &[u8] = &[
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x02, 0x15, 0xfd, 0xe2,
        0x92, 0xc0, 0x46, 0x9f, 0x92, 0xbe, 0xd7, 0xe9, 0x1a, 0x3c, 0x50, 0x5e, 0x55, 0x49, 0x17,
        0xa6, 0xf8, 0xa5, 0xca, 0xa4, 0x6d, 0x60, 0xcc, 0xea, 0xf7, 0x25, 0xf0, 0x6e, 0x20, 0x41,
        0x20, 0x18, 0x66, 0x5c, 0xae, 0x08, 0xb0, 0x10, 0x96, 0x3c, 0xad, 0xb4, 0x13, 0xe1, 0x92,
        0xce, 0x96, 0xad, 0x9d, 0x45, 0x05, 0xb7, 0xa6, 0x4c, 0x01, 0x71, 0x08, 0x74, 0x0d, 0x1f,
        0x35, 0x00, 0x2a, 0x3a, 0x3a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0, 0x2b,
        0xcc, 0xa9, 0xc0, 0x30, 0xc0, 0x2f, 0xcc, 0xa8, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0,
        0x13, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0xc0, 0x08, 0xc0, 0x12, 0x00, 0x0a,
        0x01, 0x00, 0x01, 0x89, 0xda, 0xda, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00,
        0x00, 0x0f, 0x6f, 0x6e, 0x65, 0x2e, 0x6f, 0x6e, 0x65, 0x2e, 0x6f, 0x6e, 0x65, 0x2e, 0x6f,
        0x6e, 0x65, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0c,
        0x00, 0x0a, 0xfa, 0xfa, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00,
        0x02, 0x01, 0x00, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
        0x16, 0x00, 0x14, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x08, 0x05,
        0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x33, 0x00,
        0x2b, 0x00, 0x29, 0xfa, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20, 0x7c, 0xe1, 0xc6,
        0xc2, 0x01, 0x69, 0x42, 0xba, 0x2b, 0xec, 0x07, 0x2f, 0x04, 0xbd, 0xb6, 0x2a, 0x7e, 0x04,
        0x6b, 0x96, 0x98, 0x51, 0x4e, 0x80, 0xb3, 0x2a, 0x4c, 0x4f, 0x1f, 0x39, 0x82, 0x2b, 0x00,
        0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x0b, 0x0a, 0x6a, 0x6a, 0x03, 0x04, 0x03,
        0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x01, 0x3a, 0x3a, 0x00,
        0x01, 0x00, 0x00, 0x15, 0x00, 0xd3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const TLS_BUT_NO_SNI: &[u8] = &[
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x28, 0x5b, 0x8f, 0x90,
        0x22, 0x2a, 0x90, 0x95, 0x89, 0xa9, 0x62, 0x1f, 0xdb, 0x68, 0xbe, 0x4c, 0x0e, 0xdf, 0xe4,
        0x76, 0x50, 0x48, 0xa5, 0x40, 0x56, 0x5f, 0x9a, 0xba, 0x19, 0x29, 0x66, 0xdd, 0x20, 0x7a,
        0x7f, 0x7e, 0xc7, 0xbd, 0xfb, 0x88, 0x07, 0xd9, 0xf5, 0x99, 0xfa, 0xf3, 0x0d, 0x37, 0x30,
        0x52, 0x4d, 0x44, 0xe4, 0x26, 0xc0, 0xd1, 0x9a, 0xcd, 0x78, 0xf6, 0x7a, 0xf1, 0x7a, 0x66,
        0xe1, 0x00, 0x3e, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f,
        0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0,
        0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
        0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00,
        0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x01, 0x75, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
        0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00,
        0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x10,
        0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e,
        0x31, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x0d,
        0x00, 0x2a, 0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08,
        0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
        0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00,
        0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00,
        0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xe0, 0xb9, 0xfb, 0x5a, 0xd5, 0x60,
        0x30, 0x39, 0xad, 0xfb, 0xd3, 0x94, 0xa2, 0xff, 0x08, 0x71, 0x9b, 0xcc, 0x6f, 0xbe, 0x9e,
        0xcc, 0x7b, 0xad, 0x3c, 0xd0, 0xde, 0xe8, 0x3e, 0x5d, 0xba, 0x6b, 0x00, 0x15, 0x00, 0xca,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[tokio::test]
    async fn test_sni_router() {
        let tls_service = service_fn(async |req: SniRequest<_>| {
            let sni = req.sni.map(|sni| sni.to_string());
            Ok::<_, Infallible>(sni)
        });
        let plain_service = service_fn(async || Ok::<_, Infallible>(Some("plain".to_owned())));

        let peek_tls_svc = SniRouter::new(tls_service).with_fallback(plain_service);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!(Some("plain".to_owned()), response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                CH_ONE_ONE_ONE_ONE.to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(Some("one.one.one.one".to_owned()), response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!(Some("plain".to_owned()), response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!(Some("plain".to_owned()), response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                TLS_BUT_NO_SNI.to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(None, response);
    }

    #[tokio::test]
    async fn test_peek_router_read_eof() {
        async fn tls_service_fn(
            SniRequest { mut stream, sni }: SniRequest<impl Io + Unpin>,
        ) -> Result<&'static str, BoxError> {
            let mut v = Vec::default();
            _ = stream.read_to_end(&mut v).await?;
            assert_eq!(CH_ONE_ONE_ONE_ONE, v);
            assert!(sni.is_some());
            assert_eq!("one.one.one.one", sni.unwrap());
            Ok("ok")
        }
        let tls_service = service_fn(tls_service_fn);

        let peek_tls_svc =
            SniRouter::new(tls_service).with_fallback(
                RejectService::<&'static str, RejectError>::new(RejectError::default()),
            );

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                CH_ONE_ONE_ONE_ONE.to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("ok", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_no_tls_eof() {
        let cases = ["", "foo", "abcd", "abcde", "foobarbazbananas"];
        for content in cases {
            async fn tls_service_fn() -> Result<Vec<u8>, BoxError> {
                Ok("tls".as_bytes().to_vec())
            }
            let tls_service = service_fn(tls_service_fn);

            async fn plain_service_fn(mut stream: impl Io + Unpin) -> Result<Vec<u8>, BoxError> {
                let mut v = Vec::default();
                _ = stream.read_to_end(&mut v).await?;
                Ok(v)
            }
            let plain_service = service_fn(plain_service_fn);

            let peek_tls_svc = SniRouter::new(tls_service).with_fallback(plain_service);

            let response = peek_tls_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    content.as_bytes().to_vec(),
                )))
                .await
                .unwrap();

            assert_eq!(content.as_bytes(), &response[..]);
        }
    }

    #[tokio::test]
    async fn test_peek_router_read_tls_no_sni_eof() {
        async fn tls_service_fn(
            SniRequest { mut stream, sni }: SniRequest<impl Io + Unpin>,
        ) -> Result<&'static str, BoxError> {
            let mut v = Vec::default();
            _ = stream.read_to_end(&mut v).await?;
            assert_eq!(TLS_BUT_NO_SNI, v);
            assert!(sni.is_none());
            Ok("ok")
        }
        let tls_service = service_fn(tls_service_fn);

        let peek_tls_svc =
            SniRouter::new(tls_service).with_fallback(
                RejectService::<&'static str, RejectError>::new(RejectError::default()),
            );

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                TLS_BUT_NO_SNI.to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("ok", response);
    }

    #[tokio::test]
    async fn record_fragmentation_selects_strict_sni_route_and_replays_wire_bytes() {
        use crate::client::test_support::{fragments, hello};
        for (padding, chunk_size) in [(0, 1), (60_000, rama_utils::octets::kib(16))] {
            let mut wire = fragments(&hello(padding), chunk_size);
            wire.extend_from_slice(b"following bytes");
            let router = SniRouter::new(service_fn(
                async |mut req: SniRequest<ServiceInput<ScriptedReader>>| {
                    assert_eq!(req.sni.as_ref().unwrap().as_str(), "x.com");
                    let mut replay = Vec::new();
                    tokio::io::AsyncReadExt::read_to_end(&mut req, &mut replay)
                        .await
                        .unwrap();
                    Ok::<_, Infallible>(replay)
                },
            ))
            .with_fallback(service_fn(async || Ok::<_, Infallible>(Vec::<u8>::new())));
            let stream = ScriptedReader::one_byte_per_read(&wire, false);
            assert_eq!(router.serve(ServiceInput::new(stream)).await.unwrap(), wire);
        }
    }

    #[tokio::test]
    async fn sni_router_propagates_configured_limits() {
        use crate::client::test_support::{fragments, hello};
        let message = hello(400);
        let wire = fragments(&message, 1);
        let router = SniRouter::new(service_fn(async |req: SniRequest<_>| {
            Ok::<_, Infallible>(req.sni.unwrap().to_string())
        }))
        .with_reassembly_config(
            ClientHelloReassemblyConfig::default().with_max_records(message.len()),
        )
        .with_fallback(service_fn(async || {
            Ok::<_, Infallible>("fallback".to_owned())
        }));
        assert_eq!(
            router
                .serve(ServiceInput::new(std::io::Cursor::new(wire.clone())))
                .await
                .unwrap(),
            "x.com"
        );
        router
            .with_malformed_tls_policy(MalformedTlsPolicy::Reject)
            .with_reassembly_config(ClientHelloReassemblyConfig::default())
            .serve(ServiceInput::new(std::io::Cursor::new(wire)))
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn fragmented_client_hello_sni_is_extracted() {
        // The ClientHello arriving one byte per read must still yield its SNI.
        // The previous single 2 KiB read (which required `read_size` to equal the
        // declared record length in one go) errored on any fragmentation; the
        // streaming peek now assembles it. This fails on `main` today.
        let tls_service = service_fn(async |req: SniRequest<_>| {
            Ok::<_, Infallible>(req.sni.map(|sni| sni.to_string()))
        });
        let plain_service = service_fn(async || Ok::<_, Infallible>(Some("plain".to_owned())));
        let peek_tls_svc = SniRouter::new(tls_service).with_fallback(plain_service);

        let stream = ScriptedReader::one_byte_per_read(CH_ONE_ONE_ONE_ONE, false);
        let response = peek_tls_svc.serve(ServiceInput::new(stream)).await.unwrap();
        assert_eq!(Some("one.one.one.one".to_owned()), response);
    }

    #[tokio::test]
    async fn fragmented_partial_client_hello_fail_closed_does_not_invoke_fallback() {
        const SPLIT_AT: usize = 64;

        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls_for_service = Arc::clone(&fallback_calls);
        let fallback = service_fn(move || {
            fallback_calls_for_service.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, Infallible>(Some("fallback".to_owned())) }
        });
        let router = SniRouter::new(service_fn(async || {
            Ok::<_, Infallible>(Some("tls".to_owned()))
        }))
        .with_peek_timeout(Duration::from_millis(10))
        .with_peek_policy(PeekPolicy::FAIL_CLOSED)
        .with_fallback(fallback);
        let stream = ScriptedReader::one_byte_per_read(&CH_ONE_ONE_ONE_ONE[..SPLIT_AT], true);

        let error = router.serve(ServiceInput::new(stream)).await.unwrap_err();

        assert!(error_chain_has_peek_timeout(error.as_ref()));
        assert_eq!(0, fallback_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn malformed_tls_client_hello_is_rejected() {
        // A non-ClientHello TLS handshake must never take a permissive fallback.
        let bytes = [
            0x16, 0x03, 0x03, 0x00, 0x06, 0x02, 0x00, 0x00, 0x02, 0xaa, 0xbb,
        ];
        for policy in [PeekPolicy::FAIL_OPEN, PeekPolicy::FAIL_CLOSED] {
            let tls_service =
                service_fn(async |_req: SniRequest<_>| Ok::<_, Infallible>(Some("tls".to_owned())));
            let plain_service = service_fn(async || Ok::<_, Infallible>(Some("plain".to_owned())));
            let peek_tls_svc = SniRouter::new(tls_service)
                .with_peek_timeout(Duration::from_millis(10))
                .with_peek_policy(policy)
                .with_malformed_tls_policy(MalformedTlsPolicy::Reject)
                .with_fallback(plain_service);

            peek_tls_svc
                .serve(ServiceInput::new(std::io::Cursor::new(bytes.to_vec())))
                .await
                .unwrap_err();
        }
    }

    #[tokio::test]
    async fn sni_default_fallback_receives_failure_marker_and_original_bytes() {
        use super::super::ClientHelloPeekStatus;
        use crate::client::test_support::{fragments, hello};
        use rama_core::io::peek::PeekStopReason;
        for wire in [vec![0x16, 3], vec![0x16, 3, 5], fragments(&hello(400), 1)] {
            let router = SniRouter::new(service_fn(async || Ok::<_, Infallible>(Vec::<u8>::new())))
                .with_fallback(service_fn(
                    async |mut io: SniPrefixedIo<ServiceInput<ScriptedReader>>| {
                        let status = io.extensions().get_ref::<ClientHelloPeekStatus>().unwrap();
                        assert!(matches!(
                            status.failure,
                            Some(PeekStopReason::Rejected | PeekStopReason::Eof)
                        ));
                        let mut replay = Vec::new();
                        tokio::io::AsyncReadExt::read_to_end(&mut io, &mut replay)
                            .await
                            .unwrap();
                        Ok::<_, Infallible>(replay)
                    },
                ));
            let stream = ScriptedReader::one_byte_per_read(&wire, false);
            assert_eq!(router.serve(ServiceInput::new(stream)).await.unwrap(), wire);
        }
    }

    #[tokio::test]
    async fn non_tls_prefix_then_idle_routes_to_fallback_without_blocking() {
        let tls_service =
            service_fn(async |_req: SniRequest<_>| Ok::<_, Infallible>(Some("tls".to_owned())));
        let plain_service = service_fn(async || Ok::<_, Infallible>(Some("plain".to_owned())));
        let peek_tls_svc = SniRouter::new(tls_service).with_fallback(plain_service);

        // Include binary non-TLS prefixes that resemble TLS for only one byte.
        // One byte per read plus an idle peer tests classification independently
        // of TCP segmentation, without relying on EOF to reach the fallback.
        for bytes in [
            &b"f"[..],
            &b"\x16GET"[..],
            &b"\x17hello"[..],
            &b"\x14\x00"[..],
        ] {
            let stream = ScriptedReader::one_byte_per_read(bytes, true);
            let response = tokio::time::timeout(
                Duration::from_secs(5),
                peek_tls_svc.serve(ServiceInput::new(stream)),
            )
            .await
            .expect("SNI router must fail fast on a non-TLS prefix, not block")
            .unwrap();
            assert_eq!(Some("plain".to_owned()), response);
        }
    }

    fn error_chain_has_peek_timeout(error: &(dyn std::error::Error + 'static)) -> bool {
        error_chain(error).any(|error| {
            error.is::<PeekTimeoutError>()
                || error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        })
    }

    /// A test stream yielding one byte per read from `data`, then either EOF or
    /// (when `idle_after`) pending forever — modelling both fragmentation and an
    /// idle-after-prefix peer.
    struct ScriptedReader {
        remaining: VecDeque<u8>,
        idle_after: bool,
    }

    impl ScriptedReader {
        fn one_byte_per_read(data: &[u8], idle_after: bool) -> Self {
            Self {
                remaining: data.iter().copied().collect(),
                idle_after,
            }
        }
    }

    impl AsyncRead for ScriptedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if let Some(byte) = self.remaining.pop_front() {
                buf.put_slice(&[byte]);
                Poll::Ready(Ok(()))
            } else if self.idle_after {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for ScriptedReader {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
