use crate::protocol::{HeaderResult, PartialResult, v1, v2};
use rama_core::{
    Context, Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt},
};
use rama_net::{
    forwarded::{Forwarded, ForwardedElement},
    stream::{HeapReader, PeekStream, Stream},
};
use rama_utils::macros::generate_set_and_with;
use std::{fmt, net::SocketAddr};
use tokio::io::AsyncReadExt;

/// Layer to decode the HaProxy Protocol
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct HaProxyLayer {
    peek: bool,
}

impl HaProxyLayer {
    /// Create a new [`HaProxyLayer`].
    pub const fn new() -> Self {
        Self { peek: false }
    }

    generate_set_and_with!(
        /// Instruct [`HaProxyLayer`] to peek prior to comitting to the `HaProxy` protocol.
        ///
        /// Doing so makes it possible to support traffic with or without the use of that data.
        /// This can be useful to run services locally (not behind a loadbalancer) as well as in the
        /// the cloud (production, behind a loadbalancer).
        pub fn peek(mut self, value: impl Into<bool>) -> Self {
            self.peek = value.into();
            self
        }
    );
}

impl<S> Layer<S> for HaProxyLayer {
    type Service = HaProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HaProxyService {
            inner,
            peek: self.peek,
        }
    }
}

/// Service to decode the HaProxy Protocol
///
/// This service will decode the HaProxy Protocol header and pass the decoded
/// information to the inner service.
pub struct HaProxyService<S> {
    inner: S,
    peek: bool,
}

impl<S> HaProxyService<S> {
    /// Create a new [`HaProxyService`] with the given inner service.
    pub const fn new(inner: S) -> Self {
        HaProxyService { inner, peek: false }
    }

    generate_set_and_with!(
        /// Instruct [`HaProxyService`] to peek prior to comitting to the `HaProxy` protocol.
        ///
        /// Doing so makes it possible to support traffic with or without the use of that data.
        /// This can be useful to run services locally (not behind a loadbalancer) as well as in the
        /// the cloud (production, behind a loadbalancer).
        pub fn peek(mut self, value: impl Into<bool>) -> Self {
            self.peek = value.into();
            self
        }
    );
}

impl<S: fmt::Debug> fmt::Debug for HaProxyService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HaProxyService")
            .field("inner", &self.inner)
            .field("peek", &self.peek)
            .finish()
    }
}

impl<S: Clone> Clone for HaProxyService<S> {
    fn clone(&self) -> Self {
        HaProxyService {
            inner: self.inner.clone(),
            peek: self.peek,
        }
    }
}

impl<State, S, IO> Service<State, IO> for HaProxyService<S>
where
    State: Clone + Send + Sync + 'static,
    S: Service<State, PeekStream<HeapReader, IO>, Error: Into<BoxError>>,
    IO: Stream + Unpin,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        mut stream: IO,
    ) -> Result<Self::Response, Self::Error> {
        let (mut buffer, mut read) = if self.peek {
            tracing::trace!("haproxy protocol peeking enabled: start detection");

            let mut peek_buf = [0; v2::PROTOCOL_PREFIX.len()]; // sufficient for both v1 and v2

            let n = stream
                .read(&mut peek_buf)
                .await
                .context("try to read haProxy peek data")?;

            if peek_buf == v2::PROTOCOL_PREFIX {
                tracing::trace!(
                    "haproxy protocol peeked: v2 detected: continue with haproxy handling"
                );

                let mut buf = [0; 512];
                buf[..n].copy_from_slice(&peek_buf[..n]);
                (buf, n)
            } else if n > v1::PROTOCOL_PREFIX.len()
                && &peek_buf[..v1::PROTOCOL_PREFIX.len()] == v1::PROTOCOL_PREFIX.as_bytes()
            {
                tracing::trace!(
                    "haproxy protocol peeked: v1 detected: continue with haproxy handling"
                );

                let mut buf = [0; 512];
                buf[..n].copy_from_slice(&peek_buf[..n]);
                (buf, n)
            } else {
                tracing::trace!(
                    "no haproxy protocol detected... delegating immediately to inner..."
                );

                let mem = HeapReader::new(peek_buf[..n].into());
                let stream = PeekStream::new(mem, stream);
                return self.inner.serve(ctx, stream).await.map_err(Into::into);
            }
        } else {
            tracing::trace!("haproxy protocol enforced: skip peeking");
            ([0; 512], 0)
        };

        let header = loop {
            let n = stream.read(&mut buffer[read..]).await?;
            read += n;

            let header = HeaderResult::parse(&buffer[..read]);
            if header.is_complete() {
                break header;
            }

            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)
                    .context("HaProxy header incomplete")
                    .into_boxed());
            }

            tracing::debug!("Incomplete header. Read {} bytes so far.", read);
        };

        let consumed = match header {
            HeaderResult::V1(Ok(header)) => {
                match header.addresses {
                    v1::Addresses::Tcp4(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let el = ForwardedElement::forwarded_for(peer_addr);
                        match ctx.get_mut::<Forwarded>() {
                            Some(forwarded) => {
                                forwarded.append(el);
                            }
                            None => {
                                let forwarded = Forwarded::new(el);
                                ctx.insert(forwarded);
                            }
                        }
                    }
                    v1::Addresses::Tcp6(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let el = ForwardedElement::forwarded_for(peer_addr);
                        match ctx.get_mut::<Forwarded>() {
                            Some(forwarded) => {
                                forwarded.append(el);
                            }
                            None => {
                                let forwarded = Forwarded::new(el);
                                ctx.insert(forwarded);
                            }
                        }
                    }
                    v1::Addresses::Unknown => (),
                };
                header.header.len()
            }
            HeaderResult::V2(Ok(header)) => {
                match header.addresses {
                    v2::Addresses::IPv4(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let el = ForwardedElement::forwarded_for(peer_addr);
                        match ctx.get_mut::<Forwarded>() {
                            Some(forwarded) => {
                                forwarded.append(el);
                            }
                            None => {
                                let forwarded = Forwarded::new(el);
                                ctx.insert(forwarded);
                            }
                        }
                    }
                    v2::Addresses::IPv6(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let el = ForwardedElement::forwarded_for(peer_addr);
                        match ctx.get_mut::<Forwarded>() {
                            Some(forwarded) => {
                                forwarded.append(el);
                            }
                            None => {
                                let forwarded = Forwarded::new(el);
                                ctx.insert(forwarded);
                            }
                        }
                    }
                    v2::Addresses::Unix(_) | v2::Addresses::Unspecified => (),
                };
                header.header.len()
            }
            HeaderResult::V1(Err(error)) => {
                return Err(error.into());
            }
            HeaderResult::V2(Err(error)) => {
                return Err(error.into());
            }
        };

        // put back the data that is read too much
        let mem: HeapReader = buffer[consumed..read].into();
        let stream = PeekStream::new(mem, stream);

        // read the rest of the data
        self.inner.serve(ctx, stream).await.map_err(Into::into)
    }
}
