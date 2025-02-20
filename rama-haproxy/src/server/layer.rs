use crate::protocol::{HeaderResult, PartialResult, v1, v2};
use rama_core::{
    Context, Layer, Service,
    error::{BoxError, ErrorExt},
};
use rama_net::{
    forwarded::{Forwarded, ForwardedElement},
    stream::{ChainReader, HeapReader, Stream},
};
use std::{fmt, net::SocketAddr};
use tokio::io::AsyncReadExt;

/// Layer to decode the HaProxy Protocol
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct HaProxyLayer;

impl HaProxyLayer {
    /// Create a new [`HaProxyLayer`].
    pub const fn new() -> Self {
        HaProxyLayer
    }
}

impl<S> Layer<S> for HaProxyLayer {
    type Service = HaProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HaProxyService { inner }
    }
}

/// Service to decode the HaProxy Protocol
///
/// This service will decode the HaProxy Protocol header and pass the decoded
/// information to the inner service.
pub struct HaProxyService<S> {
    inner: S,
}

impl<S> HaProxyService<S> {
    /// Create a new [`HaProxyService`] with the given inner service.
    pub const fn new(inner: S) -> Self {
        HaProxyService { inner }
    }
}

impl<S: fmt::Debug> fmt::Debug for HaProxyService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HaProxyService")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Clone> Clone for HaProxyService<S> {
    fn clone(&self) -> Self {
        HaProxyService {
            inner: self.inner.clone(),
        }
    }
}

impl<State, S, IO> Service<State, IO> for HaProxyService<S>
where
    State: Clone + Send + Sync + 'static,
    S: Service<
            State,
            tokio::io::Join<
                ChainReader<HeapReader, tokio::io::ReadHalf<IO>>,
                tokio::io::WriteHalf<IO>,
            >,
            Error: Into<BoxError>,
        >,
    IO: Stream + Unpin,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        mut stream: IO,
    ) -> Result<Self::Response, Self::Error> {
        let mut buffer = [0; 512];
        let mut read = 0;
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
        let (r, w) = tokio::io::split(stream);
        let mem: HeapReader = buffer[consumed..read].into();
        let r = ChainReader::new(mem, r);
        let stream = tokio::io::join(r, w);

        // read the rest of the data
        match self.inner.serve(ctx, stream).await {
            Ok(response) => Ok(response),
            Err(error) => Err(error.into()),
        }
    }
}
