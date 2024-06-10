use std::net::SocketAddr;

use crate::{
    error::BoxError,
    net::stream::{ChainReader, HeapReader, SocketInfo, Stream},
    proxy::pp::protocol::{v1, v2, HeaderResult, PartialResult},
    service::{Context, Layer, Service},
};
use tokio::io::AsyncReadExt;

/// Layer to decode the HaProxy Protocol
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct HaProxyLayer;

impl HaProxyLayer {
    /// Create a new [`HaProxyLayer`].
    pub fn new() -> Self {
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
#[derive(Debug, Clone)]
pub struct HaProxyService<S> {
    inner: S,
}

impl<S> HaProxyService<S> {
    /// Create a new [`HaProxyService`] with the given inner service.
    pub fn new(inner: S) -> Self {
        HaProxyService { inner }
    }
}

impl<State, S, IO> Service<State, IO> for HaProxyService<S>
where
    State: Send + Sync + 'static,
    S: Service<
        State,
        tokio::io::Join<ChainReader<HeapReader, tokio::io::ReadHalf<IO>>, tokio::io::WriteHalf<IO>>,
    >,
    S::Error: Into<BoxError>,
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
            read += stream.read(&mut buffer[read..]).await?;

            let header = HeaderResult::parse(&buffer[..read]);
            if header.is_complete() {
                break header;
            }

            tracing::debug!("Incomplete header. Read {} bytes so far.", read);
        };

        let consumed = match header {
            HeaderResult::V1(Ok(header)) => {
                match header.addresses {
                    v1::Addresses::Tcp4(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let socket_info = SocketInfo::new(None, peer_addr);
                        ctx.insert(socket_info);
                    }
                    v1::Addresses::Tcp6(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let socket_info = SocketInfo::new(None, peer_addr);
                        ctx.insert(socket_info);
                    }
                    v1::Addresses::Unknown => (),
                };
                header.header.len()
            }
            HeaderResult::V2(Ok(header)) => {
                match header.addresses {
                    v2::Addresses::IPv4(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let socket_info = SocketInfo::new(None, peer_addr);
                        ctx.insert(socket_info);
                    }
                    v2::Addresses::IPv6(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let socket_info = SocketInfo::new(None, peer_addr);
                        ctx.insert(socket_info);
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
