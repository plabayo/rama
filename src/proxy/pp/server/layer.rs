use std::net::SocketAddr;

use crate::{
    error::Error,
    proxy::pp::protocol::{v1, v2, HeaderResult, PartialResult},
    service::{Context, Layer, Service},
    stream::{SocketInfo, Stream},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    S: Service<State, IO>,
    S::Error: Into<Error>,
    IO: Stream + Unpin,
{
    type Response = S::Response;
    type Error = Error;

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

        match header {
            HeaderResult::V1(Ok(header)) => match header.addresses {
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
            },
            HeaderResult::V2(Ok(header)) => match header.addresses {
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
            },
            HeaderResult::V1(Err(error)) => {
                return Err(error.into());
            }
            HeaderResult::V2(Err(error)) => {
                return Err(error.into());
            }
        }

        stream.write_all(RESPONSE.as_bytes()).await?;
        stream.flush().await?;

        match self.inner.serve(ctx, stream).await {
            Ok(response) => Ok(response),
            Err(error) => Err(error.into()),
        }
    }
}

const RESPONSE: &str = "HTTP/1.1 200 OK\r\n\r\n";
