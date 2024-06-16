use crate::{
    http::{
        client::{ClientConnection, EstablishedClientConnection},
        Request, RequestContext,
    },
    net::{
        address::{Authority, ProxyAddress},
        stream::ServerSocketAddr,
    },
    service::{Context, Service},
};
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
#[non_exhaustive]
/// A connector which can be used to establish a connection to a server.
///
/// By default it will connect to the authority of the [`Request`] [`Uri`],
/// but in case a [`ServerSocketAddr`] is set in the [`Context`], it will
/// connect to the specified [`SocketAddr`] instead.
///
/// [`Request`]: crate::http::Request
/// [`Uri`]: crate::http::Uri
/// [`Context`]: crate::service::Context
pub struct HttpConnector;

impl HttpConnector {
    /// Create a new [`HttpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`HttpConnector`] to set a [`ServerSocketAddr`],
    /// or add connection pools, retry logic and more.
    pub fn new() -> Self {
        HttpConnector
    }
}

impl Default for HttpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl<State, Body> Service<State, Request<Body>> for HttpConnector
where
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = EstablishedClientConnection<TcpStream, Body, State>;
    type Error = std::io::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(proxy) = ctx.get::<ProxyAddress>() {
            let addr = resolve_authority(proxy.authority().clone()).await?;
            let stream = TcpStream::connect(&addr).await?;
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: ClientConnection::new(stream.peer_addr()?, stream),
            });
        }

        // TODO: remove this once we have a cleaner DnsStack >>> CTX <<<< approach *yawn*
        if let Some(server) = ctx.get::<ServerSocketAddr>() {
            let stream = TcpStream::connect(*server.addr()).await?;
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: ClientConnection::new(stream.peer_addr()?, stream),
            });
        }

        let request_info: &RequestContext = ctx.get_or_insert_from(&req);
        match request_info.authority.clone() {
            Some(authority) => {
                let socket_addr = resolve_authority(authority).await?;
                let stream = TcpStream::connect(&socket_addr).await?;
                Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: ClientConnection::new(socket_addr, stream),
                })
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing http authority",
            )),
        }
    }
}

// TODO: support custom dns resolvers
// TODO: use addr iter instead of just first

async fn resolve_authority(authority: Authority) -> Result<SocketAddr, std::io::Error> {
    crate::net::lookup_authority(authority)
        .await
        .and_then(|mut iter| match iter.next() {
            Some(addr) => Ok(addr),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty host lookup result for authority",
            )),
        })
}
