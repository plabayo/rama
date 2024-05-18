use crate::{
    http::{
        client::{ClientConnection, EstablishedClientConnection},
        Request, RequestContext,
    },
    proxy::ProxySocketAddr,
    service::{Context, Service},
    stream::ServerSocketAddr,
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
        match ctx
            .get::<ProxySocketAddr>()
            .map(|proxy| *proxy.addr())
            .or_else(|| ctx.get::<ServerSocketAddr>().map(|server| *server.addr()))
        {
            Some(addr) => {
                let stream = TcpStream::connect(&addr).await?;
                Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: ClientConnection::new(addr, stream),
                })
            }
            None => {
                let request_info = ctx.get_or_insert_with(|| RequestContext::new(&req));
                match request_info.authority() {
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
    }
}

async fn resolve_authority(authority: String) -> Result<SocketAddr, std::io::Error> {
    match authority.parse::<SocketAddr>() {
        Ok(addr) => Ok(addr),
        Err(_) => tokio::net::lookup_host(&authority)
            .await
            .and_then(|mut iter| match iter.next() {
                Some(addr) => Ok(addr),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("empty host lookup result for authority: {}", authority),
                )),
            }),
    }
}
