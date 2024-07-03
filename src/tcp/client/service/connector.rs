use crate::{
    error::{ErrorContext, OpaqueError},
    http::{
        client::{ClientConnection, EstablishedClientConnection},
        get_request_context, Request,
    },
    net::address::ProxyAddress,
    service::{Context, Service},
    tcp,
};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
#[non_exhaustive]
/// A connector which can be used to establish a TCP connection to a server.
///
/// [`Request`]: crate::http::Request
/// [`Uri`]: crate::http::Uri
/// [`Context`]: crate::service::Context
pub struct HttpConnector;

impl HttpConnector {
    /// Create a new [`HttpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`HttpConnector`]
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
    type Error = OpaqueError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(proxy) = ctx.get::<ProxyAddress>() {
            let (stream, addr) = tcp::client::connect_trusted(&ctx, proxy.authority().clone())
                .await
                .context("tcp connector: conncept to proxy")?;
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: ClientConnection::new(addr, stream),
            });
        }

        let request_info = get_request_context!(ctx, req);
        match request_info.authority.clone() {
            Some(authority) => {
                let (stream, addr) = tcp::client::connect(&ctx, authority)
                    .await
                    .context("tcp connector: connect to server")?;
                Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: ClientConnection::new(addr, stream),
                })
            }
            None => Err(OpaqueError::from_display(
                "tcp connector: missing authority in request ctx",
            )),
        }
    }
}
