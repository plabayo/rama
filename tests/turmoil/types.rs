use rama::{error::BoxError, Context, Service};
use rama_http::Request;
use rama_net::{client::EstablishedClientConnection, transport::TryRefIntoTransportContext};
use tokio::io::AsyncWriteExt;

#[derive(Debug)]
struct TurmoilHttpStream {
    inner: turmoil::net::TcpStream,
}

// TODO:: investigate decoupling rama_tcp::client::tcp_connect from tokio::net::TcpStream
///// Establish a [`TcpStream`] connection for the given [`Authority`].
//pub async fn tcp_connect<State, Dns, Connector>(
//    ctx: &Context<State>,
//    authority: Authority,
//    dns: Dns,
//    connector: Connector,
//) -> Result<(TcpStream, SocketAddr), OpaqueError>
//where
//    State: Clone + Send + Sync + 'static,
//    Dns: DnsResolver + Clone,
//    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
//{
//

#[derive(Debug, Clone)]
pub struct TurmoilTcpConnector;

impl<State, Request> Service<State, Request> for TurmoilTcpConnector
where
    State: Clone + Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State> + Send + 'static,
    Request::Error: Into<BoxError> + Send + Sync + 'static,
{
    // Return the raw turmoil::net::TcpStream directly
    type Response = EstablishedClientConnection<turmoil::net::TcpStream, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let transport_context = req.try_ref_into_transport_ctx(&ctx).map_err(Into::into)?;
        let authority = &transport_context.authority;
        let host = authority.host();
        let port = authority.port();
        let address = format!("{host}:{port}");

        let conn = turmoil::net::TcpStream::connect(address)
            .await
            .map_err(BoxError::from)?;

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn, // Raw turmoil::net::TcpStream
        })
    }
}

#[cfg(test)]
mod discover_interface_tests {
    use rama::{
        http::{client::EasyHttpWebClient, Body, Request},
        Context, Service,
    };
    use rama_http_backend::client::EasyHttpWebClientBuilder;

    use super::TurmoilTcpConnector;

    #[tokio::test]
    async fn discover_interface_for_established_client_connection(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connector = TurmoilTcpConnector;

        let client = EasyHttpWebClientBuilder::default()
            .with_custom_transport_connector(connector)
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .build();
        let _resp = client
            .serve(
                Context::default(),
                Request::builder()
                    .uri(format!("http://{address}/", address = "google.com"))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await?;

        Ok(())
    }
}
