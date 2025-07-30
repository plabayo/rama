use rama::{error::BoxError, Service};
use rama_net::{client::EstablishedClientConnection, transport::TryRefIntoTransportContext};

#[derive(Debug)]
struct TurmoilHttpStream {
    _inner: turmoil::net::TcpStream,
}

impl<State, Request> Service<State, Request> for TurmoilHttpStream
where
    State: Clone + Send + Sync + 'static,
    Request: rama_http_core::body::Body<Data: Clone + Send + Sync + 'static, Error: Into<BoxError>>
        + Unpin
        + Send
        + 'static,
{
    type Response = rama_http::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        _ctx: rama::Context<State>,
        _req: Request,
    ) -> Result<Self::Response, Self::Error> {
        todo!()
        //Ok(http::response::Builder::default()
        //    .status(200)
        //    .body(rama_http::Body::empty())
        //    .unwrap())
    }
}

#[derive(Debug, Clone)]
struct TurmoilTcpConnector;

impl<State, Request> Service<State, Request> for TurmoilTcpConnector
where
    State: Clone + Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State> + Send + 'static,
    Request::Error: Into<BoxError> + Send + Sync + 'static,
{
    type Response = EstablishedClientConnection<TurmoilHttpStream, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        _ctx: rama::Context<State>,
        _req: Request,
    ) -> Result<Self::Response, Self::Error> {
        todo!()
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
        let client: EasyHttpWebClient<
            (),
            Body,
            rama_net::client::EstablishedClientConnection<
                crate::types::TurmoilHttpStream,
                _,
                http::Request<_>,
            >,
        > = EasyHttpWebClientBuilder::default()
            .with_custom_transport_connector(connector)
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
