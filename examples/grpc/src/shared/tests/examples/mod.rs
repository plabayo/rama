use rama::{
    Service,
    error::{BoxError, OpaqueError},
    http::{self, Body, client::EasyHttpWebClient},
    net::test_utils::client::{MockConnectorService, MockSocket},
    rt::Executor,
    service::BoxService,
};

mod health;
mod helloworld;

pub(super) type WebClient = BoxService<http::Request, http::Response, OpaqueError>;

// TODO: might make sense in future to turn this into a general utility,
// for testing or generic one-time stuff. Be it perhaps with an actual error
// returned incase of duplicate consumptions.

pub(super) fn mock_io_client<F, Server>(make_server: F) -> WebClient
where
    F: Fn() -> Server + Send + Sync + 'static,
    Server: Service<MockSocket, Error: Into<BoxError>>,
{
    EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(MockConnectorService::new(make_server))
        .without_tls_proxy_support()
        .without_proxy_support()
        .without_tls_support()
        .with_default_http_connector::<Body>(Executor::default())
        .try_with_default_connection_pool()
        .unwrap()
        .build_client()
        .boxed()
}
