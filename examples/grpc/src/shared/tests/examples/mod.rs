use rama::{
    Service,
    error::{BoxError, extra::OpaqueError},
    graceful::WeakScope,
    http::{self, client::EasyHttpWebClient},
    net::{
        client::ConnectRequest,
        test_utils::client::{MockConnectorService, MockSocket},
    },
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
    F: Fn(&ConnectRequest) -> Server + Send + Sync + 'static,
    Server: Service<MockSocket, Error: Into<BoxError>>,
{
    EasyHttpWebClient::connector_builder(WeakScope::detached())
        .with_custom_tcp_connector(MockConnectorService::new(make_server))
        .without_dns_connector()
        .without_proxy_support()
        .without_tls_support()
        .with_default_http_connector()
        .with_default_connection_pool()
        .build_client()
        .boxed()
}
