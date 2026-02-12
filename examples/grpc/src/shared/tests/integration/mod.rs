use rama::{
    Service,
    error::BoxError,
    http::{self, Body, client::EasyHttpWebClient},
    net::test_utils::client::{MockConnectorService, MockSocket},
    rt::Executor,
    service::BoxService,
};

pub mod pb {
    rama::http::grpc::include_proto!("integration_test");
    rama::http::grpc::include_proto!("integration_stream");
}

mod client_layer;
mod http2_keep_alive;
mod http2_max_header_list_size;
mod max_message_size;
mod timeout;

pub(super) type WebClient = BoxService<http::Request, http::Response, BoxError>;

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
