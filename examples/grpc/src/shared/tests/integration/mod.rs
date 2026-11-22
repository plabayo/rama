use rama::{
    Service,
    error::{BoxError, extra::OpaqueError},
    graceful::WeakScope,
    http::{self, client::EasyHttpWebClient},
    net::test_utils::client::{MakeMockServer, MockConnectorService, MockSocket},
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

pub(super) type WebClient = BoxService<http::Request, http::Response, OpaqueError>;

pub(super) fn mock_io_client<F, M>(make_server: F) -> WebClient
where
    F: MakeMockServer<MockSocket, M, Server: Service<MockSocket, Error: Into<BoxError>>>
        + Send
        + Sync
        + 'static,
    M: Send + Sync + 'static,
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
