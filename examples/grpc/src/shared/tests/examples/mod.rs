use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

use rama::{
    Service as _, ServiceInput,
    error::OpaqueError,
    http::{self, Body, client::EasyHttpWebClient},
    net::client::EstablishedClientConnection,
    service::{BoxService, service_fn},
};

mod health;
mod helloworld;

pub(super) type WebClient = BoxService<http::Request, http::Response, OpaqueError>;

// TODO: might make sense in future to turn this into a general utility,
// for testing or generic one-time stuff. Be it perhaps with an actual error
// returned incase of duplicate consumptions.

fn mock_io_client(client: tokio::io::DuplexStream) -> WebClient {
    let client_opt = Arc::new(Mutex::new(Some(client)));
    EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(service_fn(move |input: http::Request| {
            let client = client_opt.lock().unwrap().take().unwrap();
            async move {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(client),
                })
            }
        }))
        .without_tls_proxy_support()
        .without_proxy_support()
        .without_tls_support()
        .with_default_http_connector::<Body>()
        .try_with_default_connection_pool()
        .unwrap()
        .build_client()
        .boxed()
}
