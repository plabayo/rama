use super::utils::{self, ClientService};
use rama::{
    Context, Layer, Service,
    context::RequestContextExt,
    error::BoxError,
    http::{
        Response,
        client::{EasyHttpWebClient, TlsConnectorConfig},
        layer::{
            decompression::DecompressionLayer,
            follow_redirect::FollowRedirectLayer,
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
        },
    },
    layer::MapResultLayer,
    net::{
        address::{Domain, Host},
        tls::{
            ApplicationProtocol, DataEncoding,
            client::{
                ClientConfig, ClientHelloExtension, NegotiatedTlsParameters, ServerVerifyMode,
            },
        },
    },
    tls::boring::core::x509::X509,
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};

use std::{str::FromStr, time::Duration};

#[tokio::test]
#[ignore]
async fn test_tls_rustls_dynamic_certs() {
    utils::init_tracing();

    let chain = DataEncoding::DerStack(
        X509::stack_from_pem(include_bytes!(
            "../../../../examples/assets/example.com.crt"
        ))
        .unwrap()
        .into_iter()
        .map(|i| i.to_der().unwrap())
        .collect(),
    );

    let second_chain = DataEncoding::DerStack(
        X509::stack_from_pem(include_bytes!(
            "../../../../examples/assets/second_example.com.crt"
        ))
        .unwrap()
        .into_iter()
        .map(|i| i.to_der().unwrap())
        .collect(),
    );

    let default_chain = chain.clone();

    let tests: Vec<(DataEncoding, Option<&'static str>)> = vec![
        (chain, Some("example")),
        (second_chain, Some("second.example")),
        (default_chain, None),
    ];

    let mut runner = utils::ExampleRunner::interactive("tls_rustls_dynamic_certs", Some("rustls"));

    for (chain, host) in tests.into_iter() {
        let client = http_client(&host);
        runner.set_client(client);

        let response = runner
            .get("https://127.0.0.1:64802")
            .send(Context::default())
            .await
            .unwrap();

        let certificates = response
            .extensions()
            .get::<RequestContextExt>()
            .and_then(|ext| ext.get::<NegotiatedTlsParameters>())
            .unwrap()
            .peer_certificate_chain
            .clone()
            .unwrap();

        assert_eq!(chain, certificates);
    }
}

fn http_client<State>(host: &Option<&str>) -> ClientService<State>
where
    State: Clone + Send + Sync + 'static,
{
    let host = host.map(|host| Host::Name(Domain::from_str(host).unwrap()));
    let tls_config = ClientConfig {
        server_verify_mode: Some(ServerVerifyMode::Disable),
        extensions: Some(vec![
            ClientHelloExtension::ServerName(host),
            ClientHelloExtension::ApplicationLayerProtocolNegotiation(vec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11,
            ]),
        ]),
        store_server_certificate_chain: true,
        ..Default::default()
    };
    let mut inner_client = EasyHttpWebClient::new();
    inner_client.set_tls_connector_config(TlsConnectorConfig::Boring(Some(tls_config)));

    (
        MapResultLayer::new(map_internal_client_error),
        TraceLayer::new_for_http(),
        #[cfg(feature = "compression")]
        DecompressionLayer::new(),
        FollowRedirectLayer::default(),
        RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(100),
                    Duration::from_secs(60),
                    0.01,
                    HasherRng::default,
                )
                .unwrap(),
            ),
        ),
        AddRequiredRequestHeadersLayer::default(),
    )
        .into_layer(inner_client)
        .boxed()
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, rama::error::BoxError>
where
    E: Into<rama::error::BoxError>,
    Body: rama::http::dep::http_body::Body<Data = bytes::Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
