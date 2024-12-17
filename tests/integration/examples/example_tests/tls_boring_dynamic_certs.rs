use super::utils::{self, ClientService};
use rama::{
    error::{BoxError, OpaqueError},
    layer::MapResultLayer,
    Context, Layer, Service,
};
use rama_http::{
    dep::http_body,
    layer::{
        decompression::DecompressionLayer,
        follow_redirect::FollowRedirectLayer,
        required_header::AddRequiredRequestHeadersLayer,
        retry::{ManagedPolicy, RetryLayer},
        trace::TraceLayer,
    },
    Request, Response,
};
use rama_http_backend::client::HttpConnector;
use rama_net::{
    address::{Domain, Host},
    client::{ConnectorService, EstablishedClientConnection},
    tls::{
        client::{ClientConfig, ClientHelloExtension, NegotiatedTlsParameters, ServerVerifyMode},
        ApplicationProtocol, DataEncoding,
    },
};
use rama_tcp::client::service::TcpConnector;
use rama_tls::std::{client::TlsConnector, dep::boring::x509::X509};
use rama_utils::{backoff::ExponentialBackoff, rng::HasherRng};
use std::{str::FromStr, time::Duration};

#[tokio::test]
#[ignore]
async fn test_tls_boring_dynamic_certs() {
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

    let tests: Vec<(DataEncoding, Option<&'static str>)> = vec![
        (chain.clone(), Some("example")),
        (second_chain, Some("second.example")),
        (chain, None),
        // (chain, Some("google.com")),
    ];

    println!("spawning example");
    for (chain, host) in tests.into_iter() {
        let mut runner =
            utils::ExampleRunner::interactive("tls_boring_dynamic_certs", Some("boring"));

        let client = http_client(&host);
        runner.set_client(client);

        println!("repsonse");
        let response = runner
            .get("https://127.0.0.1:64801")
            .send(Context::default())
            .await
            .unwrap();
        println!("certs");

        let certificates = response
            .extensions()
            .get::<PeerCertificates>()
            .unwrap()
            .clone()
            .0;
        assert_eq!(chain, certificates.clone());
    }
}

fn http_client<State>(host: &Option<&str>) -> ClientService<State>
where
    State: Clone + Send + Sync + 'static,
{
    let host = host.map(|host| Host::Name(Domain::from_str(host).unwrap()));
    let inner_client = HttpClient::new(ClientConfig {
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
    });

    let client = (
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
        .layer(inner_client)
        .boxed();

    client
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

// Custom http client so we can extract client certificates. In the future
// this won't be needed once we can extract data out of context. This is a
// simplified version of the default http client.

// TODO refactor once a solution is merged to this issue: https://github.com/plabayo/rama/issues/364

#[derive(Debug, Clone)]
struct HttpClient {
    tls_config: ClientConfig,
}

impl HttpClient {
    fn new(tls_config: ClientConfig) -> Self {
        Self { tls_config }
    }
}

impl<State, Body> Service<State, Request<Body>> for HttpClient
where
    State: Clone + Send + Sync + 'static,
    Body: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Response = Response;
    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let tcp_connector = TcpConnector::new();
        let tls_connector_data = self.tls_config.clone().try_into().unwrap();
        let connector = HttpConnector::new(
            TlsConnector::auto(tcp_connector).with_connector_data(tls_connector_data),
        );

        let EstablishedClientConnection { ctx, req, conn, .. } =
            connector.connect(ctx, req).await.unwrap();

        // Extra logic to extract certificates
        let params = ctx.get::<NegotiatedTlsParameters>().unwrap();
        let cert_chain = params.peer_certificate_chain.clone().unwrap();
        let peer_certs = PeerCertificates(cert_chain);

        let mut resp = conn.serve(ctx, req).await.unwrap();
        resp.extensions_mut().insert(peer_certs);

        Ok(resp)
    }
}

#[derive(Debug, Clone)]
struct PeerCertificates(DataEncoding);
