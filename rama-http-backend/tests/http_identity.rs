use std::convert::Infallible;

use rama_core::{Layer, service::service_fn};
use rama_http::{
    Body, HeaderValue, Request, Response,
    header::{self, SetIdentityError},
    headers::{Date, HeaderMapExt, Server, UserAgent},
    layer::required_header::{AddRequiredRequestHeadersLayer, AddRequiredResponseHeadersLayer},
    service::client::HttpClientExt,
};
use rama_http_backend::proxy::mitm::DefaultErrorResponse;

#[tokio::test]
async fn application_identity_and_explicit_overrides() {
    let layers = (
        AddRequiredRequestHeadersLayer::new(),
        AddRequiredResponseHeadersLayer::new(),
    );
    let echo = service_fn(async |req: Request| {
        let mut resp = Response::new(Body::empty());
        resp.headers_mut().insert(
            header::USER_AGENT,
            req.headers()[header::USER_AGENT].clone(),
        );
        Ok::<_, Infallible>(resp)
    });
    let client = layers.into_layer(echo.clone());
    for expected in [
        concat!("rama/", env!("CARGO_PKG_VERSION")),
        "Example Proxy/2",
    ] {
        if expected == "Example Proxy/2" {
            for invalid in ["bad\r\nvalue", "bad\0value", "bad\x7f", "雪"] {
                assert_eq!(
                    header::set_identity(invalid),
                    Err(SetIdentityError::InvalidValue)
                );
            }
            header::set_identity(expected).unwrap();
            assert_eq!(header::identity().as_bytes().as_ptr(), expected.as_ptr());
            assert_eq!(
                header::set_identity("Other/1"),
                Err(SetIdentityError::AlreadySet)
            );
        }
        let owned: HeaderValue = header::identity_header_str().clone().into();
        assert_eq!(owned.as_bytes().as_ptr(), header::identity().as_ptr());
        assert_eq!(
            header::identity_header().as_bytes().as_ptr(),
            header::identity().as_ptr()
        );
        assert_eq!(Server::default().as_str(), expected);
        assert_eq!(UserAgent::default().as_str(), expected);
        let resp = client.get("http://example.com/").send().await.unwrap();
        assert_eq!(resp.headers()[header::SERVER], expected);
        assert_eq!(resp.headers()[header::USER_AGENT], expected);
        check_connect_identity(expected).await.unwrap();
        let relay: Response = DefaultErrorResponse.into();
        assert_eq!(relay.status(), 502);
        assert_eq!(relay.headers()["x-proxy-framework"], expected);
        assert!(relay.headers().typed_get::<Date>().is_some());
    }

    let client = (
        AddRequiredRequestHeadersLayer::new()
            .with_user_agent_header_value(HeaderValue::from_static("client")),
        AddRequiredResponseHeadersLayer::new().with_server(Server::from_static("server")),
    )
        .into_layer(echo);
    let resp = client.get("http://example.com/").send().await.unwrap();
    assert_eq!(resp.headers()[header::SERVER], "server");
    assert_eq!(resp.headers()[header::USER_AGENT], "client");
}

async fn check_connect_identity(expected: &'static str) -> Result<(), rama_core::error::BoxError> {
    use rama_core::{Service, graceful::WeakScope};
    use rama_http_backend::{
        client::{HttpConnectorLayer, proxy::layer::HttpConnectProxyConnector},
        server::HttpServer,
    };
    use rama_net::{
        Protocol,
        address::HostWithPort,
        client::{ConnectRequest, ProxyRoute},
        test_utils::client::MockConnectorService,
    };
    let server = HttpServer::auto(WeakScope::detached()).service(service_fn(
        move |req: Request| async move {
            assert_eq!(req.method(), rama_http::Method::CONNECT);
            assert_eq!(
                req.headers()[header::USER_AGENT].as_bytes(),
                expected.as_bytes()
            );
            Ok::<_, Infallible>(Response::new(Body::empty()))
        },
    ));
    let connector = HttpConnectProxyConnector::<_, Body>::new(
        HttpConnectorLayer::default().into_layer(MockConnectorService::new(server)),
    );
    let input = ConnectRequest::new(HostWithPort::example_domain_https())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions
        .insert(ProxyRoute::Proxy("http://proxy.example:8080".parse()?));
    connector.serve(input).await?;
    Ok(())
}
