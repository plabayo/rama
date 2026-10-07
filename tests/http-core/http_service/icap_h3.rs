//! ICAP adaptation of an exchange received over HTTP/3: both directions travel through the
//! ICAP service as HTTP/1 heads (RFC 3507) and return to the HTTP/3 exchange.

use super::{TEST_TIMEOUT, client_with_http3, close_client_endpoint, credentials};
use rama::{
    Layer, Service,
    dns::client::DnsConnector,
    error::BoxError,
    http::{
        Body, Method, Request, Response, StatusCode, Version, body::util::BodyExt as _,
        header::HeaderValue, server::HttpServer,
    },
    icap::{
        client::Client as IcapClient,
        codec::{Header, ResponseLine},
        http::{
            HttpService, IncomingRequest,
            layer::{AdaptationLayer, ServiceEndpoint},
        },
        proto::{MethodKind, ServiceTag, StatusCode as IcapStatusCode},
        server::{OutgoingResponse, Server as IcapServer},
    },
    layer::ConsumeErrLayer,
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tcp::{client::service::TcpConnector, server::TcpListener},
    tls::server::TlsServerConfig,
};
use std::{convert::Infallible, sync::Arc};
use tokio::{spawn, time::timeout};

const TAG: ServiceTag = ServiceTag::from_static("rama-h3-icap-test");

/// Tag the request on REQMOD and the response on RESPMOD.
async fn adapt(request: IncomingRequest) -> Result<OutgoingResponse, BoxError> {
    match request.icap().method() {
        MethodKind::Reqmod => {
            let mut adapted = request.into_request()?;
            adapted
                .headers_mut()
                .insert("x-icap-request", HeaderValue::from_static("adapted"));
            Ok(OutgoingResponse::from_http_request(
                ResponseLine::new(IcapStatusCode::OK, b"OK")?,
                &[Header::new("ISTag", b"\"rama-h3-icap-test\"")?],
                adapted,
            )?)
        }
        MethodKind::Respmod => {
            let mut adapted = request.into_response()?;
            adapted
                .headers_mut()
                .insert("x-icap-response", HeaderValue::from_static("adapted"));
            Ok(OutgoingResponse::from_http_response(
                MethodKind::Respmod,
                ResponseLine::new(IcapStatusCode::OK, b"OK")?,
                &[Header::new("ISTag", b"\"rama-h3-icap-test\"")?],
                adapted,
            )?)
        }
        _ => Ok(request.respond_method_not_allowed(TAG)?),
    }
}

/// Answers with what it saw of the adapted request, echoing its body.
async fn origin(request: Request) -> Result<Response, Infallible> {
    let saw = |value: String| HeaderValue::try_from(value).unwrap();
    let mut response = Response::new(Body::empty());
    let headers = response.headers_mut();
    headers.insert("x-saw-version", saw(format!("{:?}", request.version())));
    // The adapted head gets its absolute target back, routable on any version.
    headers.insert("x-saw-target", saw(request.uri().to_string()));
    headers.insert(
        "x-saw-icap",
        request
            .headers()
            .get("x-icap-request")
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("none")),
    );
    let body = request.into_body().collect().await.unwrap().to_bytes();
    *response.body_mut() = Body::from(body);
    Ok(response)
}

#[tokio::test]
async fn icap_adapts_both_directions_of_an_http3_exchange() {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::new())
        .await
        .unwrap();
    let icap_address = listener.local_addr().unwrap();
    let icap_task =
        spawn(listener.serve(IcapServer::new(HttpService::new(service_fn(adapt)), TAG).unwrap()));

    let endpoint = ServiceEndpoint::new(format!("icap://{icap_address}/adapt")).unwrap();
    let adaptation = AdaptationLayer::new(Arc::new(IcapClient::new(DnsConnector::new(
        TcpConnector::new(),
    ))))
    .with_request_service(endpoint.clone())
    .with_response_service(endpoint);
    let service = (ConsumeErrLayer::trace_as_debug(), adaptation).into_layer(service_fn(origin));

    let (auth, tls) = credentials();
    let config = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let executor = Executor::new();
    let server_endpoint = Endpoint::build(executor.clone())
        .with_server_config(
            ServerConfig::try_from_rama_tls(&config, TlsOptions::default()).unwrap(),
        )
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let port = server_endpoint.local_addr().unwrap().port();
    let server_task = spawn({
        let endpoint = server_endpoint.clone();
        let server = HttpServer::new_http3(executor.clone());
        async move {
            while let Some(incoming) = endpoint.accept().await {
                let server = server.clone();
                let service = service.clone();
                executor.spawn_task(async move {
                    if let Ok(connection) = incoming.await {
                        _ = server.serve(connection, service).await;
                    }
                });
            }
        }
    });

    let (client, client_endpoint) = client_with_http3(tls).await;
    let request = Request::builder()
        .version(Version::HTTP_3)
        .method(Method::POST)
        .uri(format!("https://localhost:{port}/scan"))
        .body(Body::from("scan me"))
        .unwrap();
    let response = timeout(TEST_TIMEOUT, client.serve(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_3);
    let headers = response.headers().clone();
    assert_eq!(headers["x-icap-response"], "adapted");
    assert_eq!(headers["x-saw-icap"], "adapted");
    assert_eq!(headers["x-saw-version"], "HTTP/3.0");
    assert_eq!(
        headers["x-saw-target"],
        format!("https://localhost:{port}/scan")
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "scan me");

    close_client_endpoint(client_endpoint).await;
    server_endpoint.close(0u32, b"done");
    timeout(TEST_TIMEOUT, server_endpoint.shutdown())
        .await
        .unwrap();
    server_task.abort();
    icap_task.abort();
}
