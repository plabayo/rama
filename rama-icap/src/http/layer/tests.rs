use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{
    Layer as _, Service as _, ServiceInput,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::{Extension, ExtensionsRef as _},
    futures::{StreamExt as _, stream},
    io::Io,
    rt::Executor,
    service::{BoxService, service_fn},
};
use rama_http::io::upgrade;
use rama_http_backend::{client::proxy::layer::HttpProxyConnectorLayer, server::HttpServer};
use rama_http_types::{
    Body, HeaderMap, Request, Response,
    body::{Frame, util::BodyExt as _},
    header::{self as http_header, HeaderValue, TRAILER},
};
use rama_net::{
    AuthorityInputExt, ConnectorTargetInputExt as _, Protocol, ProtocolInputExt,
    TransportProtocolInputExt as _, UriInputExt,
    address::{Domain, ProxyAddress},
    client::{
        ConnectRequest, ConnectorTarget, EstablishedClientConnection, ProxyRoute,
        pool::{BasicConnIdentifier, ConnID, LruDropPool, PooledConnector},
    },
    test_utils::client::{MockConnectorService, MockSocket},
};
use rama_tls::{
    SecureTransport,
    client::{ServerVerifyMode, TlsClientConfig},
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_tls_boring::client::TlsConnector as BoringTlsConnector;
use rama_tls_rustls::{client::TlsConnector, server::TlsAcceptorLayer};

use super::*;
use crate::{
    client::options::{OptionsCacheLayer, OptionsService, OptionsValidation, ServiceCapabilities},
    codec::{HeadParserConfig, Header, HeaderFolding, HeaderSlot, ResponseLine},
    http::{HttpService, IncomingRequest, IncomingRequestParts, OutgoingResponse},
    io::ConnectionOptions,
    message::{EncapsulatedParts, Response as IcapResponse},
    proto::{EncapsulatedKind, Method, MethodKind, Preview, ServiceTag, StatusCode, header},
    server::{
        BodyFrame, IncomingRequest as RawIncomingRequest, OptionsResponse, OutgoingBody, Server,
    },
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::Notify,
    time::timeout,
};

const TEST_SERVICE_TAG: ServiceTag = ServiceTag::from_static("rama-test");
const LAYER_SERVICE_TAG: ServiceTag = ServiceTag::from_static("layer-test");
const OPTIONS_SERVICE_TAG: ServiceTag = ServiceTag::from_static("options-test");
const CHANGED_SERVICE_TAG: ServiceTag = ServiceTag::from_static("changed");

fn endpoint(path: &str) -> ServiceEndpoint {
    ServiceEndpoint::new(format!("icap://icap.test/{path}"))
        .unwrap()
        .with_preview(Preview::new(4))
        .with_allow_206(true)
}

fn adaptation_response_fields() -> [Header<'static>; 1] {
    adaptation_response_fields_with_tag(b"\"layer-test\"")
}

fn adaptation_response_fields_with_tag(service_tag: &'static [u8]) -> [Header<'static>; 1] {
    [Header::new(header::ISTAG, service_tag).unwrap()]
}

const REQUEST_HEADER_LINES: &[(&str, &str)] = &[
    ("X-FOO-bar", "hello"),
    ("content-type", "text/plain"),
    ("x-Foo-BAR", "goodbye"),
    ("host", "origin.test"),
];

const RESPONSE_HEADER_LINES: &[(&str, &str)] = &[
    ("X-Response-FOO", "hello"),
    ("content-type", "text/plain"),
    ("x-Response-Foo", "goodbye"),
];

fn assert_header_lines(headers: &HeaderMap, expected: &[(&str, &str)]) {
    let actual = headers
        .ordered_iter()
        .map(|(name, value)| {
            (
                name.as_original_str().into_owned(),
                value.to_str().unwrap().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let expected = expected
        .iter()
        .map(|&(name, value)| (name.to_owned(), value.to_owned()))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

fn discovered_capabilities() -> ServiceCapabilities {
    let response = IcapResponse::new(
        MethodKind::Options,
        ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
        &[
            Header::new(header::METHODS, b"REQMOD, RESPMOD").unwrap(),
            Header::new(header::ISTAG, b"\"options-test\"").unwrap(),
            Header::new(header::PREVIEW, b"2").unwrap(),
            Header::new(header::ALLOW, b"204, 206").unwrap(),
            Header::new(header::TRANSFER_PREVIEW, b"*").unwrap(),
        ],
        Some(EncapsulatedParts::null()),
    )
    .unwrap();
    ServiceCapabilities::parse(response, None, 16, true, OptionsValidation::Compatible).unwrap()
}

fn discovered_transfer_capabilities(
    transfer_preview: &'static [u8],
    transfer_ignore: Option<&'static [u8]>,
    transfer_complete: Option<&'static [u8]>,
) -> ServiceCapabilities {
    let mut fields = vec![
        Header::new(header::METHODS, b"REQMOD, RESPMOD").unwrap(),
        Header::new(header::ISTAG, b"\"options-test\"").unwrap(),
        Header::new(header::PREVIEW, b"2").unwrap(),
        Header::new(header::TRANSFER_PREVIEW, transfer_preview).unwrap(),
    ];
    if let Some(value) = transfer_ignore {
        fields.push(Header::new(header::TRANSFER_IGNORE, value).unwrap());
    }
    if let Some(value) = transfer_complete {
        fields.push(Header::new(header::TRANSFER_COMPLETE, value).unwrap());
    }
    let response = IcapResponse::new(
        MethodKind::Options,
        ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
        &fields,
        Some(EncapsulatedParts::null()),
    )
    .unwrap();
    ServiceCapabilities::parse(response, None, 16, false, OptionsValidation::Compatible).unwrap()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestConnectionId;

impl ConnID for TestConnectionId {}

#[derive(Debug, Extension)]
struct EndpointExtension(&'static str);

fn test_connection_id(_input: &ConnectRequest) -> Result<TestConnectionId, BoxError> {
    Ok(TestConnectionId)
}

fn mock_icap_client<S>(
    create_server: S,
    max_buffer_size: usize,
) -> crate::client::Client<MockConnectorService<S>> {
    crate::client::Client::new(
        MockConnectorService::new(create_server).with_max_buffer_size(max_buffer_size),
    )
}

#[derive(Clone)]
struct TlsIcapHandler<S> {
    adaptation: S,
    secure: bool,
    port: Option<u16>,
}

impl<S> rama_core::Service<RawIncomingRequest> for TlsIcapHandler<S>
where
    S: rama_core::Service<RawIncomingRequest, Output = OutgoingResponse, Error = BoxError>,
{
    type Output = OutgoingResponse;
    type Error = BoxError;

    async fn serve(&self, request: RawIncomingRequest) -> Result<OutgoingResponse, BoxError> {
        assert_eq!(
            request.extensions().contains::<SecureTransport>(),
            self.secure,
        );
        let method = request.request().method();
        {
            let mut slots = [HeaderSlot::EMPTY; 16];
            let head = request.request().parse_head(&mut slots)?;
            let uri = head.line().uri();
            assert_eq!(uri.scheme(), &Protocol::ICAP);
            assert_eq!(uri.host(), Some("icap.test"));
            assert_eq!(uri.path(), "/scan");
            assert_eq!(uri.port().as_u16(), self.port);
            let expected_host = self.port.map_or_else(
                || "icap.test".to_owned(),
                |port| format!("icap.test:{port}"),
            );
            assert_eq!(
                head.header(header::HOST).and_then(|value| value.as_bytes()),
                Some(expected_host.as_bytes()),
            );
        }
        match method {
            MethodKind::Options => {
                OptionsResponse::new(TEST_SERVICE_TAG, &[Method::Reqmod, Method::Respmod])
                    .build()
                    .map_err(Into::into)
            }
            MethodKind::Reqmod | MethodKind::Respmod => self.adaptation.serve(request).await,
            MethodKind::Extension => Err(BoxError::from_static_str(
                "unexpected ICAP extension method",
            )),
        }
    }
}

#[derive(Clone)]
struct TlsIcapConnectionServer<S> {
    inner: Server<S>,
}

impl<S, IO> rama_core::Service<IO> for TlsIcapConnectionServer<S>
where
    IO: Io + Unpin + rama_core::extensions::ExtensionsRef,
    S: rama_core::Service<RawIncomingRequest, Output = OutgoingResponse, Error = BoxError>,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, io: IO) -> Result<(), Infallible> {
        if let Err(error) = self.inner.serve_connection(io).await {
            assert_eq!(error.kind(), crate::server::ServerErrorKind::Connection);
        }
        Ok(())
    }
}

async fn serve_adaptation(request: IncomingRequest) -> Result<OutgoingResponse, BoxError> {
    serve_adaptation_with_service_tag(request, LAYER_SERVICE_TAG).await
}

async fn serve_adaptation_with_service_tag(
    request: IncomingRequest,
    service_tag: ServiceTag,
) -> Result<OutgoingResponse, BoxError> {
    let method = request.icap().method();
    let (parts, body) = request.into_parts();
    let IncomingRequestParts { encapsulated, .. } = parts;
    let encapsulated = encapsulated.expect("typed HTTP metadata");
    let collected = body.collect().await?;
    let body = Body::new(collected);
    let line = ResponseLine::new(StatusCode::OK, b"OK").unwrap();
    let service_tag = service_tag.to_wire();
    let fields = [Header::new(header::ISTAG, service_tag.as_bytes()).unwrap()];
    match method {
        MethodKind::Reqmod => {
            let mut request = encapsulated.request.expect("REQMOD request head");
            request
                .headers_mut()
                .insert("x-reqmod", HeaderValue::from_static("yes"));
            OutgoingResponse::from_http_request(
                line,
                &fields,
                Request::from_parts(request.clone_parts(), body),
            )
            .map_err(Into::into)
        }
        MethodKind::Respmod => {
            let mut response = encapsulated.response.expect("RESPMOD response head");
            response
                .headers_mut()
                .insert("x-respmod", HeaderValue::from_static("yes"));
            OutgoingResponse::from_http_response(
                MethodKind::Respmod,
                line,
                &fields,
                Response::from_parts(response.clone_parts(), body),
            )
            .map_err(Into::into)
        }
        _ => Err(BoxError::from_static_str(
            "HTTP adaptation only uses REQMOD and RESPMOD",
        )),
    }
}

async fn serve_header_preserving_adaptation(
    request: IncomingRequest,
) -> Result<OutgoingResponse, BoxError> {
    let method = request.icap().method();
    let (parts, body) = request.into_parts();
    let encapsulated = parts.encapsulated.expect("typed HTTP metadata");
    let body = Body::new(body.collect().await?);
    let line = ResponseLine::new(StatusCode::OK, b"OK").unwrap();
    let fields = adaptation_response_fields();

    match method {
        MethodKind::Reqmod => {
            let request = encapsulated.request.expect("REQMOD request head");
            assert_header_lines(request.headers(), REQUEST_HEADER_LINES);
            assert_eq!(request.uri().as_str(), "http://origin.test/upload");
            OutgoingResponse::from_http_request(
                line,
                &fields,
                Request::from_parts(request.clone_parts(), body),
            )
            .map_err(Into::into)
        }
        MethodKind::Respmod => {
            let response = encapsulated.response.expect("RESPMOD response head");
            assert_header_lines(response.headers(), RESPONSE_HEADER_LINES);
            OutgoingResponse::from_http_response(
                MethodKind::Respmod,
                line,
                &fields,
                Response::from_parts(response.clone_parts(), body),
            )
            .map_err(Into::into)
        }
        _ => Err(BoxError::from_static_str(
            "header preservation only uses REQMOD and RESPMOD",
        )),
    }
}

async fn serve_adaptation_with_outer_trailers(
    request: IncomingRequest,
) -> Result<OutgoingResponse, BoxError> {
    assert!(request.icap().allows_icap_trailers());
    let response = serve_adaptation(request).await?;
    let (parts, body) = response.into_parts();
    let crate::server::OutgoingResponseParts {
        response, body_end, ..
    } = parts;
    assert_eq!(body_end, crate::server::OutgoingBodyEnd::Complete);
    let response = IcapResponse::new_with_icap_trailer_names(
        response.method(),
        ResponseLine::new(response.status(), b"OK")?,
        &adaptation_response_fields(),
        response
            .encapsulated()
            .context("adapted response body has no Encapsulated metadata")?
            .clone(),
        crate::message::IcapTrailerNames::new(["X-Scan"])?,
    )?;
    let body = OutgoingBody::from_frames(body.chain(stream::once(async {
        Ok::<_, BoxError>(BodyFrame::icap_trailers(
            crate::message::TrailerBlock::from_bytes(Bytes::from_static(b"X-Scan: clean\r\n\r\n"))?,
        ))
    })));
    Ok(OutgoingResponse::new(response, body))
}

async fn serve_blocking_adaptation(request: IncomingRequest) -> Result<OutgoingResponse, BoxError> {
    let method = request.icap().method();
    let line = ResponseLine::new(StatusCode::OK, b"OK").unwrap();
    match method {
        MethodKind::Reqmod => {
            let fields = [
                Header::new(header::ISTAG, b"\"layer-test\"").unwrap(),
                Header::new(header::PROXY_AUTHENTICATE, b"Basic realm=blocked").unwrap(),
            ];
            let mut trailers = HeaderMap::new();
            trailers.insert("x-block-end", HeaderValue::from_static("yes"));
            let response = Response::builder()
                .status(403)
                .header("x-blocked", "yes")
                .body(Body::from_frame_stream(stream::iter([
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"blocked"))),
                    Ok(Frame::trailers(trailers)),
                ])))
                .unwrap();
            OutgoingResponse::from_http_response(MethodKind::Reqmod, line, &fields, response)
                .map_err(Into::into)
        }
        _ => Err(BoxError::from_static_str(
            "blocking HTTP adaptation only uses REQMOD",
        )),
    }
}

#[tokio::test]
async fn detours_request_and_response_with_preview() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let transport = MockConnectorService::new(|| {
        Server::new(
            HttpService::new(service_fn(serve_adaptation_with_outer_trailers)),
            TEST_SERVICE_TAG,
        )
        .unwrap()
    })
    .with_max_buffer_size(256);
    let connector = service_fn(move |input: ConnectRequest| {
        let connector_connections = Arc::clone(&connector_connections);
        let transport = transport.clone();
        async move {
            assert_eq!(input.authority.to_string(), "icap.test:1344");
            assert_eq!(input.protocol(), Some(&Protocol::ICAP));
            assert_eq!(input.transport_protocol(), None);
            connector_connections.fetch_add(1, Ordering::Relaxed);
            transport.serve(input).await
        }
    });
    let connector = crate::client::Client::new(connector);

    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.headers()["x-reqmod"], "yes");
        assert_eq!(request.headers()[TRAILER], "x-request-end");
        assert!(request.extensions().contains::<ReqmodResult>());
        let request_body = request.into_body().collect().await.unwrap();
        assert_eq!(request_body.trailers().unwrap()["x-request-end"], "yes");
        assert_eq!(request_body.to_bytes(), "request-body");
        let mut trailers = HeaderMap::new();
        trailers.insert("x-response-end", HeaderValue::from_static("yes"));
        Ok::<_, Infallible>(
            Response::builder()
                .status(201)
                .header("x-origin", "yes")
                .header(TRAILER, "x-response-end")
                .body(Body::from_frame_stream(stream::iter([
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"response-body"))),
                    Ok(Frame::trailers(trailers)),
                ])))
                .unwrap(),
        )
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod").with_allow_icap_trailers(true))
        .with_response_service(endpoint("respmod").with_allow_icap_trailers(true))
        .layer(inner);
    let mut request_trailers = HeaderMap::new();
    request_trailers.insert("x-request-end", HeaderValue::from_static("yes"));
    let response = service
        .serve(
            Request::builder()
                .method("POST")
                .uri("/upload")
                .header(TRAILER, "x-request-end")
                .body(Body::from_frame_stream(stream::iter([
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"request-body"))),
                    Ok(Frame::trailers(request_trailers)),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 201);
    assert_eq!(response.headers()["x-origin"], "yes");
    assert_eq!(response.headers()["x-respmod"], "yes");
    assert_eq!(response.headers()[TRAILER], "x-response-end");
    assert!(response.extensions().contains::<ReqmodResult>());
    assert!(response.extensions().contains::<RespmodResult>());
    let response_body = response.into_body().collect().await.unwrap();
    assert_eq!(response_body.trailers().unwrap()["x-response-end"], "yes");
    assert!(!response_body.trailers().unwrap().contains_key("x-scan"));
    assert_eq!(response_body.to_bytes(), "response-body");
    assert_eq!(connections.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn preserves_ordinary_header_order_and_casing_end_to_end() {
    let connector = mock_icap_client(
        || {
            Server::new(
                HttpService::new(service_fn(serve_header_preserving_adaptation)),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        4096,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert_header_lines(request.headers(), REQUEST_HEADER_LINES);
        assert_eq!(request.uri().as_str(), "http://origin.test/upload");
        Ok::<_, Infallible>(
            Response::builder()
                .header("X-Response-FOO", "hello")
                .header("content-type", "text/plain")
                .header("x-Response-Foo", "goodbye")
                .body(Body::empty())
                .unwrap(),
        )
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .with_response_service(endpoint("respmod"))
        .layer(inner);

    let response = service
        .serve(
            Request::builder()
                .method("POST")
                .uri("http://origin.test/upload")
                .extension(rama_http_types::proto::h1::ext::RequestTargetForm::Absolute)
                .header("X-FOO-bar", "hello")
                .header("content-type", "text/plain")
                .header("x-Foo-BAR", "goodbye")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_header_lines(response.headers(), RESPONSE_HEADER_LINES);
}

#[tokio::test]
async fn icaps_endpoint_uses_direct_tls_for_options_reqmod_and_respmod() {
    let server_auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::generated_ca_for(
        Domain::from_static("icap.test"),
    ))
    .unwrap();
    let trust_anchor = server_auth.cert_chain.last().unwrap().clone();
    let tls_config = TlsServerConfig::new().with_single_cert(server_auth);
    let icap_server = Server::new(
        TlsIcapHandler {
            adaptation: HttpService::new(service_fn(serve_adaptation)),
            secure: true,
            port: Some(Protocol::ICAPS_DEFAULT_PORT),
        },
        TEST_SERVICE_TAG,
    )
    .unwrap();
    let icap_server = TlsIcapConnectionServer { inner: icap_server };
    let server = TlsAcceptorLayer::new(tls_config).into_layer(icap_server);
    let transport = MockConnectorService::new(move || server.clone()).with_max_buffer_size(4096);
    let transport = service_fn(move |input: ConnectRequest| {
        let transport = transport.clone();
        async move {
            assert_eq!(input.authority.to_string(), "icap.test:11344");
            assert_eq!(
                input.connector_target().unwrap().to_string(),
                "127.0.0.1:31344",
            );
            transport.serve(input).await
        }
    });
    let tls = TlsConnector::auto(transport).with_base_config(
        TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([trust_anchor])
            .unwrap(),
    );
    let client = crate::client::Client::new(tls);
    let mut endpoint = ServiceEndpoint::new("icaps://icap.test/scan").unwrap();
    endpoint.insert_connection_extension(ConnectorTarget("127.0.0.1:31344".parse().unwrap()));

    let options_request = endpoint.options_request().unwrap();
    assert_eq!(options_request.service_uri(), endpoint.uri());
    assert_eq!(
        options_request.connect_request().protocol(),
        Some(&Protocol::ICAPS)
    );
    assert_eq!(
        options_request.connect_request().authority.to_string(),
        "icap.test:11344"
    );
    OptionsService::new(client.clone())
        .serve(options_request)
        .await
        .unwrap();

    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.headers()["x-reqmod"], "yes");
        Ok::<_, Infallible>(
            Response::builder()
                .status(201)
                .body(Body::from("secure-response"))
                .unwrap(),
        )
    });
    let service = AdaptationLayer::new(client)
        .with_request_service(endpoint.clone())
        .with_response_service(endpoint)
        .layer(inner);
    let response = service
        .serve(
            Request::builder()
                .method("POST")
                .uri("http://origin.test/upload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 201);
    assert_eq!(response.headers()["x-respmod"], "yes");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "secure-response"
    );
}

#[tokio::test]
async fn boring_icaps_interoperates_for_options_reqmod_and_respmod() {
    let server_auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::generated_ca_for(
        Domain::from_static("icap.test"),
    ))
    .unwrap();
    let trust_anchor = server_auth.cert_chain.last().unwrap().clone();
    let tls_config = TlsServerConfig::new().with_single_cert(server_auth);
    let icap_server = Server::new(
        TlsIcapHandler {
            adaptation: HttpService::new(service_fn(serve_adaptation)),
            secure: true,
            port: Some(Protocol::ICAPS_DEFAULT_PORT),
        },
        TEST_SERVICE_TAG,
    )
    .unwrap();
    let server = TlsAcceptorLayer::new(tls_config)
        .into_layer(TlsIcapConnectionServer { inner: icap_server });
    let transport = MockConnectorService::new(move || server.clone()).with_max_buffer_size(4096);
    let tls = BoringTlsConnector::auto(transport).with_base_config(
        TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([trust_anchor])
            .unwrap(),
    );
    let client = crate::client::Client::new(tls);
    let endpoint = ServiceEndpoint::new("icaps://icap.test/scan").unwrap();

    OptionsService::new(client.clone())
        .serve(endpoint.options_request().unwrap())
        .await
        .unwrap();

    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.headers()["x-reqmod"], "yes");
        Ok::<_, Infallible>(Response::new(Body::from("boring-response")))
    });
    let response = AdaptationLayer::new(client)
        .with_request_service(endpoint.clone())
        .with_response_service(endpoint)
        .layer(inner)
        .serve(Request::new(Body::from("boring-request")))
        .await
        .unwrap();

    assert_eq!(response.headers()["x-respmod"], "yes");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "boring-response",
    );
}

#[tokio::test]
async fn boring_icaps_rejects_wrong_certificate_identity() {
    let server_auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::generated_ca_for(
        Domain::from_static("wrong.test"),
    ))
    .unwrap();
    let trust_anchor = server_auth.cert_chain.last().unwrap().clone();
    let tls_config = TlsServerConfig::new().with_single_cert(server_auth);
    let icap_server = Server::new(
        HttpService::new(service_fn(serve_adaptation)),
        TEST_SERVICE_TAG,
    )
    .unwrap();
    let server = TlsAcceptorLayer::new(tls_config)
        .into_layer(TlsIcapConnectionServer { inner: icap_server });
    let transport = MockConnectorService::new(move || server.clone()).with_max_buffer_size(4096);
    let tls = BoringTlsConnector::auto(transport).with_base_config(
        TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([trust_anchor])
            .unwrap(),
    );
    let endpoint = ServiceEndpoint::new("icaps://icap.test/scan").unwrap();

    OptionsService::new(crate::client::Client::new(tls))
        .serve(endpoint.options_request().unwrap())
        .await
        .unwrap_err();
}

#[tokio::test]
async fn auto_tls_connector_keeps_icap_endpoint_plaintext() {
    let transport = MockConnectorService::new(|| {
        Server::new(
            HttpService::new(service_fn(serve_adaptation)),
            TEST_SERVICE_TAG,
        )
        .unwrap()
    })
    .with_max_buffer_size(4096);
    let tls = TlsConnector::auto(transport)
        .with_base_config(TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable));
    let client = crate::client::Client::new(tls);
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.headers()["x-reqmod"], "yes");
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(client)
        .with_request_service(ServiceEndpoint::new("icap://icap.test/plain").unwrap())
        .layer(inner);

    service.serve(Request::new(Body::empty())).await.unwrap();
}

#[tokio::test]
async fn http_connect_tunnel_carries_and_reuses_plain_icap() {
    let tunnels = Arc::new(AtomicUsize::new(0));
    let icap_server = TlsIcapConnectionServer {
        inner: Server::new(
            TlsIcapHandler {
                adaptation: HttpService::new(service_fn(serve_adaptation)),
                secure: false,
                port: None,
            },
            TEST_SERVICE_TAG,
        )
        .unwrap(),
    };
    let proxy_server = HttpServer::auto(Executor::default()).service(service_fn({
        let tunnels = Arc::clone(&tunnels);
        move |request: Request| {
            let tunnels = Arc::clone(&tunnels);
            let icap_server = icap_server.clone();
            async move {
                assert_eq!(request.method(), rama_http_types::Method::CONNECT);
                assert_eq!(
                    request.uri().authority().unwrap().to_string(),
                    "icap.test:1344"
                );
                let on_upgrade = upgrade::handle_upgrade(&request);
                tunnels.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let tunnel = on_upgrade.await.unwrap();
                    Box::pin(icap_server.serve(tunnel)).await.unwrap();
                });
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        }
    }));
    let transport =
        MockConnectorService::new(move || proxy_server.clone()).with_max_buffer_size(4096);
    let transport = HttpProxyConnectorLayer::required().into_layer(transport);
    let pool = LruDropPool::try_new(1, 2)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let client = Arc::new(crate::client::Client::new(PooledConnector::new(
        transport,
        pool,
        BasicConnIdentifier::new(),
    )));
    let mut endpoint = ServiceEndpoint::new("icap://icap.test/scan").unwrap();
    endpoint.insert_connection_extension(ProxyRoute::Proxy(
        "http://proxy.test:8080".parse::<ProxyAddress>().unwrap(),
    ));

    Box::pin(OptionsService::new(client.clone()).serve(endpoint.options_request().unwrap()))
        .await
        .unwrap();
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.headers()["x-reqmod"], "yes");
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "plain-connect-request",
        );
        Ok::<_, Infallible>(Response::new(Body::from("plain-connect-response")))
    });
    let service = AdaptationLayer::new(client)
        .with_request_service(endpoint.clone())
        .with_response_service(endpoint)
        .layer(inner);
    let response = Box::pin(service.serve(Request::new(Body::from("plain-connect-request"))))
        .await
        .unwrap();

    assert_eq!(response.headers()["x-respmod"], "yes");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "plain-connect-response",
    );
    assert_eq!(
        tunnels.load(Ordering::Relaxed),
        1,
        "OPTIONS, REQMOD and RESPMOD must reuse one CONNECT tunnel",
    );
}

#[tokio::test]
async fn http_connect_tunnel_carries_and_reuses_icaps() {
    let server_auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::generated_ca_for(
        Domain::from_static("icap.test"),
    ))
    .unwrap();
    let trust_anchor = server_auth.cert_chain.last().unwrap().clone();
    let tls_config = TlsServerConfig::new().with_single_cert(server_auth);
    let icap_server = TlsIcapConnectionServer {
        inner: Server::new(
            TlsIcapHandler {
                adaptation: HttpService::new(service_fn(serve_adaptation)),
                secure: true,
                port: Some(Protocol::ICAPS_DEFAULT_PORT),
            },
            TEST_SERVICE_TAG,
        )
        .unwrap(),
    };
    let icap_server = BoxService::<upgrade::Upgraded, (), BoxError>::new(
        TlsAcceptorLayer::new(tls_config).into_layer(icap_server),
    );
    let tunnels = Arc::new(AtomicUsize::new(0));
    let proxy_server = HttpServer::auto(Executor::default()).service(service_fn({
        let tunnels = Arc::clone(&tunnels);
        move |request: Request| {
            let tunnels = Arc::clone(&tunnels);
            let icap_server = icap_server.clone();
            async move {
                assert_eq!(request.method(), rama_http_types::Method::CONNECT);
                assert_eq!(
                    request.uri().authority().unwrap().to_string(),
                    "icap.test:11344",
                );
                let on_upgrade = upgrade::handle_upgrade(&request);
                tunnels.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let tunnel = on_upgrade.await.unwrap();
                    let result: Result<(), BoxError> = icap_server.serve(tunnel).await;
                    result.unwrap();
                });
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        }
    }));
    let transport =
        MockConnectorService::new(move || proxy_server.clone()).with_max_buffer_size(4096);
    let transport = HttpProxyConnectorLayer::required().into_layer(transport);
    let transport = TlsConnector::auto(transport).with_base_config(
        TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([trust_anchor])
            .unwrap(),
    );
    let pool = LruDropPool::try_new(1, 2)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let client = Arc::new(crate::client::Client::new(PooledConnector::new(
        transport,
        pool,
        BasicConnIdentifier::new(),
    )));
    let mut endpoint = ServiceEndpoint::new("icaps://icap.test/scan").unwrap();
    endpoint.insert_connection_extension(ProxyRoute::Proxy(
        "http://proxy.test:8080".parse::<ProxyAddress>().unwrap(),
    ));

    Box::pin(OptionsService::new(client.clone()).serve(endpoint.options_request().unwrap()))
        .await
        .unwrap();
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.headers()["x-reqmod"], "yes");
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "secure-connect-request",
        );
        Ok::<_, Infallible>(Response::new(Body::from("secure-connect-response")))
    });
    let service = AdaptationLayer::new(client)
        .with_request_service(endpoint.clone())
        .with_response_service(endpoint)
        .layer(inner);
    let response = Box::pin(service.serve(Request::new(Body::from("secure-connect-request"))))
        .await
        .unwrap();

    assert_eq!(response.headers()["x-respmod"], "yes");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "secure-connect-response",
    );
    assert_eq!(
        tunnels.load(Ordering::Relaxed),
        1,
        "OPTIONS, REQMOD and RESPMOD must reuse one TLS CONNECT tunnel",
    );
}

#[tokio::test]
async fn options_discovery_constrains_ephemeral_adaptation_policy() {
    let connector = mock_icap_client(
        || {
            let adaptation = service_fn(async |request: IncomingRequest| {
                assert_eq!(request.icap().preview(), Some(Preview::new(2)));
                assert!(!request.icap().allows_204());
                assert!(!request.icap().allows_206());
                serve_adaptation(request).await
            });
            Server::new(HttpService::new(adaptation), TEST_SERVICE_TAG).unwrap()
        },
        256,
    );
    let discoveries = Arc::new(AtomicUsize::new(0));
    let provider_discoveries = Arc::clone(&discoveries);
    let options = service_fn(move |_request| {
        provider_discoveries.fetch_add(1, Ordering::Relaxed);
        async { Ok::<_, Infallible>(discovered_capabilities()) }
    });
    let inner = service_fn(async |request: Request<Body>| {
        assert!(request.extensions().contains::<ServiceCapabilities>());
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .with_options_service(options)
        .layer(inner);

    let response = service
        .serve(
            Request::builder()
                .method("POST")
                .uri("http://origin.test/upload")
                .body(Body::from_stream(stream::iter([Ok::<_, Infallible>(
                    Bytes::from_static(b"body"),
                )])))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.extensions().contains::<ServiceCapabilities>());
    assert_eq!(discoveries.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn matching_adaptation_istags_preserve_cached_options() {
    assert_istag_cache_discoveries(OPTIONS_SERVICE_TAG, 1).await;
}

#[tokio::test]
async fn changed_reqmod_and_respmod_istags_invalidate_cached_options() {
    assert_istag_cache_discoveries(CHANGED_SERVICE_TAG, 4).await;
}

async fn assert_istag_cache_discoveries(adaptation_tag: ServiceTag, expected_discoveries: usize) {
    let connector = mock_icap_client(
        move || {
            let adaptation = service_fn(move |request: IncomingRequest| {
                serve_adaptation_with_service_tag(request, adaptation_tag)
            });
            Server::new(HttpService::new(adaptation), adaptation_tag).unwrap()
        },
        256,
    );
    let discoveries = Arc::new(AtomicUsize::new(0));
    let provider_discoveries = Arc::clone(&discoveries);
    let options = OptionsCacheLayer::new().layer(service_fn(move |_request| {
        provider_discoveries.fetch_add(1, Ordering::Relaxed);
        async { Ok::<_, Infallible>(discovered_capabilities()) }
    }));
    let inner = service_fn(async |_request: Request<Body>| {
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service_endpoint = endpoint("adapt");
    let service = AdaptationLayer::new(connector)
        .with_request_service(service_endpoint.clone())
        .with_response_service(service_endpoint)
        .with_options_cache(options)
        .layer(inner);

    for _ in 0..2 {
        service
            .serve(
                Request::builder()
                    .method("POST")
                    .uri("http://origin.test/upload")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }

    assert_eq!(discoveries.load(Ordering::Relaxed), expected_discoveries);
}

#[tokio::test]
async fn transfer_ignore_bypasses_reqmod_and_respmod() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let connector = mock_icap_client(
        move || {
            connector_connections.fetch_add(1, Ordering::Relaxed);
            service_fn(|_io: MockSocket| async { Ok::<_, Infallible>(()) })
        },
        256,
    );
    let options = service_fn(|_request| async {
        Ok::<_, Infallible>(discovered_transfer_capabilities(b"*", Some(b"html"), None))
    });
    let inner = service_fn(async |request: Request<Body>| {
        assert!(request.extensions().contains::<ServiceCapabilities>());
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "request-body",
        );
        Ok::<_, Infallible>(Response::new(Body::from("response-body")))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .with_response_service(endpoint("respmod"))
        .with_options_service(options)
        .layer(inner);

    let response = service
        .serve(
            Request::builder()
                .method("POST")
                .uri("http://origin.test/resource.html")
                .body(Body::from("request-body"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.extensions().contains::<ServiceCapabilities>());
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "response-body",
    );
    assert_eq!(connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn transfer_complete_disables_preview_in_both_directions() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let connector = mock_icap_client(
        move || {
            connector_connections.fetch_add(1, Ordering::Relaxed);
            let adaptation = service_fn(async |request: IncomingRequest| {
                assert_eq!(request.icap().preview(), None);
                serve_adaptation(request).await
            });
            Server::new(HttpService::new(adaptation), TEST_SERVICE_TAG).unwrap()
        },
        256,
    );
    let options = service_fn(|_request| async {
        Ok::<_, Infallible>(discovered_transfer_capabilities(b"*", None, Some(b"zip")))
    });
    let inner = service_fn(async |_request: Request<Body>| {
        Ok::<_, Infallible>(Response::new(Body::from("response-body")))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .with_response_service(endpoint("respmod"))
        .with_options_service(options)
        .layer(inner);

    service
        .serve(
            Request::builder()
                .method("POST")
                .uri("http://origin.test/resource.zip")
                .body(Body::from("request-body"))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    assert_eq!(connections.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn preserves_trailer_only_response_declaration() {
    let connector = mock_icap_client(
        || {
            Server::new(
                HttpService::new(service_fn(serve_adaptation)),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        256,
    );
    let inner = service_fn(async |_request: Request<Body>| {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-response-end", HeaderValue::from_static("yes"));
        Ok::<_, Infallible>(
            Response::builder()
                .header(TRAILER, "x-response-end")
                .body(Body::from_frame_stream(stream::iter([
                    Ok::<_, Infallible>(Frame::trailers(trailers)),
                ])))
                .unwrap(),
        )
    });
    let service = AdaptationLayer::new(connector)
        .with_response_service(endpoint("respmod"))
        .layer(inner);
    let response = service
        .serve(
            Request::builder()
                .uri("http://origin.test/trailers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.headers()[TRAILER], "x-response-end");
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(body.trailers().unwrap()["x-response-end"], "yes");
    assert!(body.to_bytes().is_empty());
}

#[tokio::test]
async fn reuses_healthy_exclusive_transport_connections() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let transport = MockConnectorService::new(move || {
        connector_connections.fetch_add(1, Ordering::Relaxed);
        Server::new(
            HttpService::new(service_fn(serve_adaptation)),
            TEST_SERVICE_TAG,
        )
        .unwrap()
    })
    .with_max_buffer_size(256);
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let connector = Arc::new(crate::client::Client::new(PooledConnector::new(
        transport,
        pool,
        test_connection_id,
    )));
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "body",
        );
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .layer(inner);

    for _ in 0..2 {
        service
            .serve(
                Request::builder()
                    .method("POST")
                    .uri("/resource")
                    .body(Body::from("body"))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    assert_eq!(connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn pool_discards_transports_with_preloaded_responses() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let transport = service_fn(move |input: ConnectRequest| {
        let index = connector_connections.fetch_add(1, Ordering::Relaxed);
        async move {
            let (client_io, mut server_io) = tokio::io::duplex(1024);
            if index <= 1 {
                const HTTP_HEAD: &[u8] = b"GET /stray HTTP/1.1\r\n\r\n";
                let head = format!(
                    "ICAP/1.0 200 OK\r\n\
                     ISTag: \"stray\"\r\n\
                     Encapsulated: req-hdr=0, null-body={}\r\n\r\n",
                    HTTP_HEAD.len(),
                );
                if index == 0 {
                    server_io.write_all(head.as_bytes()).await.unwrap();
                    server_io.write_all(HTTP_HEAD).await.unwrap();
                } else {
                    let mut response = head.into_bytes();
                    response.extend_from_slice(HTTP_HEAD);
                    let remainder = response.split_off(17);
                    assert_eq!(response, b"ICAP/1.0 200 OK\r\n");
                    server_io.write_all(&response).await.unwrap();
                    tokio::spawn(async move {
                        let mut request_byte = [0];
                        if server_io.read(&mut request_byte).await.unwrap() > 0 {
                            server_io.write_all(&remainder).await.unwrap();
                        }
                    });
                }
            } else {
                tokio::spawn(async move {
                    let server = Server::new(
                        HttpService::new(service_fn(serve_adaptation)),
                        TEST_SERVICE_TAG,
                    )
                    .unwrap();
                    let _result = server.serve(ServiceInput::new(server_io)).await;
                });
            }
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(client_io),
            })
        }
    });
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let connector = Arc::new(crate::client::Client::new(PooledConnector::new(
        transport,
        pool,
        test_connection_id,
    )));
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let inner_origin_calls = Arc::clone(&origin_calls);
    let inner = service_fn(move |_request: Request<Body>| {
        inner_origin_calls.fetch_add(1, Ordering::Relaxed);
        async { Ok::<_, Infallible>(Response::new(Body::empty())) }
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .layer(inner);
    let request = || {
        Request::builder()
            .uri("http://origin.example/resource")
            .body(Body::empty())
            .unwrap()
    };

    timeout(Duration::from_secs(1), service.serve(request()))
        .await
        .expect("fully preloaded response handling deadlocked")
        .unwrap_err();
    timeout(Duration::from_secs(1), service.serve(request()))
        .await
        .expect("partially preloaded response handling deadlocked")
        .unwrap_err();
    timeout(Duration::from_secs(1), service.serve(request()))
        .await
        .expect("replacement connection handling deadlocked")
        .unwrap();
    assert_eq!(connections.load(Ordering::Relaxed), 3);
    assert_eq!(origin_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn evicts_transport_when_adapted_body_is_dropped() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let transport = MockConnectorService::new(move || {
        connector_connections.fetch_add(1, Ordering::Relaxed);
        service_fn(|server_io: MockSocket| async move {
            let server = Server::new(
                HttpService::new(service_fn(serve_adaptation)),
                TEST_SERVICE_TAG,
            )
            .unwrap();
            let _result = server.serve(server_io).await;
            Ok::<_, Infallible>(())
        })
    })
    .with_max_buffer_size(256);
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let connector = Arc::new(crate::client::Client::new(PooledConnector::new(
        transport,
        pool,
        test_connection_id,
    )));
    let requests = Arc::new(AtomicUsize::new(0));
    let inner_requests = Arc::clone(&requests);
    let inner = service_fn(move |request: Request<Body>| {
        let inner_requests = Arc::clone(&inner_requests);
        async move {
            if inner_requests.fetch_add(1, Ordering::Relaxed) == 0 {
                drop(request);
            } else {
                assert_eq!(
                    request.into_body().collect().await.unwrap().to_bytes(),
                    "body",
                );
            }
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .layer(inner);

    for _ in 0..2 {
        service
            .serve(
                Request::builder()
                    .method("POST")
                    .uri("/resource")
                    .body(Body::from("body"))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    assert_eq!(connections.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn releases_preview_204_lease_before_original_replay() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let transport = MockConnectorService::new(move || {
        connector_connections.fetch_add(1, Ordering::Relaxed);
        Server::new(
            service_fn(async |request: RawIncomingRequest| {
                let response = IcapResponse::new(
                    request.request().method(),
                    ResponseLine::new(
                        StatusCode::NO_MODIFICATION_NEEDED,
                        b"No Modification Needed",
                    )
                    .unwrap(),
                    &adaptation_response_fields(),
                    None,
                )
                .unwrap();
                Ok::<_, Infallible>(OutgoingResponse::without_body(response))
            }),
            TEST_SERVICE_TAG,
        )
        .unwrap()
    })
    .with_max_buffer_size(256);
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let connector = Arc::new(crate::client::Client::new(PooledConnector::new(
        transport,
        pool,
        test_connection_id,
    )));
    let entered = Arc::new(AtomicUsize::new(0));
    let first_entered = Arc::new(Notify::new());
    let release_first = Arc::new(Notify::new());
    let inner = service_fn({
        let entered = Arc::clone(&entered);
        let first_entered = Arc::clone(&first_entered);
        let release_first = Arc::clone(&release_first);
        move |request: Request<Body>| {
            let entered = Arc::clone(&entered);
            let first_entered = Arc::clone(&first_entered);
            let release_first = Arc::clone(&release_first);
            async move {
                if entered.fetch_add(1, Ordering::Relaxed) == 0 {
                    first_entered.notify_one();
                    release_first.notified().await;
                }
                drop(request);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        }
    });
    let service = Arc::new(
        AdaptationLayer::new(connector)
            .with_request_service(endpoint("reqmod"))
            .layer(inner),
    );
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/resource")
            .body(Body::from("original body"))
            .unwrap()
    };
    let first = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.serve(request()).await.unwrap() }
    });
    first_entered.notified().await;
    timeout(Duration::from_secs(1), service.serve(request()))
        .await
        .expect("completed ICAP lease remained tied to original replay")
        .unwrap();
    release_first.notify_one();
    first.await.unwrap();

    assert_eq!(connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn omits_configured_preview_for_empty_body() {
    let connector = mock_icap_client(
        || {
            Server::new(
                service_fn(async |request: RawIncomingRequest| {
                    assert_eq!(request.request().preview(), None);
                    assert_eq!(
                        request.request().encapsulated().unwrap().body_kind(),
                        crate::proto::EncapsulatedKind::NullBody,
                    );
                    let response = IcapResponse::new(
                        request.request().method(),
                        ResponseLine::new(
                            StatusCode::NO_MODIFICATION_NEEDED,
                            b"No Modification Needed",
                        )
                        .unwrap(),
                        &adaptation_response_fields(),
                        None,
                    )
                    .unwrap();
                    Ok::<_, Infallible>(OutgoingResponse::without_body(response))
                }),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        256,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert!(
            request
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod").with_allow_204(true))
        .layer(inner);

    service.serve(Request::new(Body::empty())).await.unwrap();
}

#[tokio::test]
async fn reconstructs_reqmod_partial_content() {
    let connector = mock_icap_client(
        || {
            service_fn(|server_io: MockSocket| async move {
                let mut connection = crate::server::ServerConnection::new(server_io);
                let mut transaction = connection.accept().await.unwrap().unwrap();
                assert_eq!(transaction.next_data().await.unwrap().unwrap(), "abcd");
                assert!(transaction.next_data().await.unwrap().is_none());
                let parts = EncapsulatedParts::new(
                    Some(Bytes::from_static(b"POST /adapted HTTP/1.1\r\n\r\n")),
                    None,
                    EncapsulatedKind::RequestBody,
                )
                .unwrap();
                let response = IcapResponse::new(
                    MethodKind::Reqmod,
                    ResponseLine::new(StatusCode::PARTIAL_CONTENT, b"Partial Content").unwrap(),
                    &adaptation_response_fields(),
                    Some(parts),
                )
                .unwrap();
                let mut response = transaction.respond(response).await.unwrap();
                response.write_data(b"XY").await.unwrap();
                response.finish_partial(3).await.unwrap();
                Ok::<_, Infallible>(())
            })
        },
        256,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.uri().as_str(), "/adapted");
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "XYdef",
        );
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .layer(inner);

    service
        .serve(
            Request::builder()
                .method("POST")
                .uri("/original")
                .body(Body::from("abcdef"))
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn reconstructs_preview_204_after_splitting_one_source_frame() {
    let connector = mock_icap_client(
        || {
            service_fn(|server_io: MockSocket| async move {
                let mut connection = crate::server::ServerConnection::new(server_io);
                let mut transaction = connection.accept().await.unwrap().unwrap();
                assert_eq!(transaction.next_data().await.unwrap().unwrap(), "abcd");
                assert!(transaction.next_data().await.unwrap().is_none());
                let response = IcapResponse::new(
                    MethodKind::Reqmod,
                    ResponseLine::new(
                        StatusCode::NO_MODIFICATION_NEEDED,
                        b"No Modification Needed",
                    )
                    .unwrap(),
                    &adaptation_response_fields(),
                    None,
                )
                .unwrap();
                transaction
                    .respond(response)
                    .await
                    .unwrap()
                    .finish()
                    .await
                    .unwrap();
                Ok::<_, Infallible>(())
            })
        },
        256,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "abcdef",
        );
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .layer(inner);

    service
        .serve(
            Request::builder()
                .method("POST")
                .uri("/original")
                .body(Body::from("abcdef"))
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn oversized_known_body_degrades_to_adaptation_without_204() {
    let connector = mock_icap_client(
        || {
            Server::new(
                HttpService::new(service_fn(async |request: IncomingRequest| {
                    assert!(!request.icap().allows_204());
                    assert!(!request.icap().allows_206());
                    serve_adaptation(request).await
                })),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        512,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "five!"
        );
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(
            endpoint("reqmod")
                .with_allow_204(true)
                .with_replay_limits(crate::http::ReplayLimits::new().with_max_bytes(4)),
        )
        .layer(inner);

    service
        .serve(
            Request::builder()
                .method("POST")
                .uri("/large")
                .body(Body::from("five!"))
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn preview_split_preserves_one_source_frame_replay_budget() {
    let connector = mock_icap_client(
        || {
            Server::new(
                HttpService::new(service_fn(async |request: IncomingRequest| {
                    assert_eq!(request.icap().preview(), Some(Preview::new(1)));
                    assert!(request.icap().allows_204());
                    assert!(request.icap().allows_206());
                    serve_adaptation(request).await
                })),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        512,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "abcdef"
        );
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(
            endpoint("reqmod").with_allow_204(true).with_replay_limits(
                crate::http::ReplayLimits::new()
                    .with_max_bytes(100)
                    .with_max_frames(1),
            ),
        )
        .layer(inner);

    service
        .serve(
            Request::builder()
                .method("POST")
                .uri("/single-frame")
                .body(Body::from("abcdef"))
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn unknown_body_does_not_offer_replay_after_preview_continue() {
    let connector = mock_icap_client(
        || {
            Server::new(
                HttpService::new(service_fn(async |request: IncomingRequest| {
                    assert!(!request.icap().allows_204());
                    assert!(!request.icap().allows_206());
                    serve_adaptation(request).await
                })),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        512,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "streamed"
        );
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod").with_allow_204(true))
        .layer(inner);

    service
        .serve(
            Request::builder()
                .method("POST")
                .uri("/unknown")
                .body(Body::from_stream(stream::iter([Ok::<_, Infallible>(
                    Bytes::from_static(b"streamed"),
                )])))
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn reqmod_response_bypasses_origin_and_respmod() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let transport = MockConnectorService::new(move || {
        connector_connections.fetch_add(1, Ordering::Relaxed);
        service_fn(|server_io: MockSocket| async move {
            let server = Server::new(
                HttpService::new(service_fn(serve_blocking_adaptation)),
                TEST_SERVICE_TAG,
            )
            .unwrap();
            let _result = server.serve(server_io).await;
            Ok::<_, Infallible>(())
        })
    })
    .with_max_buffer_size(256);
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let connector = Arc::new(crate::client::Client::new(PooledConnector::new(
        transport,
        pool,
        test_connection_id,
    )));
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let inner_origin_calls = Arc::clone(&origin_calls);
    let inner = service_fn(move |_request: Request<Body>| {
        inner_origin_calls.fetch_add(1, Ordering::Relaxed);
        async { Ok::<_, Infallible>(Response::new(Body::empty())) }
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .with_response_service(endpoint("respmod"))
        .layer(inner);
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/blocked")
            .body(Body::from("request body"))
            .unwrap()
    };

    let response = timeout(Duration::from_secs(1), service.serve(request()))
        .await
        .expect("direct REQMOD response waited for a second pool lease")
        .unwrap();

    assert_eq!(origin_calls.load(Ordering::Relaxed), 0);
    assert_eq!(connections.load(Ordering::Relaxed), 1);
    assert_eq!(response.status(), 403);
    assert_eq!(response.headers()["x-blocked"], "yes");
    assert_eq!(
        response.headers()[http_header::PROXY_AUTHENTICATE],
        "Basic realm=blocked",
    );
    assert!(response.extensions().contains::<ReqmodResult>());
    assert!(!response.extensions().contains::<RespmodResult>());
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(body.trailers().unwrap()["x-block-end"], "yes");
    assert_eq!(body.to_bytes(), "blocked");

    let response = timeout(Duration::from_secs(1), service.serve(request()))
        .await
        .expect("completed direct response did not release its pool lease")
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "blocked"
    );
    assert_eq!(connections.load(Ordering::Relaxed), 1);
    assert_eq!(origin_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn preserves_reqmod_proxy_authorization_and_canonical_host() {
    let connector = mock_icap_client(
        || {
            Server::new(
                HttpService::new(service_fn(async |request: IncomingRequest| {
                    let mut slots = [HeaderSlot::EMPTY; 8];
                    let head = request.icap().parse_head(&mut slots).unwrap();
                    assert_eq!(
                        head.header(header::PROXY_AUTHORIZATION).unwrap().as_bytes(),
                        Some(b"Basic downstream-secret".as_slice()),
                    );
                    let request = request.encapsulated().unwrap().request().unwrap();
                    assert_eq!(request.headers()[http_header::HOST], "origin.example:8080");
                    assert!(
                        !request
                            .headers()
                            .contains_key(http_header::PROXY_AUTHORIZATION)
                    );
                    assert!(!request.headers().contains_key(http_header::CONNECTION));

                    let response = IcapResponse::new(
                        MethodKind::Reqmod,
                        ResponseLine::new(
                            StatusCode::NO_MODIFICATION_NEEDED,
                            b"No Modification Needed",
                        )
                        .unwrap(),
                        &adaptation_response_fields(),
                        None,
                    )
                    .unwrap();
                    Ok::<_, Infallible>(OutgoingResponse::without_body(response))
                })),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        512,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.headers()[http_header::HOST], "origin.example:8080");
        assert_eq!(
            request.headers()[http_header::PROXY_AUTHORIZATION],
            "Basic downstream-secret",
        );
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod").with_allow_204(true))
        .layer(inner);

    service
        .serve(
            Request::builder()
                .uri("http://origin.example:8080/resource")
                .header(http_header::HOST, "wrong.example")
                .header(http_header::CONNECTION, "host")
                .header(http_header::PROXY_AUTHORIZATION, "Basic downstream-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn preserves_upgrade_request_fields_around_reqmod_sanitization() {
    let connector = mock_icap_client(
        || {
            Server::new(
                HttpService::new(service_fn(async |request: IncomingRequest| {
                    let request = request.encapsulated().unwrap().request().unwrap();
                    assert!(!request.headers().contains_key(http_header::CONNECTION));
                    assert!(!request.headers().contains_key(http_header::UPGRADE));
                    assert!(!request.headers().contains_key("x-hop"));
                    let response = IcapResponse::new(
                        MethodKind::Reqmod,
                        ResponseLine::new(
                            StatusCode::NO_MODIFICATION_NEEDED,
                            b"No Modification Needed",
                        )
                        .unwrap(),
                        &adaptation_response_fields(),
                        None,
                    )
                    .unwrap();
                    Ok::<_, Infallible>(OutgoingResponse::without_body(response))
                })),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        512,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.headers()[http_header::CONNECTION], "upgrade");
        assert_eq!(request.headers()[http_header::UPGRADE], "websocket");
        assert!(!request.headers().contains_key("x-hop"));
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod").with_allow_204(true))
        .layer(inner);

    service
        .serve(
            Request::builder()
                .uri("http://origin.example/socket")
                .header(http_header::CONNECTION, "Upgrade, x-hop")
                .header(http_header::UPGRADE, "websocket")
                .header("x-hop", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn canonicalizes_authority_of_adapted_absolute_request() {
    let connector = mock_icap_client(
        || {
            Server::new(
                service_fn(async |request: RawIncomingRequest| {
                    let request_head = Bytes::from_static(
                        b"GET http://[2001:db8::9]:8081/changed HTTP/1.1\r\n\
                      Host: stale.invalid\r\n\
                      Connection: host\r\n\r\n",
                    );
                    let parts = EncapsulatedParts::new(
                        Some(request_head),
                        None,
                        EncapsulatedKind::NullBody,
                    )
                    .unwrap();
                    let response = IcapResponse::new(
                        request.request().method(),
                        ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
                        &adaptation_response_fields(),
                        Some(parts),
                    )
                    .unwrap();
                    Ok::<_, Infallible>(OutgoingResponse::without_body(response))
                }),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        512,
    );
    let inner = service_fn(async |request: Request<Body>| {
        assert_eq!(request.uri().as_str(), "http://[2001:db8::9]:8081/changed",);
        assert_eq!(request.headers()[http_header::HOST], "[2001:db8::9]:8081");
        assert!(!request.headers().contains_key(http_header::CONNECTION));
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .layer(inner);

    service
        .serve(
            Request::builder()
                .uri("http://original.example/resource")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn preserves_respmod_proxy_authenticate_after_204() {
    let connector = mock_icap_client(
        || {
            Server::new(
                HttpService::new(service_fn(async |request: IncomingRequest| {
                    let mut slots = [HeaderSlot::EMPTY; 8];
                    let head = request.icap().parse_head(&mut slots).unwrap();
                    assert_eq!(
                        head.header(header::PROXY_AUTHENTICATE).unwrap().as_bytes(),
                        Some(b"Basic realm=upstream".as_slice()),
                    );
                    assert!(
                        !request
                            .encapsulated()
                            .unwrap()
                            .response()
                            .unwrap()
                            .headers()
                            .contains_key(http_header::PROXY_AUTHENTICATE)
                    );
                    let response = IcapResponse::new(
                        MethodKind::Respmod,
                        ResponseLine::new(
                            StatusCode::NO_MODIFICATION_NEEDED,
                            b"No Modification Needed",
                        )
                        .unwrap(),
                        &adaptation_response_fields(),
                        None,
                    )
                    .unwrap();
                    Ok::<_, Infallible>(OutgoingResponse::without_body(response))
                })),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        512,
    );
    let inner = service_fn(async |_request: Request<Body>| {
        Ok::<_, Infallible>(
            Response::builder()
                .status(407)
                .header(http_header::PROXY_AUTHENTICATE, "Basic realm=upstream")
                .body(Body::empty())
                .unwrap(),
        )
    });
    let service = AdaptationLayer::new(connector)
        .with_response_service(endpoint("respmod").with_allow_204(true))
        .layer(inner);

    let response = service.serve(Request::new(Body::empty())).await.unwrap();
    assert_eq!(response.status(), 407);
    assert_eq!(
        response.headers()[http_header::PROXY_AUTHENTICATE],
        "Basic realm=upstream",
    );
}

#[tokio::test]
async fn preserves_upgrade_response_fields_around_respmod_sanitization() {
    let connector = mock_icap_client(
        || {
            Server::new(
                HttpService::new(service_fn(async |request: IncomingRequest| {
                    let response = request.encapsulated().unwrap().response().unwrap();
                    assert!(!response.headers().contains_key(http_header::CONNECTION));
                    assert!(!response.headers().contains_key(http_header::UPGRADE));
                    assert!(!response.headers().contains_key("x-hop"));
                    let response = IcapResponse::new(
                        MethodKind::Respmod,
                        ResponseLine::new(
                            StatusCode::NO_MODIFICATION_NEEDED,
                            b"No Modification Needed",
                        )
                        .unwrap(),
                        &adaptation_response_fields(),
                        None,
                    )
                    .unwrap();
                    Ok::<_, Infallible>(OutgoingResponse::without_body(response))
                })),
                TEST_SERVICE_TAG,
            )
            .unwrap()
        },
        512,
    );
    let inner = service_fn(async |_request: Request<Body>| {
        Ok::<_, Infallible>(
            Response::builder()
                .status(101)
                .header(http_header::CONNECTION, "Upgrade, x-hop")
                .header(http_header::UPGRADE, "websocket")
                .header("x-hop", "secret")
                .body(Body::empty())
                .unwrap(),
        )
    });
    let service = AdaptationLayer::new(connector)
        .with_response_service(endpoint("respmod").with_allow_204(true))
        .layer(inner);

    let response = service.serve(Request::new(Body::empty())).await.unwrap();
    assert_eq!(response.status(), 101);
    assert_eq!(response.headers()[http_header::CONNECTION], "upgrade");
    assert_eq!(response.headers()[http_header::UPGRADE], "websocket");
    assert!(!response.headers().contains_key("x-hop"));
}

#[tokio::test]
async fn preserves_parser_policy_for_returned_proxy_headers() {
    let connector = crate::client::Client::new(
        MockConnectorService::new(|| {
            service_fn(|mut server_io: MockSocket| async move {
                let mut request = Vec::new();
                while request
                    .windows(4)
                    .filter(|window| *window == b"\r\n\r\n")
                    .count()
                    < 2
                {
                    let mut buffer = [0; 256];
                    let read = server_io.read(&mut buffer).await.unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&buffer[..read]);
                    assert!(request.len() < 1024);
                }

                const HTTP_HEAD: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
                let response = format!(
                    concat!(
                        "ICAP/1.0 200 OK\r\n",
                        "ISTag: \"folded-test\"\r\n",
                        "Proxy-Authenticate: Basic\r\n",
                        " realm=folded\r\n",
                        "Encapsulated: res-hdr=0, null-body={}\r\n\r\n",
                    ),
                    HTTP_HEAD.len(),
                );
                server_io.write_all(response.as_bytes()).await.unwrap();
                server_io.write_all(HTTP_HEAD).await.unwrap();
                Ok::<_, Infallible>(())
            })
        })
        .with_max_buffer_size(512),
    )
    .with_options(
        ConnectionOptions::new()
            .with_head_parser(HeadParserConfig::new().with_header_folding(HeaderFolding::Allow)),
    );
    let origin_calls = Arc::new(AtomicUsize::new(0));
    let inner_origin_calls = Arc::clone(&origin_calls);
    let inner = service_fn(move |_request: Request<Body>| {
        inner_origin_calls.fetch_add(1, Ordering::Relaxed);
        async { Ok::<_, Infallible>(Response::new(Body::empty())) }
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint("reqmod"))
        .layer(inner);

    let response = service.serve(Request::new(Body::empty())).await.unwrap();
    assert_eq!(response.status(), 407);
    assert_eq!(origin_calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        response.headers()[http_header::PROXY_AUTHENTICATE],
        "Basic realm=folded",
    );
}

#[test]
fn endpoint_derives_headers_and_target() {
    let mut endpoint = ServiceEndpoint::new("icap://[::1]:31344/scan")
        .unwrap()
        .with_allow_204(true)
        .with_allow_206(true);
    let shared_partition = endpoint.options_cache_partition().clone();
    assert!(
        endpoint
            .clone()
            .options_cache_partition()
            .shares_cache_with(&shared_partition)
    );
    endpoint
        .headers_mut()
        .insert("authorization", "secret".parse().unwrap());
    assert!(
        !endpoint
            .options_cache_partition()
            .shares_cache_with(&shared_partition)
    );
    let previous_endpoint = endpoint.clone();
    let previous_partition = endpoint.options_cache_partition().clone();
    endpoint.insert_connection_extension(EndpointExtension("new"));
    assert_eq!(
        endpoint
            .connection_extension::<EndpointExtension>()
            .unwrap()
            .0,
        "new"
    );
    assert!(
        previous_endpoint
            .connection_extension::<EndpointExtension>()
            .is_none()
    );
    assert!(
        !endpoint
            .options_cache_partition()
            .shares_cache_with(&previous_partition)
    );
    assert_eq!(endpoint.uri().as_str(), "icap://[::1]:31344/scan");
    assert_eq!(endpoint.service_protocol(), &Protocol::ICAP);
    assert_eq!(endpoint.service_authority().to_string(), "[::1]:31344");
    assert_eq!(
        UriInputExt::uri(&endpoint).as_str(),
        "icap://[::1]:31344/scan"
    );
    assert_eq!(
        AuthorityInputExt::authority(&endpoint).unwrap().to_string(),
        "[::1]:31344"
    );
    assert_eq!(ProtocolInputExt::protocol(&endpoint), Some(&Protocol::ICAP));
    let fields = endpoint.request_headers(&[]).unwrap();
    assert_eq!(fields[0], Header::new("authorization", b"secret").unwrap());
    assert_eq!(fields[1], Header::new(header::ALLOW, b"204, 206").unwrap());
    let endpoint_debug = format!("{endpoint:?}");
    assert!(endpoint_debug.starts_with("ServiceEndpoint"));
    assert!(endpoint_debug.contains("[::1]:31344"));
    assert!(endpoint_debug.contains("protocol"));
    assert!(!endpoint_debug.contains("secret"));
    let first_options = endpoint.options_request().unwrap();
    let second_options = endpoint.options_request().unwrap();
    assert_eq!(
        first_options.request().head_bytes().as_ptr(),
        second_options.request().head_bytes().as_ptr(),
    );
    assert_eq!(
        first_options.service_uri().as_str(),
        "icap://[::1]:31344/scan"
    );
    let first_connect = first_options.connect_request();
    assert_eq!(
        first_connect
            .extensions
            .get_ref::<EndpointExtension>()
            .unwrap()
            .0,
        "new"
    );
    first_connect
        .extensions
        .insert(EndpointExtension("attempt-only"));
    assert_eq!(
        first_connect
            .extensions
            .get_ref::<EndpointExtension>()
            .unwrap()
            .0,
        "attempt-only"
    );
    assert_eq!(
        second_options
            .connect_request()
            .extensions
            .get_ref::<EndpointExtension>()
            .unwrap()
            .0,
        "new"
    );
    assert_eq!(
        endpoint
            .options_request()
            .unwrap()
            .connect_request()
            .extensions
            .get_ref::<EndpointExtension>()
            .unwrap()
            .0,
        "new"
    );
    assert!(!format!("{first_options:?}").contains("secret"));

    let userinfo_endpoint = ServiceEndpoint::new("icap://user:secret@icap.test:/scan").unwrap();
    assert_eq!(
        userinfo_endpoint.service_authority().to_string(),
        "icap.test:1344"
    );
    let request = userinfo_endpoint.options_request().unwrap();
    let mut slots = [HeaderSlot::EMPTY; 4];
    let head = request.request().parse_head(&mut slots).unwrap();
    assert_eq!(
        head.line().uri().as_str(),
        "icap://user:secret@icap.test/scan",
    );
    assert_eq!(
        head.header(header::HOST).and_then(|value| value.as_bytes()),
        Some(b"icap.test".as_slice()),
    );
    assert!(!format!("{userinfo_endpoint:?}").contains("secret"));

    for (uri, protocol, target, wire_uri, host) in [
        (
            "icap://icap.test:01344/scan",
            &Protocol::ICAP,
            "icap.test:1344",
            "icap://icap.test:1344/scan",
            "icap.test:1344",
        ),
        (
            "icap://icap.test:031344/scan",
            &Protocol::ICAP,
            "icap.test:31344",
            "icap://icap.test:31344/scan",
            "icap.test:31344",
        ),
        (
            "icap://[0:0:0:0:0:0:0:1]:1344/scan",
            &Protocol::ICAP,
            "[::1]:1344",
            "icap://[::1]:1344/scan",
            "[::1]:1344",
        ),
        (
            "icap://icap.test:/scan",
            &Protocol::ICAP,
            "icap.test:1344",
            "icap://icap.test/scan",
            "icap.test",
        ),
        (
            "icaps://icap.test/scan",
            &Protocol::ICAPS,
            "icap.test:11344",
            "icap://icap.test:11344/scan",
            "icap.test:11344",
        ),
        (
            "icaps://icap.test:/scan",
            &Protocol::ICAPS,
            "icap.test:11344",
            "icap://icap.test:11344/scan",
            "icap.test:11344",
        ),
        (
            "icaps://icap.test:011344/scan",
            &Protocol::ICAPS,
            "icap.test:11344",
            "icap://icap.test:11344/scan",
            "icap.test:11344",
        ),
        (
            "icap://icap.test:11344/scan",
            &Protocol::ICAP,
            "icap.test:11344",
            "icap://icap.test:11344/scan",
            "icap.test:11344",
        ),
        (
            "icaps://icap.test:1344/scan",
            &Protocol::ICAPS,
            "icap.test:1344",
            "icap://icap.test:1344/scan",
            "icap.test:1344",
        ),
    ] {
        let endpoint = ServiceEndpoint::new(uri).unwrap();
        assert_eq!(endpoint.service_protocol(), protocol);
        assert_eq!(endpoint.service_authority().to_string(), target);
        let fields = endpoint.request_headers(&[]).unwrap();
        let request = crate::message::Request::new_from_source(
            crate::codec::RequestLineSource::prepared(Method::Options, endpoint.uri()),
            &fields,
            None,
        )
        .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 4];
        let head = request.parse_head(&mut slots).unwrap();
        assert_eq!(head.line().uri().as_str(), wire_uri);
        assert_eq!(
            head.header(header::HOST).and_then(|value| value.as_bytes()),
            Some(host.as_bytes()),
        );
    }

    for uri in [
        "http://icap.test/scan",
        "icap:///scan",
        "icap://icap.test",
        "icap://icap.test?mode=scan",
        "icap://icap.test/scan#fragment",
    ] {
        assert!(ServiceEndpoint::new(uri).is_err(), "accepted {uri}");
    }

    endpoint
        .headers_mut()
        .insert("preview", "10".parse().unwrap());
    endpoint.request_headers(&[]).unwrap_err();

    let mut endpoint = ServiceEndpoint::new("icap://icap.test/scan").unwrap();
    endpoint.headers_mut().insert(
        http_header::PROXY_AUTHORIZATION,
        HeaderValue::from_static("Basic ambiguous"),
    );
    endpoint.request_headers(&[]).unwrap_err();

    validate_success_status(Method::Reqmod, StatusCode::OK).unwrap();
    validate_success_status(Method::Respmod, StatusCode::CREATED).unwrap();
    validate_success_status(Method::Respmod, StatusCode::PARTIAL_CONTENT).unwrap();
    validate_success_status(Method::Reqmod, StatusCode::PARTIAL_CONTENT).unwrap();
    validate_success_status(Method::Respmod, StatusCode::NOT_FOUND).unwrap_err();
}

#[tokio::test]
async fn allow_204_is_offered_only_for_a_body_within_replay_bounds() {
    struct ExactFrames {
        frames: std::collections::VecDeque<Frame<Bytes>>,
        data_len: u64,
    }

    impl rama_http_types::body::StreamingBody for ExactFrames {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Ready(self.frames.pop_front().map(Ok))
        }

        fn size_hint(&self) -> rama_http_types::body::SizeHint {
            rama_http_types::body::SizeHint::with_exact(self.data_len)
        }
    }

    let endpoint = ServiceEndpoint::new("icap://icap.test/scan")
        .unwrap()
        .with_replay_limits(crate::http::ReplayLimits::new().with_max_bytes(4));

    let (body, replayable) =
        super::service::prepare_replay_body(Body::from("four"), endpoint.replay_limits())
            .await
            .unwrap();
    assert!(replayable);
    assert_eq!(body.collect().await.unwrap().to_bytes(), "four");
    let (body, replayable) =
        super::service::prepare_replay_body(Body::from("five!"), endpoint.replay_limits())
            .await
            .unwrap();
    assert!(!replayable);
    assert_eq!(body.collect().await.unwrap().to_bytes(), "five!");

    let limits = crate::http::ReplayLimits::new()
        .with_max_bytes(100)
        .with_max_frames(2);
    let (body, replayable) = super::service::prepare_replay_body(
        Body::new(ExactFrames {
            frames: ["a", "b", "c"]
                .map(|data| Frame::data(Bytes::from_static(data.as_bytes())))
                .into(),
            data_len: 3,
        }),
        limits,
    )
    .await
    .unwrap();
    assert!(!replayable, "the source frame bound must be proven");
    assert_eq!(body.collect().await.unwrap().to_bytes(), "abc");

    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", HeaderValue::from_static("1234"));
    let (body, replayable) = super::service::prepare_replay_body(
        Body::new(ExactFrames {
            frames: [
                Frame::data(Bytes::from_static(b"four")),
                Frame::trailers(trailers),
            ]
            .into(),
            data_len: 4,
        }),
        crate::http::ReplayLimits::new()
            .with_max_bytes(4)
            .with_max_frames(2),
    )
    .await
    .unwrap();
    assert!(!replayable, "the trailer byte bound must be proven");
    let collected = body.collect().await.unwrap();
    assert_eq!(collected.to_bytes(), "four");
    assert_eq!(
        super::service::replay_bounded_preview(Preview::new(100), &endpoint),
        Preview::new(4)
    );

    let endpoint = endpoint.with_replay_limits(
        crate::http::ReplayLimits::new()
            .with_max_bytes(100)
            .with_max_frames(2),
    );
    assert_eq!(
        super::service::replay_bounded_preview(Preview::new(100), &endpoint),
        Preview::new(2)
    );
}

#[test]
fn connector_target_does_not_replace_logical_service_authority() {
    let mut endpoint = ServiceEndpoint::new("icaps://icap.test/scan").unwrap();
    endpoint.insert_connection_extension(ConnectorTarget("127.0.0.1:31344".parse().unwrap()));

    let adaptation = endpoint.connect_request();
    assert_eq!(adaptation.authority.to_string(), "icap.test:11344");
    assert_eq!(adaptation.protocol(), Some(&Protocol::ICAPS));
    assert_eq!(
        adaptation.connector_target().unwrap().to_string(),
        "127.0.0.1:31344",
    );

    let options = endpoint.options_request().unwrap();
    assert_eq!(
        options.connect_request().authority.to_string(),
        "icap.test:11344",
    );
    assert_eq!(
        options
            .connect_request()
            .connector_target()
            .unwrap()
            .to_string(),
        "127.0.0.1:31344",
    );
}

#[test]
fn application_protocol_separates_plaintext_and_tls_at_same_authority() {
    let plain = ServiceEndpoint::new("icap://icap.test:11344/scan")
        .unwrap()
        .connect_request();
    let secure = ServiceEndpoint::new("icaps://icap.test:11344/scan")
        .unwrap()
        .connect_request();

    assert_eq!(plain.authority, secure.authority);
    assert_eq!(plain.protocol(), Some(&Protocol::ICAP));
    assert_eq!(secure.protocol(), Some(&Protocol::ICAPS));
}

#[test]
fn endpoint_outer_icap_trailer_offer_is_explicit_and_resets_options_request() {
    let endpoint = ServiceEndpoint::new("icap://icap.test/scan").unwrap();
    assert!(!endpoint.allows_icap_trailers());
    assert!(
        endpoint
            .request_headers(&[])
            .unwrap()
            .iter()
            .all(|field| !field.name().eq_ignore_ascii_case(header::ALLOW))
    );
    let before = endpoint.options_request().unwrap();

    let endpoint = endpoint
        .with_allow_204(true)
        .with_allow_206(true)
        .with_allow_icap_trailers(true);
    assert!(endpoint.allows_icap_trailers());
    let fields = endpoint.request_headers(&[]).unwrap();
    assert_eq!(
        fields.last().copied(),
        Some(Header::new(header::ALLOW, b"204, 206, trailers").unwrap())
    );
    let after = endpoint.options_request().unwrap();
    assert_ne!(
        before.request().head_bytes().as_ptr(),
        after.request().head_bytes().as_ptr()
    );
    assert!(after.request().allows_icap_trailers());
}

#[test]
fn discovered_capabilities_gate_outer_icap_trailer_offers() {
    let endpoint = endpoint("reqmod").with_allow_icap_trailers(true);
    let capabilities = discovered_capabilities();
    let policy = effective_policy(
        &endpoint,
        Some(&capabilities),
        MethodKind::Reqmod,
        "html",
        UnsupportedMethodPolicy::Error,
    )
    .unwrap();
    assert!(!policy.allow_icap_trailers);

    let response = IcapResponse::new(
        MethodKind::Options,
        ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
        &[
            Header::new(header::METHODS, b"REQMOD").unwrap(),
            Header::new(header::ISTAG, b"\"options-test\"").unwrap(),
            Header::new(header::ALLOW, b"trailers").unwrap(),
        ],
        Some(EncapsulatedParts::null()),
    )
    .unwrap();
    let capabilities =
        ServiceCapabilities::parse(response, None, 8, false, OptionsValidation::Compatible)
            .unwrap();
    let policy = effective_policy(
        &endpoint,
        Some(&capabilities),
        MethodKind::Reqmod,
        "html",
        UnsupportedMethodPolicy::Error,
    )
    .unwrap();
    assert!(policy.allow_icap_trailers);
}

#[test]
fn discovered_capabilities_skip_an_unsupported_adaptation_direction() {
    let response = IcapResponse::new(
        MethodKind::Options,
        ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
        &[
            Header::new(header::METHODS, b"REQMOD").unwrap(),
            Header::new(header::ISTAG, b"\"options-test\"").unwrap(),
        ],
        Some(EncapsulatedParts::null()),
    )
    .unwrap();
    let capabilities =
        ServiceCapabilities::parse(response, None, 8, false, OptionsValidation::Compatible)
            .unwrap();

    let request = effective_policy(
        &endpoint("adapt"),
        Some(&capabilities),
        MethodKind::Reqmod,
        "html",
        UnsupportedMethodPolicy::Bypass,
    )
    .unwrap();
    assert!(request.adapt);

    let response = effective_policy(
        &endpoint("adapt"),
        Some(&capabilities),
        MethodKind::Respmod,
        "html",
        UnsupportedMethodPolicy::Bypass,
    )
    .unwrap();
    assert!(!response.adapt);
    assert_eq!(response.preview, None);
    assert!(!response.allow_204);
    assert!(!response.allow_206);
    assert!(!response.allow_icap_trailers);
    effective_policy(
        &endpoint("adapt"),
        Some(&capabilities),
        MethodKind::Respmod,
        "html",
        UnsupportedMethodPolicy::Error,
    )
    .unwrap_err();
}

#[test]
fn transfer_defaults_to_complete_and_uses_decoded_target_extension() {
    let response = IcapResponse::new(
        MethodKind::Options,
        ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
        &[
            Header::new(header::METHODS, b"REQMOD").unwrap(),
            Header::new(header::ISTAG, b"\"options-test\"").unwrap(),
            Header::new(header::PREVIEW, b"2").unwrap(),
        ],
        Some(EncapsulatedParts::null()),
    )
    .unwrap();
    let capabilities =
        ServiceCapabilities::parse(response, None, 8, false, OptionsValidation::Compatible)
            .unwrap();
    let policy = effective_policy(
        &endpoint("reqmod"),
        Some(&capabilities),
        MethodKind::Reqmod,
        "html",
        UnsupportedMethodPolicy::Error,
    )
    .unwrap();
    assert!(policy.adapt);
    assert_eq!(policy.preview, None);

    let uri = rama_net::uri::Uri::parse_strict("http://origin.test/a%2EHTML?download=1").unwrap();
    assert_eq!(request_target_extension(&uri).as_deref(), Some("HTML"));
}

#[test]
fn separates_proxy_credentials_and_removes_hop_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http_header::PROXY_AUTHORIZATION,
        HeaderValue::from_static("Basic secret"),
    );
    headers.insert(
        http_header::PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=test"),
    );
    headers.insert(
        http_header::CONNECTION,
        HeaderValue::from_static("x-private, keep-alive"),
    );
    headers.insert("x-private", HeaderValue::from_static("drop"));
    headers.insert(
        http_header::KEEP_ALIVE,
        HeaderValue::from_static("timeout=5"),
    );
    headers.insert(http_header::TE, HeaderValue::from_static("trailers"));
    headers.insert(http_header::TRAILER, HeaderValue::from_static("x-trailer"));
    headers.insert(
        http_header::TRANSFER_ENCODING,
        HeaderValue::from_static("chunked"),
    );
    headers.insert(http_header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(
        http_header::PROXY_CONNECTION,
        HeaderValue::from_static("keep-alive"),
    );
    headers.insert("x-end-to-end", HeaderValue::from_static("keep"));

    let forwarded = sanitize_http_headers(&mut headers);
    assert_eq!(headers.len(), 1);
    assert_eq!(headers["x-end-to-end"], "keep");

    let endpoint = ServiceEndpoint::new("icap://icap.test/scan").unwrap();
    let fields = endpoint.request_headers(&forwarded).unwrap();
    assert!(fields.contains(&Header::new(header::PROXY_AUTHORIZATION, b"Basic secret").unwrap()));
    assert!(
        fields.contains(&Header::new(header::PROXY_AUTHENTICATE, b"Basic realm=test").unwrap())
    );

    let mut request = Request::builder()
        .uri("http://[2001:db8::5]:8080/path")
        .header(http_header::HOST, "wrong.example")
        .body(())
        .unwrap();
    normalize_request_authority(&mut request).unwrap();
    assert_eq!(request.headers()[http_header::HOST], "[2001:db8::5]:8080");
    let encoded =
        crate::http::Encapsulated::from_request(&request, EncapsulatedKind::NullBody).unwrap();
    assert_eq!(
        encoded.request_header().unwrap().as_ref(),
        b"GET /path HTTP/1.1\r\nhost: [2001:db8::5]:8080\r\n\r\n",
    );
}

#[test]
fn caller_can_choose_shared_connector_ownership() {
    struct NonCloneConnector;
    fn assert_clone<T: Clone>(_value: &T) {}

    let layer = AdaptationLayer::new(Arc::new(NonCloneConnector));
    let service = layer.layer(());
    assert_clone(&layer);
    assert_clone(&service);
}
