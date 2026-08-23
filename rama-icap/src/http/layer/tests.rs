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
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    futures::stream,
    service::service_fn,
};
use rama_http_types::{
    Body, HeaderMap, Request, Response,
    body::{Frame, util::BodyExt as _},
    header::{self as http_header, HeaderValue, TRAILER},
};
use rama_net::{
    Protocol, ProtocolInputExt as _, TransportProtocolInputExt as _,
    client::{
        ConnectRequest, EstablishedClientConnection,
        pool::{ConnID, LruDropPool, PooledConnector},
    },
    transport::TransportProtocol,
};

use super::*;
use crate::{
    client::{
        ClientConnection,
        options::{OptionsValidation, ServiceCapabilities},
    },
    codec::{HeadParserConfig, Header, HeaderFolding, HeaderSlot, ResponseLine},
    http::{HttpService, IncomingRequest, OutgoingResponse},
    io::ConnectionOptions,
    message::{EncapsulatedParts, Response as IcapResponse},
    proto::{EncapsulatedKind, Method, MethodKind, Preview, StatusCode, header},
    server::{IncomingRequest as RawIncomingRequest, Server},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::Notify,
    time::timeout,
};

fn endpoint(path: &str) -> ServiceEndpoint {
    ServiceEndpoint::new(format!("icap://icap.test/{path}"))
        .unwrap()
        .with_preview(Preview::new(4))
        .with_allow_206(true)
}

fn adaptation_response_fields() -> [Header<'static>; 1] {
    [Header::new(header::ISTAG, b"\"layer-test\"").unwrap()]
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

fn test_connection_id(_input: &ConnectRequest) -> Result<TestConnectionId, BoxError> {
    Ok(TestConnectionId)
}

async fn serve_adaptation(request: IncomingRequest) -> Result<OutgoingResponse, BoxError> {
    let method = request.icap().method();
    let (_icap, encapsulated, body, _extensions) = request.into_parts();
    let encapsulated = encapsulated.expect("typed HTTP metadata");
    let collected = body.collect().await?;
    let body = Body::new(collected);
    let line = ResponseLine::new(StatusCode::OK, b"OK").unwrap();
    let fields = adaptation_response_fields();
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
    let connector = service_fn(move |input: ConnectRequest| {
        let connector_connections = Arc::clone(&connector_connections);
        async move {
            assert_eq!(input.authority.to_string(), "icap.test:1344");
            assert_eq!(input.protocol(), Some(&Protocol::ICAP));
            assert_eq!(input.transport_protocol(), Some(TransportProtocol::Tcp));
            connector_connections.fetch_add(1, Ordering::Relaxed);
            let (client_io, server_io) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let server = Server::new(
                    HttpService::new(service_fn(serve_adaptation)),
                    b"\"rama-test\"",
                )
                .unwrap();
                server.serve(ServiceInput::new(server_io)).await.unwrap();
            });
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ClientConnection::new(ServiceInput::new(client_io)),
            })
        }
    });

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
        .with_request_service(endpoint("reqmod"))
        .with_response_service(endpoint("respmod"))
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
    assert_eq!(response_body.to_bytes(), "response-body");
    assert_eq!(connections.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn options_discovery_constrains_ephemeral_adaptation_policy() {
    let connector = service_fn(move |input: ConnectRequest| async move {
        let (client_io, server_io) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let adaptation = service_fn(async |request: IncomingRequest| {
                assert_eq!(request.icap().preview(), Some(Preview::new(2)));
                assert!(!request.icap().allows_204());
                assert!(request.icap().allows_206());
                serve_adaptation(request).await
            });
            Server::new(HttpService::new(adaptation), b"\"rama-test\"")
                .unwrap()
                .serve(ServiceInput::new(server_io))
                .await
                .unwrap();
        });
        Ok::<_, Infallible>(EstablishedClientConnection {
            input,
            conn: ClientConnection::new(ServiceInput::new(client_io)),
        })
    });
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
async fn transfer_ignore_bypasses_reqmod_and_respmod() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let connector = service_fn(move |input: ConnectRequest| {
        connector_connections.fetch_add(1, Ordering::Relaxed);
        async move {
            let (client_io, _server_io) = tokio::io::duplex(256);
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ClientConnection::new(ServiceInput::new(client_io)),
            })
        }
    });
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
    let connector = service_fn(move |input: ConnectRequest| {
        let connector_connections = Arc::clone(&connector_connections);
        async move {
            connector_connections.fetch_add(1, Ordering::Relaxed);
            let (client_io, server_io) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let adaptation = service_fn(async |request: IncomingRequest| {
                    assert_eq!(request.icap().preview(), None);
                    serve_adaptation(request).await
                });
                Server::new(HttpService::new(adaptation), b"\"rama-test\"")
                    .unwrap()
                    .serve(ServiceInput::new(server_io))
                    .await
                    .unwrap();
            });
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ClientConnection::new(ServiceInput::new(client_io)),
            })
        }
    });
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
    let connector = service_fn(move |input: ConnectRequest| async move {
        let (client_io, server_io) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let server = Server::new(
                HttpService::new(service_fn(serve_adaptation)),
                b"\"rama-test\"",
            )
            .unwrap();
            server.serve(ServiceInput::new(server_io)).await.unwrap();
        });
        Ok::<_, Infallible>(EstablishedClientConnection {
            input,
            conn: ClientConnection::new(ServiceInput::new(client_io)),
        })
    });
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
    let transport = service_fn(move |input: ConnectRequest| {
        let connector_connections = Arc::clone(&connector_connections);
        async move {
            connector_connections.fetch_add(1, Ordering::Relaxed);
            let (client_io, server_io) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let server = Server::new(
                    HttpService::new(service_fn(serve_adaptation)),
                    b"\"rama-test\"",
                )
                .unwrap();
                server.serve(ServiceInput::new(server_io)).await.unwrap();
            });
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(client_io),
            })
        }
    });
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let connector =
        crate::client::Client::new(PooledConnector::new(transport, pool, test_connection_id));
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
                        b"\"rama-test\"",
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
    let connector =
        crate::client::Client::new(PooledConnector::new(transport, pool, test_connection_id));
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
    let transport = service_fn(move |input: ConnectRequest| {
        let connector_connections = Arc::clone(&connector_connections);
        async move {
            connector_connections.fetch_add(1, Ordering::Relaxed);
            let (client_io, server_io) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let server = Server::new(
                    HttpService::new(service_fn(serve_adaptation)),
                    b"\"rama-test\"",
                )
                .unwrap();
                let _result = server.serve(ServiceInput::new(server_io)).await;
            });
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(client_io),
            })
        }
    });
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let connector =
        crate::client::Client::new(PooledConnector::new(transport, pool, test_connection_id));
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
    let transport = service_fn(move |input: ConnectRequest| {
        let connector_connections = Arc::clone(&connector_connections);
        async move {
            connector_connections.fetch_add(1, Ordering::Relaxed);
            let (client_io, server_io) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let server = Server::new(
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
                    b"\"rama-test\"",
                )
                .unwrap();
                server.serve(ServiceInput::new(server_io)).await.unwrap();
            });
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(client_io),
            })
        }
    });
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let connector =
        crate::client::Client::new(PooledConnector::new(transport, pool, test_connection_id));
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
    let connector = service_fn(async |input: ConnectRequest| {
        let (client_io, server_io) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let server = Server::new(
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
                b"\"rama-test\"",
            )
            .unwrap();
            server.serve(ServiceInput::new(server_io)).await.unwrap();
        });
        Ok::<_, Infallible>(EstablishedClientConnection {
            input,
            conn: ClientConnection::new(ServiceInput::new(client_io)),
        })
    });
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
    let connector = service_fn(async |input: ConnectRequest| {
        let (client_io, server_io) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut connection = crate::server::ServerConnection::new(ServiceInput::new(server_io));
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
        });
        Ok::<_, Infallible>(EstablishedClientConnection {
            input,
            conn: ClientConnection::new(ServiceInput::new(client_io)),
        })
    });
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
async fn reqmod_response_bypasses_origin_and_respmod() {
    let connections = Arc::new(AtomicUsize::new(0));
    let connector_connections = Arc::clone(&connections);
    let transport = service_fn(move |input: ConnectRequest| {
        let connector_connections = Arc::clone(&connector_connections);
        async move {
            connector_connections.fetch_add(1, Ordering::Relaxed);
            let (client_io, server_io) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let server = Server::new(
                    HttpService::new(service_fn(serve_blocking_adaptation)),
                    b"\"rama-test\"",
                )
                .unwrap();
                let _result = server.serve(ServiceInput::new(server_io)).await;
            });
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(client_io),
            })
        }
    });
    let pool = LruDropPool::try_new(1, 1)
        .unwrap()
        .with_drop_connection_if_no_response(false);
    let connector =
        crate::client::Client::new(PooledConnector::new(transport, pool, test_connection_id));
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
    let connector = service_fn(async |input: ConnectRequest| {
        let (client_io, server_io) = tokio::io::duplex(512);
        tokio::spawn(async move {
            let server = Server::new(
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
                b"\"rama-test\"",
            )
            .unwrap();
            server.serve(ServiceInput::new(server_io)).await.unwrap();
        });
        Ok::<_, Infallible>(EstablishedClientConnection {
            input,
            conn: ClientConnection::new(ServiceInput::new(client_io)),
        })
    });
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
async fn canonicalizes_authority_of_adapted_absolute_request() {
    let connector = service_fn(async |input: ConnectRequest| {
        let (client_io, server_io) = tokio::io::duplex(512);
        tokio::spawn(async move {
            let server = Server::new(
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
                b"\"rama-test\"",
            )
            .unwrap();
            server.serve(ServiceInput::new(server_io)).await.unwrap();
        });
        Ok::<_, Infallible>(EstablishedClientConnection {
            input,
            conn: ClientConnection::new(ServiceInput::new(client_io)),
        })
    });
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
    let connector = service_fn(async |input: ConnectRequest| {
        let (client_io, server_io) = tokio::io::duplex(512);
        tokio::spawn(async move {
            let server = Server::new(
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
                b"\"rama-test\"",
            )
            .unwrap();
            server.serve(ServiceInput::new(server_io)).await.unwrap();
        });
        Ok::<_, Infallible>(EstablishedClientConnection {
            input,
            conn: ClientConnection::new(ServiceInput::new(client_io)),
        })
    });
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
async fn preserves_parser_policy_for_returned_proxy_headers() {
    let connector = service_fn(async |input: ConnectRequest| {
        let (client_io, mut server_io) = tokio::io::duplex(512);
        tokio::spawn(async move {
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
        });
        let options = ConnectionOptions::new()
            .with_head_parser(HeadParserConfig::new().with_header_folding(HeaderFolding::Allow));
        Ok::<_, Infallible>(EstablishedClientConnection {
            input,
            conn: ClientConnection::with_options(ServiceInput::new(client_io), options),
        })
    });
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
    assert_eq!(endpoint.uri().as_str(), "icap://[::1]:31344/scan");
    assert_eq!(endpoint.authority().to_string(), "[::1]:31344");
    let fields = endpoint.request_headers(&[]).unwrap();
    assert_eq!(fields[0], Header::new("authorization", b"secret").unwrap());
    assert_eq!(
        fields[1],
        Header::new(header::HOST, b"[::1]:31344").unwrap()
    );
    assert_eq!(fields[2], Header::new(header::ALLOW, b"204, 206").unwrap());
    assert!(!format!("{endpoint:?}").contains("secret"));
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
    assert!(
        first_options
            .connect_request()
            .extensions
            .parent()
            .is_none()
    );
    assert!(!format!("{first_options:?}").contains("secret"));

    let userinfo_endpoint = ServiceEndpoint::new("icap://user:secret@icap.test:/scan").unwrap();
    assert_eq!(userinfo_endpoint.authority().to_string(), "icap.test:1344");
    assert_eq!(
        userinfo_endpoint.request_headers(&[]).unwrap()[0],
        Header::new(header::HOST, b"icap.test").unwrap(),
    );
    assert!(!format!("{userinfo_endpoint:?}").contains("secret"));

    for (uri, target, host) in [
        (
            "icap://icap.test:01344/scan",
            "icap.test:1344",
            "icap.test:1344",
        ),
        (
            "icap://icap.test:031344/scan",
            "icap.test:31344",
            "icap.test:31344",
        ),
        (
            "icap://[0:0:0:0:0:0:0:1]:1344/scan",
            "[::1]:1344",
            "[::1]:1344",
        ),
    ] {
        let endpoint = ServiceEndpoint::new(uri).unwrap();
        assert_eq!(endpoint.authority().to_string(), target);
        let fields = endpoint.request_headers(&[]).unwrap();
        assert_eq!(
            fields[0],
            Header::new(header::HOST, host.as_bytes()).unwrap()
        );
        let request = crate::message::Request::new_from_source(
            crate::codec::RequestLineSource::prepared(
                Method::Options,
                endpoint.uri(),
                endpoint.host_header(),
            ),
            &fields,
            None,
        )
        .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 4];
        let head = request.parse_head(&mut slots).unwrap();
        assert_eq!(head.line().uri().as_str(), uri);
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
    validate_success_status(Method::Respmod, StatusCode::PARTIAL_CONTENT).unwrap();
    validate_success_status(Method::Reqmod, StatusCode::PARTIAL_CONTENT).unwrap();
    validate_success_status(Method::Respmod, StatusCode::NOT_FOUND).unwrap_err();
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
fn layer_and_service_clone_without_cloning_connector() {
    struct NonCloneConnector;
    fn assert_clone<T: Clone>(_value: &T) {}

    let layer = AdaptationLayer::new(NonCloneConnector);
    let service = layer.layer(());
    assert_clone(&layer);
    assert_clone(&service);
}
