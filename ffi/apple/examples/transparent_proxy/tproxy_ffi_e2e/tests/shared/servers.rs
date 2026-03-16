use std::{convert::Infallible, io, sync::Arc, time::Duration};

use rama::{
    Layer, Service,
    bytes::Bytes as RamaBytes,
    futures::async_stream::stream_fn,
    http::{
        Body, Request, Response, StatusCode,
        header::SEC_WEBSOCKET_VERSION,
        headers::ContentType,
        layer::{
            compression::{CompressionLayer, predicate::Always},
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            upgrade::{
                DefaultHttpProxyConnectReplyService, UpgradeLayer, mitm::HttpUpgradeMitmRelayLayer,
            },
        },
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{
            Router,
            response::{Headers, Html, IntoResponse as _, Json, Sse},
        },
        sse::{
            self,
            server::{KeepAlive, KeepAliveStream},
        },
        ws::handshake::{
            matcher::{
                HttpWebSocketRelayServiceRequestMatcher, WebSocketMatcher,
                is_http_req_websocket_handshake,
            },
            server::{WebSocketAcceptor, WebSocketEchoService},
        },
    },
    layer::ConsumeErrLayer,
    net::{
        address::{Domain, SocketAddress},
        proxy::IoForwardService,
        tls::server::SelfSignedData,
    },
    proxy::socks5::{Socks5Acceptor, server::Socks5PeekRouter},
    rt::Executor,
    service::service_fn,
    tcp::{proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing,
    tls::rustls::server::{TlsAcceptorDataBuilder, TlsAcceptorLayer},
};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener as TokioTcpListener, UdpSocket},
};

use super::types::{HttpObservation, OBSERVED_HEADER, SharedObservations};

fn http_app(
    observations: &SharedObservations,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let router = Router::new()
            .with_get("/html", {
                let observations = Arc::clone(observations);
                move |req: Request| {
                    let observations = Arc::clone(&observations);
                    async move {
                        record_http_observation(observations, &req).await;
                        Html(
                            "<!DOCTYPE html><html><head><title>ffi html</title></head><body><h1>hello ffi</h1></body></html>",
                        )
                        .into_response()
                    }
                }
            })
            .with_get("/json", {
                let observations = Arc::clone(observations);
                move |req: Request| {
                    let observations = Arc::clone(&observations);
                    async move {
                        record_http_observation(observations, &req).await;
                        Json(json!({
                            "path": req.uri().path(),
                            "query": req.uri().query(),
                            "observed": req.headers().get(OBSERVED_HEADER).is_some(),
                            "version": format!("{:?}", req.version()),
                        }))
                    }
                }
            })
            .with_get("/chunked", {
                let observations = Arc::clone(observations);
                move |req: Request| {
                    let observations = Arc::clone(&observations);
                    async move {
                        record_http_observation(observations, &req).await;
                        (
                            Headers::single(ContentType::html_utf8()),
                            Body::from_stream(stream_fn(move |mut yielder| async move {
                                yielder
                                    .yield_item(Ok::<_, io::Error>(RamaBytes::from_static(
                                        b"<!DOCTYPE html><html><body>chunk-0",
                                    )))
                                    .await;
                                tokio::time::sleep(Duration::from_millis(15)).await;
                                yielder
                                    .yield_item(Ok::<_, io::Error>(RamaBytes::from_static(
                                        b"<p>chunk-1</p>",
                                    )))
                                    .await;
                                tokio::time::sleep(Duration::from_millis(15)).await;
                                yielder
                                    .yield_item(Ok::<_, io::Error>(RamaBytes::from_static(
                                        b"<p>chunk-2</p></body></html>",
                                    )))
                                    .await;
                            })),
                        )
                            .into_response()
                    }
                }
            })
            .with_get("/sse", {
                let observations = Arc::clone(observations);
                move |req: Request| {
                    let observations = Arc::clone(&observations);
                    async move {
                        record_http_observation(observations, &req).await;
                        Sse::new(KeepAliveStream::new(
                            KeepAlive::new(),
                            stream_fn(move |mut yielder| async move {
                                for idx in 0..3 {
                                    yielder
                                        .yield_item(Ok::<_, io::Error>(
                                            sse::Event::new().with_data(format!("event-{idx}")),
                                        ))
                                        .await;
                                }
                            }),
                        ))
                        .into_response()
                    }
                }
            });

    Arc::new(
        (
            UpgradeLayer::new(
                Executor::default(),
                HttpMatcher::path("/ws").and_custom(WebSocketMatcher::new()),
                WebSocketAcceptor::new(),
                ConsumeErrLayer::trace_as_debug().into_layer(WebSocketEchoService::new()),
            ),
            MapResponseBodyLayer::new_boxed_streaming_body(),
            CompressionLayer::new().with_compress_predicate(Always::new()),
        )
            .into_layer(router),
    )
}

pub(crate) async fn spawn_http_server(bind_port: u16, observations: SharedObservations) {
    let mut server = HttpServer::auto(Executor::default());
    server.h2_mut().set_enable_connect_protocol();
    let listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(bind_port), Executor::default())
            .await
            .expect("bind plain http server");
    tokio::spawn(listener.serve(server.service(http_app(&observations))));
}

pub(crate) async fn spawn_https_server(bind_port: u16, observations: SharedObservations) {
    let tls_data = TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData {
        organisation_name: Some("Rama FFI HTTPS E2E".to_owned()),
        common_name: Some(Domain::from_static("127.0.0.1")),
        ..Default::default()
    })
    .expect("https tls data")
    .with_alpn_protocols_http_auto()
    .build();

    let mut server = HttpServer::auto(Executor::default());
    server.h2_mut().set_enable_connect_protocol();
    let listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(bind_port), Executor::default())
            .await
            .expect("bind https server");
    tokio::spawn(listener.serve(
        TlsAcceptorLayer::new(tls_data).into_layer(server.service(http_app(&observations))),
    ));
}

async fn record_http_observation(observations: SharedObservations, req: &Request) {
    observations.lock().await.push(HttpObservation {
        uri: req.uri().path().to_owned(),
        observed_header: req
            .headers()
            .get(OBSERVED_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
    });
}

pub(crate) async fn spawn_raw_tcp_echo(bind_port: u16) {
    let listener = TokioTcpListener::bind(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("bind raw tcp echo");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0_u8; 1024];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

pub(crate) async fn spawn_raw_tls_echo(bind_port: u16) {
    let tls_data = TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData {
        organisation_name: Some("Rama FFI Raw TLS E2E".to_owned()),
        common_name: Some(Domain::from_static("127.0.0.1")),
        ..Default::default()
    })
    .expect("raw tls data")
    .build();

    let listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(bind_port), Executor::default())
            .await
            .expect("bind raw tls echo");
    tokio::spawn(
        listener.serve(TlsAcceptorLayer::new(tls_data).into_layer(service_fn(
            |stream| async move { tls_echo_service(stream).await },
        ))),
    );
}

async fn tls_echo_service<S>(mut stream: S) -> Result<(), io::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0_u8; 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        stream.write_all(&buf[..n]).await?;
    }
}

pub(crate) async fn spawn_udp_echo(bind_port: u16) {
    let socket = UdpSocket::bind(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("bind udp echo");
    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        loop {
            let Ok((n, addr)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let reply = buf[..n]
                .iter()
                .map(|byte| byte.to_ascii_uppercase())
                .collect::<Vec<_>>();
            if socket.send_to(&reply, addr).await.is_err() {
                break;
            }
        }
    });
}

pub(crate) async fn spawn_combined_proxy(bind_port: u16) {
    let exec = Executor::default();
    let mut http_server = HttpServer::auto(exec.clone());
    http_server.h2_mut().set_enable_connect_protocol();

    let http_proxy = http_server.service(
        UpgradeLayer::new(
            exec.clone(),
            HttpMatcher::header_exists(SEC_WEBSOCKET_VERSION)
                .negate()
                .and_method_connect(),
            DefaultHttpProxyConnectReplyService::new(),
            ConsumeErrLayer::trace_as_debug().into_layer(
                IoToProxyBridgeIoLayer::extension_proxy_target(exec.clone())
                    .into_layer(IoForwardService::new()),
            ),
        )
        .into_layer(service_fn(http_plain_proxy)),
    );

    let listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(bind_port), Executor::default())
            .await
            .expect("bind proxy listener");

    tokio::spawn(
        listener.serve(Socks5PeekRouter::new(Socks5Acceptor::default()).with_fallback(http_proxy)),
    );
}

async fn http_plain_proxy(req: Request) -> Result<Response, Infallible> {
    let inner_client = rama::http::client::EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .without_tls_support()
        .with_default_http_connector(Executor::default())
        .build_client();

    if is_http_req_websocket_handshake(&req) {
        let ws_client = HttpUpgradeMitmRelayLayer::new(
            Executor::default(),
            HttpWebSocketRelayServiceRequestMatcher::new(
                ConsumeErrLayer::trace_as_debug().into_layer(IoForwardService::new()),
            ),
        )
        .into_layer(inner_client);

        return Ok(match ws_client.serve(req).await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::error!("ffi e2e ws proxy upstream request failed: {err:?}");
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::empty())
                    .expect("build proxy error response")
            }
        });
    }

    let http_client = (
        RemoveRequestHeaderLayer::hop_by_hop(),
        RemoveResponseHeaderLayer::hop_by_hop(),
    )
        .into_layer(inner_client);

    Ok(match http_client.serve(req).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!("ffi e2e http proxy upstream request failed: {err:?}");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .expect("build proxy error response")
        }
    })
}
