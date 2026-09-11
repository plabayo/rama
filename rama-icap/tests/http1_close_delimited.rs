//! Raw HTTP -> MITM relay -> ICAP RESPMOD -> raw HTTP framing contracts.
//! ICAP chunking and downstream HTTP framing are independent. Paused clocks
//! prove incremental progress without waiting for real idle timeouts.
#![cfg(feature = "http")]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bounded wire fixtures fail immediately on malformed data or stalled IO"
)]

use rama_core::{
    Service, ServiceInput, error::BoxError, io::BridgeIo, layer::ArcLayer, rt::Executor,
    service::service_fn,
};
use rama_http_backend::proxy::mitm::HttpMitmRelay;
use rama_icap::{
    client::Client,
    http::layer::{AdaptationLayer, ServiceEndpoint},
    proto::Preview,
};
use rama_net::{
    client::{ConnectRequest, EstablishedClientConnection},
    test_utils::client::MockSocket,
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream},
    sync::Mutex,
    task::JoinHandle,
    time::{advance, timeout},
};

const WATCHDOG: Duration = Duration::from_secs(2);
struct Relay {
    client: BufReader<DuplexStream>,
    origin: BufReader<DuplexStream>,
    icap: BufReader<DuplexStream>,
    done: JoinHandle<Result<(), BoxError>>,
}
impl Relay {
    fn new(preview: bool) -> Self {
        Self::with_local_response(preview, false)
    }
    fn with_local_response(preview: bool, local: bool) -> Self {
        let (client, ingress) = tokio::io::duplex(4096);
        let (egress, origin) = tokio::io::duplex(4096);
        let (icap_client, icap) = tokio::io::duplex(4096);
        let transport = Arc::new(Mutex::new(Some(icap_client)));
        let connector = service_fn(move |input: ConnectRequest| {
            let transport = Arc::clone(&transport);
            async move {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(
                        transport
                            .lock()
                            .await
                            .take()
                            .expect("unexpected extra ICAP connection"),
                    ),
                })
            }
        });
        let endpoint = ServiceEndpoint::new("icap://icap.test/respmod").unwrap();
        let endpoint = if preview {
            endpoint.with_preview(Preview::new(5))
        } else {
            endpoint
        };
        let layer = AdaptationLayer::new(Client::new(connector)).with_response_service(endpoint);
        let done = tokio::spawn(async move {
            if local {
                use rama_core::{Layer as _, extensions::ExtensionsRef as _};
                use rama_http_types::{
                    Body, Request, Response, proto::h1::ext::CloseDelimitedResponse,
                };
                let adapted = layer.into_layer(service_fn(|_: Request| {
                    let response = Response::new(Body::from("firstlast"));
                    response.extensions().insert(CloseDelimitedResponse);
                    std::future::ready(Ok::<_, Infallible>(response))
                }));
                let service = service_fn(move |request: Request| {
                    let adapted = adapted.clone();
                    async move {
                        Ok::<_, Infallible>(
                            adapted
                                .serve(request)
                                .await
                                .expect("ICAP adaptation failed"),
                        )
                    }
                });
                rama_http_backend::server::HttpServer::auto(Executor::new())
                    .serve(MockSocket::new(ingress), service)
                    .await
            } else {
                HttpMitmRelay::new(Executor::new())
                    .with_http_middleware((layer, ArcLayer::new()))
                    .serve(BridgeIo(
                        MockSocket::new(ingress),
                        ServiceInput::new(egress),
                    ))
                    .await
            }
        });
        Self {
            client: BufReader::new(client),
            origin: BufReader::new(origin),
            icap: BufReader::new(icap),
            done,
        }
    }
    async fn begin(&mut self, version: &str, framing: Framing) {
        write(
            self.client.get_mut(),
            b"GET / HTTP/1.1\r\nHost: origin.test\r\nTE: trailers\r\nConnection: TE\r\n\r\n",
        )
        .await;
        assert!(
            head(&mut self.origin)
                .await
                .starts_with("GET / HTTP/1.1\r\n")
        );
        write(
            self.origin.get_mut(),
            format!("HTTP/{version} 200 OK\r\n{}\r\n", framing.headers()).as_bytes(),
        )
        .await;
        let outer = head(&mut self.icap).await;
        assert!(
            outer.starts_with("RESPMOD icap://icap.test/respmod ICAP/1.0\r\n"),
            "{outer:?}"
        );
        assert!(outer.to_ascii_lowercase().contains("res-body="));
        head(&mut self.icap).await; // Encapsulated request.
        let response = head(&mut self.icap).await;
        assert!(response.starts_with(&format!("HTTP/{version} 200 OK\r\n")));
        if matches!(framing, Framing::Close) {
            assert!(!response.to_ascii_lowercase().contains("content-length:"));
            assert!(!response.to_ascii_lowercase().contains("transfer-encoding:"));
        }
    }
    async fn adapted_head(&mut self, returned_headers: Option<&str>) -> String {
        if let Some(headers) = returned_headers {
            let response = format!("HTTP/1.1 200 OK\r\n{headers}\r\n");
            write(self.icap.get_mut(), format!("ICAP/1.0 200 OK\r\nISTag: \"framing-test\"\r\nEncapsulated: res-hdr=0, res-body={}\r\n\r\n{response}", response.len()).as_bytes()).await;
        } else {
            write(
                self.icap.get_mut(),
                b"ICAP/1.0 200 OK\r\nISTag: \"framing-test\"\r\nEncapsulated: res-body=0\r\n\r\n",
            )
            .await;
        }
        head(&mut self.client).await
    }
    async fn finish(mut self, error: bool) {
        if error {
            timeout(WATCHDOG, &mut self.done)
                .await
                .unwrap()
                .unwrap()
                .expect_err("upstream fault was swallowed");
        } else {
            drop(self.client);
            drop(self.origin);
            drop(self.icap);
            timeout(WATCHDOG, self.done)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Framing {
    Close,
    Length,
    Chunked,
}
impl Framing {
    fn headers(self) -> &'static str {
        match self {
            Self::Close => "",
            Self::Length => "Content-Length: 9\r\nConnection: keep-alive\r\n",
            Self::Chunked => "Transfer-Encoding: chunked\r\n",
        }
    }
}
async fn write(io: &mut DuplexStream, bytes: &[u8]) {
    timeout(WATCHDOG, io.write_all(bytes))
        .await
        .unwrap()
        .unwrap();
}
async fn bytes(io: &mut BufReader<DuplexStream>, len: usize) -> Vec<u8> {
    let mut data = vec![0; len];
    timeout(WATCHDOG, io.read_exact(&mut data))
        .await
        .unwrap()
        .unwrap();
    data
}
async fn head(io: &mut BufReader<DuplexStream>) -> String {
    timeout(WATCHDOG, async {
        let mut text = String::new();
        while !text.ends_with("\r\n\r\n") {
            assert_ne!(
                io.read_line(&mut text).await.unwrap(),
                0,
                "incomplete head: {text:?}"
            );
            assert!(text.len() < 4096);
        }
        text
    })
    .await
    .unwrap()
}
async fn pending(io: &mut BufReader<DuplexStream>) {
    assert!(
        timeout(Duration::from_millis(1), io.read_u8())
            .await
            .is_err(),
        "unexpected bytes or EOF"
    );
}
async fn eof(io: &mut BufReader<DuplexStream>) {
    assert_eq!(
        timeout(WATCHDOG, io.read(&mut [0])).await.unwrap().unwrap(),
        0
    );
}
async fn chunk(io: &mut DuplexStream, payload: &[u8]) {
    write(io, format!("{:x}\r\n", payload.len()).as_bytes()).await;
    write(io, payload).await;
    write(io, b"\r\n").await;
}
async fn payload(io: &mut BufReader<DuplexStream>, expected: &[u8], chunked: bool) {
    if !chunked {
        assert_eq!(bytes(io, expected.len()).await, expected);
        return;
    }
    let mut received = Vec::new();
    while received.len() < expected.len() {
        let mut line = String::new();
        timeout(WATCHDOG, io.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let size = usize::from_str_radix(line.trim(), 16).unwrap();
        assert!(size > 0 && size <= expected.len() - received.len());
        received.extend(bytes(io, size).await);
        assert_eq!(bytes(io, 2).await, b"\r\n");
    }
    assert_eq!(received, expected);
}
fn assert_framing(head: &str, version: &str, chunked: bool) {
    assert!(
        head.starts_with(&format!("HTTP/{version} 200 OK\r\n")),
        "{head:?}"
    );
    let lower = head.to_ascii_lowercase();
    assert_eq!(
        lower.contains("transfer-encoding: chunked\r\n"),
        chunked,
        "{head:?}"
    );
    assert!(
        !lower.contains("content-length:"),
        "adaptation must not forward a stale length: {head:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn respmod_framing_matrix_streams_both_hops() {
    for (version, framing) in [
        ("1.0", Framing::Close),
        ("1.1", Framing::Close),
        ("1.0", Framing::Length),
        ("1.1", Framing::Length),
        ("1.1", Framing::Chunked),
    ] {
        for preview in [false, true] {
            for returned_headers in [
                None,
                Some(""),
                Some("Content-Length: 999\r\n"),
                Some("Transfer-Encoding: chunked\r\n"),
            ] {
                let mut relay = Relay::new(preview);
                relay.begin(version, framing).await;
                if matches!(framing, Framing::Chunked) {
                    chunk(relay.origin.get_mut(), b"first").await;
                } else {
                    write(relay.origin.get_mut(), b"first").await;
                }
                payload(&mut relay.icap, b"first", true).await;
                if preview {
                    assert_eq!(bytes(&mut relay.icap, 5).await, b"0\r\n\r\n");
                    write(relay.icap.get_mut(), b"ICAP/1.0 100 Continue\r\n\r\n").await;
                }
                advance(Duration::from_secs(31)).await;
                pending(&mut relay.icap).await;
                pending(&mut relay.client).await; // No adaptation decision yet.
                if matches!(framing, Framing::Chunked) {
                    chunk(relay.origin.get_mut(), b"last").await;
                    write(relay.origin.get_mut(), b"0\r\n\r\n").await;
                } else {
                    write(relay.origin.get_mut(), b"last").await;
                }
                payload(&mut relay.icap, b"last", true).await;
                if matches!(framing, Framing::Close) {
                    pending(&mut relay.icap).await;
                    relay.origin.get_mut().shutdown().await.unwrap();
                }
                assert_eq!(bytes(&mut relay.icap, 5).await, b"0\r\n\r\n");
                let head = relay.adapted_head(returned_headers).await;
                let chunked = version == "1.1" && !matches!(framing, Framing::Close);
                assert_framing(&head, version, chunked);
                if matches!(framing, Framing::Close) {
                    assert!(head.to_ascii_lowercase().contains("connection: close\r\n"));
                }
                for part in [b"adapted-first".as_slice(), b"adapted-last".as_slice()] {
                    chunk(relay.icap.get_mut(), part).await;
                    payload(&mut relay.client, part, chunked).await;
                    advance(Duration::from_secs(31)).await;
                    pending(&mut relay.client).await;
                }
                // ICAP's terminal chunk, not ICAP TCP EOF, completes this HTTP body.
                write(relay.icap.get_mut(), b"0\r\n\r\n").await;
                if chunked {
                    assert_eq!(bytes(&mut relay.client, 5).await, b"0\r\n\r\n");
                } else {
                    eof(&mut relay.client).await;
                }
                relay.finish(false).await;
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn preview_204_replays_close_delimited_body_while_origin_remains_open() {
    for version in ["1.0", "1.1"] {
        let mut relay = Relay::new(true);
        relay.begin(version, Framing::Close).await;
        write(relay.origin.get_mut(), b"first").await;
        payload(&mut relay.icap, b"first", true).await;
        assert_eq!(bytes(&mut relay.icap, 5).await, b"0\r\n\r\n");
        write(relay.icap.get_mut(), b"ICAP/1.0 204 No Content\r\nISTag: \"framing-test\"\r\nEncapsulated: null-body=0\r\n\r\n").await;
        assert_framing(&head(&mut relay.client).await, version, false);
        payload(&mut relay.client, b"first", false).await;
        advance(Duration::from_secs(31)).await;
        pending(&mut relay.client).await;
        write(relay.origin.get_mut(), b"last").await;
        payload(&mut relay.client, b"last", false).await;
        pending(&mut relay.client).await;
        relay.origin.get_mut().shutdown().await.unwrap();
        eof(&mut relay.client).await;
        relay.finish(false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn truncated_icap_response_does_not_wait_for_fixture_teardown() {
    let mut relay = Relay::new(false);
    relay.begin("1.1", Framing::Close).await;
    relay.origin.get_mut().shutdown().await.unwrap();
    assert_eq!(bytes(&mut relay.icap, 5).await, b"0\r\n\r\n");
    assert_framing(&relay.adapted_head(Some("")).await, "1.1", false);
    chunk(relay.icap.get_mut(), b"partial").await;
    payload(&mut relay.client, b"partial", false).await;
    relay.icap.get_mut().shutdown().await.unwrap(); // Missing ICAP terminal chunk.
    eof(&mut relay.client).await;
    relay.finish(true).await;
}

#[tokio::test(start_paused = true)]
async fn empty_close_delimited_origin_preserves_framing_through_icap() {
    for preview in [false, true] {
        for unchanged in [false, true] {
            if unchanged && !preview {
                continue;
            } // 204 is allowed within Preview.
            let mut relay = Relay::new(preview);
            relay.begin("1.1", Framing::Close).await;
            relay.origin.get_mut().shutdown().await.unwrap();
            let end = head(&mut relay.icap).await;
            assert_eq!(
                end,
                if preview {
                    "0; ieof\r\n\r\n"
                } else {
                    "0\r\n\r\n"
                }
            );
            let response = if unchanged {
                write(relay.icap.get_mut(), b"ICAP/1.0 204 No Content\r\nISTag: \"framing-test\"\r\nEncapsulated: null-body=0\r\n\r\n").await;
                head(&mut relay.client).await
            } else {
                let response = relay.adapted_head(Some("")).await;
                write(relay.icap.get_mut(), b"0\r\n\r\n").await;
                response
            };
            assert_framing(&response, "1.1", false);
            eof(&mut relay.client).await;
            relay.finish(false).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn icap_preserves_explicit_framing_without_mitm_metadata() {
    let mut relay = Relay::with_local_response(false, true);
    write(
        relay.client.get_mut(),
        b"GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n",
    )
    .await;
    head(&mut relay.icap).await;
    head(&mut relay.icap).await;
    head(&mut relay.icap).await;
    payload(&mut relay.icap, b"firstlast", true).await;
    assert_eq!(bytes(&mut relay.icap, 5).await, b"0\r\n\r\n");
    assert_framing(&relay.adapted_head(Some("")).await, "1.1", false);
    chunk(relay.icap.get_mut(), b"adapted").await;
    payload(&mut relay.client, b"adapted", false).await;
    pending(&mut relay.client).await;
    write(relay.icap.get_mut(), b"0\r\n\r\n").await;
    eof(&mut relay.client).await;
    relay.finish(false).await;
}

#[tokio::test(start_paused = true)]
async fn icap_added_trailers_override_close_delimited_framing() {
    let mut relay = Relay::new(false);
    relay.begin("1.1", Framing::Close).await;
    relay.origin.get_mut().shutdown().await.unwrap();
    assert_eq!(bytes(&mut relay.icap, 5).await, b"0\r\n\r\n");
    let response = relay.adapted_head(Some("Trailer: x-checksum\r\n")).await;
    assert_framing(&response, "1.1", true);
    chunk(relay.icap.get_mut(), b"adapted").await;
    payload(&mut relay.client, b"adapted", true).await;
    pending(&mut relay.client).await;
    write(relay.icap.get_mut(), b"0\r\nx-checksum: ok\r\n\r\n").await;
    assert_eq!(
        head(&mut relay.client).await.to_ascii_lowercase(),
        "0\r\nx-checksum: ok\r\n\r\n"
    );
    relay.finish(false).await;
}
