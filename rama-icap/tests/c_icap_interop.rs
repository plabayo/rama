#![cfg(feature = "std")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{env, net::SocketAddr};

#[cfg(feature = "http")]
use rama_core::{Layer as _, Service as _, service::service_fn};
use rama_core::{
    ServiceInput,
    bytes::{Bytes, BytesMut},
    extensions::ExtensionsRef,
    io::Io,
};
use rama_icap::{
    client::{ClientConnection, ClientResponse, PreviewOutcome, WriteOutcome},
    codec::{HeadParserConfig, Header, HeaderSlot, InterimServiceTag, RequestLine},
    io::{BodyEnd, ConnectionOptions},
    message::{EncapsulatedParts, Request},
    proto::{EncapsulatedKind, Method, Preview, StatusCode},
};
use tokio::net::TcpStream;

#[cfg(feature = "http")]
use rama_http_types::{
    Body, Request as HttpRequest, Response as HttpResponse,
    body::{Frame, util::BodyExt as _},
};
#[cfg(feature = "http")]
use rama_icap::http::{
    ClientRequest as HttpClientRequest, Encapsulated as HttpEncapsulated,
    layer::{AdaptationLayer, ReqmodResult, RespmodResult, ServiceEndpoint},
};
#[cfg(feature = "http")]
use rama_net::client::{
    ConnectRequest, ConnectionError, ConnectionErrorKind, EstablishedClientConnection,
};

fn oracle_addr(name: &str) -> Option<SocketAddr> {
    env::var(name).ok().map(|value| value.parse().unwrap())
}

fn c_icap_connection(stream: TcpStream) -> ClientConnection<ServiceInput<TcpStream>> {
    let head = HeadParserConfig::new().with_interim_service_tag(InterimServiceTag::AllowMissing);
    ClientConnection::with_options(
        ServiceInput::new(stream),
        ConnectionOptions::new().with_head_parser(head),
    )
}

fn request(
    method: Method<'_>,
    service: &str,
    parts: EncapsulatedParts,
    preview: Option<u64>,
) -> Request {
    let uri = format!("icap://127.0.0.1/{service}");
    let line = RequestLine::new(method, &uri).unwrap();
    let headers = [
        Header::new("Host", b"127.0.0.1").unwrap(),
        Header::new("Allow", b"204, 206").unwrap(),
    ];
    if let Some(preview) = preview {
        Request::with_preview(line, &headers, parts, Preview::new(preview)).unwrap()
    } else {
        Request::new(line, &headers, Some(parts)).unwrap()
    }
}

async fn collect<IO>(response: &mut ClientResponse<'_, IO>) -> Bytes
where
    IO: Io + Unpin + ExtensionsRef,
{
    let mut bytes = BytesMut::new();
    while let Some(data) = response.next_data().await.unwrap() {
        bytes.extend_from_slice(&data);
    }
    bytes.freeze()
}

#[tokio::test]
#[ignore = "requires the pinned c-icap Docker oracle"]
async fn rama_client_queries_c_icap_options() {
    let Some(addr) = oracle_addr("RAMA_ICAP_ORACLE_ECHO_ADDR") else {
        return;
    };
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let request = request(Method::Options, "echo", EncapsulatedParts::null(), None);
    let response = connection
        .start(request)
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    assert_eq!(response.response().status(), StatusCode::OK);
    let mut slots = [HeaderSlot::EMPTY; 32];
    let head = response.response().parse_head(&mut slots).unwrap();
    assert!(head.header("Methods").is_some());
    assert!(head.header("ISTag").is_some());
    assert!(head.preview().is_some());
}

#[tokio::test]
#[ignore = "requires the pinned c-icap Docker oracle"]
async fn rama_client_exercises_c_icap_preview_paths() {
    let Some(addr) = oracle_addr("RAMA_ICAP_ORACLE_ECHO_ADDR") else {
        return;
    };

    let small = Bytes::from_static(b"small rama preview body\n");
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let mut transaction = connection
        .start(request(
            Method::Reqmod,
            "echo",
            EncapsulatedParts::new(
                Some(Bytes::from_static(
                    b"POST /resource HTTP/1.1\r\nHost: example.test\r\n\r\n",
                )),
                None,
                EncapsulatedKind::RequestBody,
            )
            .unwrap(),
            Some(1024),
        ))
        .await
        .unwrap();
    assert_eq!(
        transaction.write_data(&small).await.unwrap(),
        WriteOutcome::Written
    );
    let PreviewOutcome::Response(mut response) = transaction.finish_preview(true).await.unwrap()
    else {
        panic!("c-icap requested more data after ieof");
    };
    assert_eq!(response.response().status(), StatusCode::OK);
    assert_eq!(collect(&mut response).await, small);

    let large = Bytes::from(vec![b'x'; 2048]);
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let mut transaction = connection
        .start(request(
            Method::Respmod,
            "echo",
            EncapsulatedParts::new(
                Some(Bytes::from_static(
                    b"GET /resource HTTP/1.1\r\nHost: example.test\r\n\r\n",
                )),
                Some(Bytes::from_static(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n",
                )),
                EncapsulatedKind::ResponseBody,
            )
            .unwrap(),
            Some(1024),
        ))
        .await
        .unwrap();
    assert_eq!(
        transaction.write_data(&large[..1024]).await.unwrap(),
        WriteOutcome::Written
    );
    let PreviewOutcome::Continue(mut transaction) =
        transaction.finish_preview(false).await.unwrap()
    else {
        panic!("c-icap should request the remainder");
    };
    assert_eq!(
        transaction.write_data(&large[1024..]).await.unwrap(),
        WriteOutcome::Written
    );
    let mut response = transaction.finish().await.unwrap();
    assert_eq!(response.response().status(), StatusCode::OK);
    assert_eq!(collect(&mut response).await, large);
}

#[tokio::test]
#[ignore = "requires the pinned c-icap Docker oracle"]
async fn rama_client_reconstructs_c_icap_206_responses() {
    const HTML: &[u8] = b"<html><body>rama ICAP oracle</body></html>\n";
    const PREFIX: &[u8] = b"<html>\n<!--A simple comment added by the  ex206 C-ICAP service-->\n\n";
    const PLAIN: &[u8] = b"<body>no html element</body>\n";
    let Some(addr) = oracle_addr("RAMA_ICAP_ORACLE_ECHO_ADDR") else {
        return;
    };

    for (original, expected_prefix, expected_offset, content_length) in
        [(HTML, PREFIX, 6, 104), (PLAIN, &[][..], 0, PLAIN.len())]
    {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut connection = c_icap_connection(stream);
        let parts = EncapsulatedParts::new(
            Some(Bytes::from_static(
                b"GET http://example.test/resource HTTP/1.1\r\n\
                  Host: example.test\r\n\r\n",
            )),
            Some(Bytes::from(format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                original.len()
            ))),
            EncapsulatedKind::ResponseBody,
        )
        .unwrap();
        let mut transaction = connection
            .start(request(
                Method::Respmod,
                "ex206",
                parts,
                Some(original.len() as u64),
            ))
            .await
            .unwrap();
        assert_eq!(
            transaction.write_data(original).await.unwrap(),
            WriteOutcome::Written
        );
        let PreviewOutcome::Response(mut response) =
            transaction.finish_preview(true).await.unwrap()
        else {
            panic!("c-icap should return a final 206 response");
        };
        assert_eq!(response.response().status(), StatusCode::PARTIAL_CONTENT);
        let response_header = response
            .response()
            .encapsulated()
            .and_then(EncapsulatedParts::response_header)
            .unwrap();
        let expected_length = format!("Content-Length: {content_length}");
        assert!(
            response_header
                .windows(expected_length.len())
                .any(|window| window == expected_length.as_bytes())
        );
        let prefix = collect(&mut response).await;
        assert_eq!(prefix, expected_prefix);
        assert_eq!(
            response.body_end(),
            Some(rama_icap::io::BodyEnd::PartialContent {
                use_original_body: expected_offset,
            })
        );
        let mut reconstructed = BytesMut::from(prefix.as_ref());
        reconstructed.extend_from_slice(&original[expected_offset as usize..]);
        if original == HTML {
            let mut expected = BytesMut::from(PREFIX);
            expected.extend_from_slice(&HTML[6..]);
            assert_eq!(reconstructed, expected);
        } else {
            assert_eq!(reconstructed, original);
        }
    }
}

#[tokio::test]
#[ignore = "requires the pinned c-icap Docker oracle"]
async fn rama_client_covers_c_icap_non_preview_and_edge_paths() {
    let Some(addr) = oracle_addr("RAMA_ICAP_ORACLE_ECHO_ADDR") else {
        return;
    };
    let body = Bytes::from_static(b"rama ICAP oracle body\n");

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let null_parts = EncapsulatedParts::new(
        Some(Bytes::from_static(
            b"GET /resource HTTP/1.1\r\nHost: example.test\r\n\r\n",
        )),
        None,
        EncapsulatedKind::NullBody,
    )
    .unwrap();
    let response = connection
        .start(request(Method::Reqmod, "echo", null_parts, None))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    assert_eq!(response.response().status(), StatusCode::OK);

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let transaction = connection
        .start(request(
            Method::Reqmod,
            "echo",
            EncapsulatedParts::new(
                Some(Bytes::from_static(
                    b"POST /resource HTTP/1.1\r\nHost: example.test\r\n\r\n",
                )),
                None,
                EncapsulatedKind::RequestBody,
            )
            .unwrap(),
            Some(0),
        ))
        .await
        .unwrap();
    let PreviewOutcome::Continue(mut transaction) =
        transaction.finish_preview(false).await.unwrap()
    else {
        panic!("c-icap should continue a zero-byte Preview");
    };
    assert_eq!(
        transaction.write_data(&body).await.unwrap(),
        WriteOutcome::Written
    );
    let mut response = transaction.finish().await.unwrap();
    assert_eq!(collect(&mut response).await, body);

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let mut transaction = connection
        .start(request(
            Method::Respmod,
            "echo",
            EncapsulatedParts::new(
                Some(Bytes::from_static(
                    b"GET /resource HTTP/1.1\r\nHost: example.test\r\n\r\n",
                )),
                Some(Bytes::from_static(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\n\r\n",
                )),
                EncapsulatedKind::ResponseBody,
            )
            .unwrap(),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(
        transaction.write_data(&body).await.unwrap(),
        WriteOutcome::Written
    );
    let mut response = transaction.finish().await.unwrap();
    assert_eq!(collect(&mut response).await, body);

    const HTML: &[u8] = b"<html><body>rama ICAP oracle</body></html>\n";
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let line = RequestLine::new(Method::Respmod, "icap://127.0.0.1/ex206").unwrap();
    let parts = EncapsulatedParts::new(
        None,
        Some(Bytes::from_static(
            b"HTTP/1.1 200 OK\r\nContent-Length: 43\r\n\r\n",
        )),
        EncapsulatedKind::ResponseBody,
    )
    .unwrap();
    let request = Request::with_preview(
        line,
        &[Header::new("Host", b"127.0.0.1").unwrap()],
        parts,
        Preview::new(HTML.len() as u64),
    )
    .unwrap();
    let mut transaction = connection.start(request).await.unwrap();
    assert_eq!(
        transaction.write_data(HTML).await.unwrap(),
        WriteOutcome::Written
    );
    let PreviewOutcome::Response(response) = transaction.finish_preview(true).await.unwrap() else {
        panic!("unnegotiated ex206 should fall back to a final response");
    };
    assert_eq!(
        response.response().status(),
        StatusCode::NO_MODIFICATION_NEEDED
    );
}

#[tokio::test]
#[ignore = "requires the pinned c-icap Docker oracle"]
async fn rama_client_accepts_c_icap_204_without_preview() {
    let Some(addr) = oracle_addr("RAMA_ICAP_ORACLE_204_ADDR") else {
        return;
    };
    let body = Bytes::from(vec![b'x'; 128 * 1024]);
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let mut transaction = connection
        .start(request(
            Method::Respmod,
            "echo",
            EncapsulatedParts::new(
                None,
                Some(Bytes::from_static(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 131072\r\n\r\n",
                )),
                EncapsulatedKind::ResponseBody,
            )
            .unwrap(),
            None,
        ))
        .await
        .unwrap();
    let _outcome = transaction.write_data(&body).await.unwrap();
    let response = transaction.finish().await.unwrap();
    assert_eq!(
        response.response().status(),
        StatusCode::NO_MODIFICATION_NEEDED
    );
}

#[tokio::test]
#[ignore = "requires the pinned c-icap Docker oracle"]
async fn rama_client_accepts_c_icap_early_204() {
    let Some(addr) = oracle_addr("RAMA_ICAP_ORACLE_204_ADDR") else {
        return;
    };
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let mut transaction = connection
        .start(request(
            Method::Reqmod,
            "echo",
            EncapsulatedParts::new(
                Some(Bytes::from_static(
                    b"POST /resource HTTP/1.1\r\nHost: example.test\r\n\r\n",
                )),
                None,
                EncapsulatedKind::RequestBody,
            )
            .unwrap(),
            Some(4),
        ))
        .await
        .unwrap();
    assert_eq!(
        transaction.write_data(b"data").await.unwrap(),
        WriteOutcome::Written
    );
    let PreviewOutcome::Response(response) = transaction.finish_preview(false).await.unwrap()
    else {
        panic!("the 204 oracle should return an early response");
    };
    assert_eq!(
        response.response().status(),
        StatusCode::NO_MODIFICATION_NEEDED
    );
}

#[cfg(feature = "http")]
#[tokio::test]
#[ignore = "requires the pinned c-icap Docker oracle"]
async fn typed_client_exercises_c_icap_http_preview_and_trailers() {
    use rama_core::futures::stream;

    let Some(addr) = oracle_addr("RAMA_ICAP_ORACLE_ECHO_ADDR") else {
        return;
    };
    let Some(trailer_addr) = oracle_addr("RAMA_ICAP_ORACLE_204_ADDR") else {
        return;
    };

    let small = Bytes::from_static(b"small typed rama preview body\n");
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let uri = "icap://127.0.0.1/echo";
    let request = HttpRequest::builder()
        .method("POST")
        .uri("/resource")
        .header("Host", "example.test")
        .body(Body::from(small.clone()))
        .unwrap();
    let request = HttpClientRequest::reqmod(
        RequestLine::new(Method::Reqmod, uri).unwrap(),
        &[Header::new("Host", b"127.0.0.1").unwrap()],
        request,
        Some(Preview::new(1024)),
    )
    .unwrap();
    let mut response = connection.send_http(request).await.unwrap();
    assert_eq!(response.icap().status(), StatusCode::OK);
    assert_eq!(
        response
            .encapsulated()
            .and_then(HttpEncapsulated::request)
            .unwrap()
            .uri()
            .as_str(),
        "/resource",
    );
    let mut echoed = BytesMut::new();
    while let Some(data) = response.next_data().await.unwrap() {
        echoed.extend_from_slice(&data);
    }
    assert_eq!(echoed, small);

    let large = Bytes::from(vec![b'x'; 2048]);
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let original_request = HttpRequest::builder()
        .method("GET")
        .uri("/resource")
        .header("Host", "example.test")
        .body(())
        .unwrap();
    let original_response = HttpResponse::builder()
        .status(200)
        .header("Content-Length", large.len())
        .body(Body::from(large.clone()))
        .unwrap();
    let request = HttpClientRequest::respmod(
        RequestLine::new(Method::Respmod, uri).unwrap(),
        &[Header::new("Host", b"127.0.0.1").unwrap()],
        &original_request,
        original_response,
        Some(Preview::new(1024)),
    )
    .unwrap();
    let mut response = connection.send_http(request).await.unwrap();
    let mut echoed = BytesMut::new();
    while let Some(data) = response.next_data().await.unwrap() {
        echoed.extend_from_slice(&data);
    }
    assert_eq!(echoed, large);

    let mut request_trailers = rama_http_types::HeaderMap::new();
    request_trailers.insert("x-rama-oracle", "complete".parse().unwrap());
    let body = Body::from_frame_stream(stream::iter([
        Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(
            b"rama ICAP oracle body\n",
        ))),
        Ok(Frame::trailers(request_trailers)),
    ]));
    // c-icap's echo service starts a body-bearing response before it has
    // consumed HTTP trailers and cannot complete that response after the
    // RFC-permitted client close fallback. Its bodyless 204 service lets the
    // conforming client finish the request and still exercises the C parser.
    let stream = TcpStream::connect(trailer_addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let request = HttpRequest::builder()
        .method("POST")
        .uri("/resource")
        .header("Host", "example.test")
        .header("Transfer-Encoding", "chunked")
        .header("Trailer", "x-rama-oracle")
        .body(body)
        .unwrap();
    let request = HttpClientRequest::reqmod(
        RequestLine::new(Method::Reqmod, uri).unwrap(),
        &[
            Header::new("Host", b"127.0.0.1").unwrap(),
            Header::new("Allow", b"204").unwrap(),
        ],
        request,
        None,
    )
    .unwrap();
    let mut response = connection.send_http(request).await.unwrap();
    assert_eq!(response.icap().status(), StatusCode::NO_MODIFICATION_NEEDED,);
    let mut reconstructed = BytesMut::new();
    let mut saw_trailers = false;
    while let Some(frame) = response.next_frame().await.unwrap() {
        match frame.into_data() {
            Ok(data) => reconstructed.extend_from_slice(&data),
            Err(frame) => {
                let trailers = frame.into_trailers().unwrap();
                assert_eq!(trailers["x-rama-oracle"], "complete");
                saw_trailers = true;
            }
        }
    }
    assert_eq!(reconstructed, b"rama ICAP oracle body\n".as_slice());
    assert!(saw_trailers);
}

#[cfg(feature = "http")]
#[tokio::test]
#[ignore = "requires the pinned c-icap Docker oracle"]
async fn typed_client_exercises_c_icap_204_and_206() {
    let Some(echo_addr) = oracle_addr("RAMA_ICAP_ORACLE_ECHO_ADDR") else {
        return;
    };
    let Some(no_mod_addr) = oracle_addr("RAMA_ICAP_ORACLE_204_ADDR") else {
        return;
    };

    const HTML: &[u8] = b"<html><body>rama ICAP oracle</body></html>\n";
    const PREFIX: &[u8] = b"<html>\n<!--A simple comment added by the  ex206 C-ICAP service-->\n\n";
    let stream = TcpStream::connect(echo_addr).await.unwrap();
    let mut connection = c_icap_connection(stream);
    let request_head = HttpRequest::builder()
        .method("GET")
        .uri("http://example.test/resource")
        .header("Host", "example.test")
        .body(())
        .unwrap();
    let response_head = HttpResponse::builder()
        .status(200)
        .header("Content-Length", HTML.len())
        .body(Body::from(Bytes::from_static(HTML)))
        .unwrap();
    let request = HttpClientRequest::respmod(
        RequestLine::new(Method::Respmod, "icap://127.0.0.1/ex206").unwrap(),
        &[
            Header::new("Host", b"127.0.0.1").unwrap(),
            Header::new("Allow", b"204, 206").unwrap(),
        ],
        &request_head,
        response_head,
        Some(Preview::new(HTML.len() as u64)),
    )
    .unwrap();
    let mut response = connection.send_http(request).await.unwrap();
    assert_eq!(response.icap().status(), StatusCode::PARTIAL_CONTENT);
    let mut reconstructed = BytesMut::new();
    while let Some(data) = response.next_data().await.unwrap() {
        reconstructed.extend_from_slice(&data);
    }
    let mut expected = BytesMut::from(PREFIX);
    expected.extend_from_slice(&HTML[6..]);
    assert_eq!(reconstructed, expected);
    assert_eq!(
        response.body_end(),
        Some(BodyEnd::PartialContent {
            use_original_body: 6,
        }),
    );
    assert_eq!(response.original_body_offset_is_verified(), Some(true));

    for preview in [Some(4), None] {
        let stream = TcpStream::connect(no_mod_addr).await.unwrap();
        let mut connection = c_icap_connection(stream);
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/resource")
            .header("Host", "example.test")
            .body(Body::from(Bytes::from(vec![b'x'; 128 * 1024])))
            .unwrap();
        let request = HttpClientRequest::reqmod(
            RequestLine::new(Method::Reqmod, "icap://127.0.0.1/echo").unwrap(),
            &[
                Header::new("Host", b"127.0.0.1").unwrap(),
                Header::new("Allow", b"204").unwrap(),
            ],
            request,
            preview.map(Preview::new),
        )
        .unwrap();
        let mut response = connection.send_http(request).await.unwrap();
        assert_eq!(response.icap().status(), StatusCode::NO_MODIFICATION_NEEDED,);
        let mut reconstructed = BytesMut::new();
        while let Some(data) = response.next_data().await.unwrap() {
            reconstructed.extend_from_slice(&data);
        }
        assert_eq!(reconstructed, vec![b'x'; 128 * 1024]);
    }
}

#[cfg(feature = "http")]
#[tokio::test]
#[ignore = "requires the pinned c-icap Docker oracle"]
async fn http_layer_detours_through_c_icap() {
    let Some(echo_addr) = oracle_addr("RAMA_ICAP_ORACLE_ECHO_ADDR") else {
        return;
    };
    let connector = service_fn(async |input: ConnectRequest| {
        let stream = TcpStream::connect(input.authority.to_string())
            .await
            .map_err(|error| ConnectionError::transport(error, ConnectionErrorKind::Unavailable))?;
        Ok::<_, ConnectionError>(EstablishedClientConnection {
            input,
            conn: c_icap_connection(stream),
        })
    });
    let endpoint = ServiceEndpoint::new(format!("icap://{echo_addr}/echo"))
        .unwrap()
        .with_preview(Preview::new(4));
    let inner = service_fn(async |request: HttpRequest<Body>| {
        assert!(request.extensions().contains::<ReqmodResult>());
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "layer request",
        );
        Ok::<_, std::convert::Infallible>(
            HttpResponse::builder()
                .status(202)
                .header("x-origin", "rama")
                .body(Body::from("layer response"))
                .unwrap(),
        )
    });
    let service = AdaptationLayer::new(connector)
        .with_request_service(endpoint.clone())
        .with_response_service(endpoint)
        .layer(inner);
    let response = service
        .serve(
            HttpRequest::builder()
                .method("POST")
                .uri("/layer")
                .header("Host", "example.test")
                .body(Body::from("layer request"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 202);
    assert_eq!(response.headers()["x-origin"], "rama");
    assert!(response.extensions().contains::<ReqmodResult>());
    assert!(response.extensions().contains::<RespmodResult>());
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "layer response",
    );
}
