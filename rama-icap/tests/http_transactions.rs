#![cfg(feature = "http")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rama_core::{
    ServiceInput,
    bytes::{Bytes, BytesMut},
    extensions::{Extension, ExtensionsRef as _},
    futures::{StreamExt as _, stream},
};
use rama_http_types::{
    Body, Request as HttpRequest,
    body::{Frame, util::BodyExt as _},
};
use rama_icap::{
    client::ClientConnection,
    codec::{Header, RequestLine, ResponseLine},
    http::{ClientRequest, Encapsulated, ErrorKind, ReplayLimits},
    io::BodyEnd,
    message::{EncapsulatedParts, Response, TrailerBlock},
    proto::{EncapsulatedKind, Method, MethodKind, Preview, StatusCode},
    server::ServerConnection,
};
use rama_net::conn::{ConnectionHealth, ConnectionHealthWatcher};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::Notify,
    time::timeout,
};

#[derive(Debug, Extension)]
struct OriginalMarker;

#[derive(Debug, Extension)]
struct IcapTransportMarker;

#[derive(Debug, Extension)]
struct IcapResponseMarker;

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn request_line(method: Method<'static>, service: &str) -> RequestLine<'static> {
    let uri = match service {
        "echo" => "icap://icap.test/echo",
        "early" => "icap://icap.test/early",
        "partial" => "icap://icap.test/partial",
        _ => panic!("unknown test service"),
    };
    RequestLine::new(method, uri).unwrap()
}

fn response(method: MethodKind, status: StatusCode, parts: Option<EncapsulatedParts>) -> Response {
    let istag = Header::new("ISTag", b"\"rama-http-test\"").unwrap();
    Response::new(
        method,
        ResponseLine::new(
            status,
            match status {
                StatusCode::OK => b"OK",
                StatusCode::NO_MODIFICATION_NEEDED => b"No Modification Needed",
                StatusCode::PARTIAL_CONTENT => b"Partial Content",
                _ => b"Test",
            },
        )
        .unwrap(),
        &[istag],
        parts,
    )
    .unwrap()
}

#[tokio::test]
async fn typed_client_streams_preview_data_and_trailers() {
    let (client_io, server_io) = tokio::io::duplex(128);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        let parts = transaction.request().encapsulated().unwrap().clone();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "hell");
        assert!(transaction.next_data().await.unwrap().is_none());
        assert_eq!(transaction.body_end(), Some(BodyEnd::Preview));
        transaction
            .continue_preview(response(MethodKind::Reqmod, StatusCode::CONTINUE, None))
            .await
            .unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "o world");
        assert!(transaction.next_data().await.unwrap().is_none());
        assert_eq!(
            transaction.trailers().unwrap().as_bytes().as_ref(),
            b"x-request-end: yes\r\n\r\n",
        );

        let mut writer = transaction
            .respond(response(MethodKind::Reqmod, StatusCode::OK, Some(parts)))
            .await
            .unwrap();
        writer.write_data(b"adapted").await.unwrap();
        writer
            .finish_with_trailers(
                &TrailerBlock::from_bytes(Bytes::from_static(b"X-Response-End: yes\r\n\r\n"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(connection.is_reusable());
    };

    let client = async move {
        let mut request_trailers = rama_http_types::HeaderMap::new();
        request_trailers.insert("x-request-end", "yes".parse().unwrap());
        let body = Body::from_frame_stream(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello world"))),
            Ok(Frame::trailers(request_trailers)),
        ]));
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/scan")
            .header("Host", "example.test")
            .body(body)
            .unwrap();
        request.extensions().insert(OriginalMarker);
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "echo"),
            &[Header::new("Host", b"icap.test").unwrap()],
            request,
            Some(Preview::new(4)),
        )
        .unwrap();
        let io = ServiceInput::new(client_io);
        io.extensions().insert(IcapTransportMarker);
        let mut connection = ClientConnection::new(io);
        let mut response = connection.send_http(request).await.unwrap();

        assert_eq!(response.icap().status(), StatusCode::OK);
        let adapted = response.request().unwrap();
        assert!(adapted.extensions().contains::<OriginalMarker>());
        assert!(!adapted.extensions().contains::<IcapTransportMarker>());
        assert_eq!(
            response
                .encapsulated()
                .and_then(Encapsulated::request)
                .unwrap()
                .uri()
                .as_str(),
            "/scan",
        );
        let Some(frame) = response.next_frame().await.unwrap() else {
            panic!("missing adapted data");
        };
        assert_eq!(frame.into_data().unwrap(), "adapted");
        let Some(frame) = response.next_frame().await.unwrap() else {
            panic!("missing adapted trailers");
        };
        assert_eq!(frame.into_trailers().unwrap()["x-response-end"], "yes");
        assert!(response.next_frame().await.unwrap().is_none());
        assert_eq!(response.body_end(), Some(BodyEnd::Complete));
        drop(response);
        assert!(connection.is_reusable());
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn typed_client_monitors_while_the_http_body_is_idle() {
    let (client_io, server_io) = tokio::io::duplex(64);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let transaction = connection.accept().await.unwrap().unwrap();
        transaction
            .respond_early(response(
                MethodKind::Reqmod,
                StatusCode::NO_MODIFICATION_NEEDED,
                None,
            ))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };

    let client = async move {
        let delayed = stream::once(async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"late")))
        });
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/scan")
            .body(Body::from_frame_stream(delayed))
            .unwrap();
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "early"),
            &[
                Header::new("Host", b"icap.test").unwrap(),
                Header::new("Allow", b"204").unwrap(),
            ],
            request,
            None,
        )
        .unwrap();
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let response = timeout(Duration::from_secs(1), connection.send_http(request))
            .await
            .expect("client did not monitor the early response")
            .unwrap();
        assert_eq!(response.icap().status(), StatusCode::NO_MODIFICATION_NEEDED,);
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn typed_client_finishes_preview_before_pending_source() {
    for preview in [0, 4] {
        let (client_io, server_io) = tokio::io::duplex(128);
        let server = async move {
            let mut connection = ServerConnection::new(ServiceInput::new(server_io));
            let mut transaction = connection.accept().await.unwrap().unwrap();
            if preview == 4 {
                assert_eq!(transaction.next_data().await.unwrap().unwrap(), "abcd");
            }
            assert!(transaction.next_data().await.unwrap().is_none());
            transaction
                .respond(response(
                    MethodKind::Reqmod,
                    StatusCode::NO_MODIFICATION_NEEDED,
                    None,
                ))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
        };

        let client = async move {
            let source = stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                b"abcd",
            )))])
            .chain(stream::pending());
            let request = HttpRequest::builder()
                .method("POST")
                .uri("/original")
                .body(Body::from_frame_stream(source))
                .unwrap();
            let request = ClientRequest::reqmod(
                request_line(Method::Reqmod, "early"),
                &[Header::new("Host", b"icap.test").unwrap()],
                request,
                Some(Preview::new(preview)),
            )
            .unwrap();
            let mut connection = ClientConnection::new(ServiceInput::new(client_io));
            let response = timeout(Duration::from_secs(1), connection.send_http(request))
                .await
                .expect("client waited for source data beyond the Preview limit")
                .unwrap();
            assert_eq!(response.icap().status(), StatusCode::NO_MODIFICATION_NEEDED);
        };

        tokio::join!(server, client);
    }
}

#[tokio::test]
async fn typed_client_reconstructs_preview_204() {
    let (client_io, server_io) = tokio::io::duplex(128);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "hell");
        assert!(transaction.next_data().await.unwrap().is_none());
        transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::NO_MODIFICATION_NEEDED,
                None,
            ))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };

    let client = async move {
        let body = Body::from_frame_stream(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello"))),
            Ok(Frame::data(Bytes::from_static(b" world"))),
        ]));
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/original")
            .body(body)
            .unwrap();
        request.extensions().insert(OriginalMarker);
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "early"),
            &[Header::new("Host", b"icap.test").unwrap()],
            request,
            Some(Preview::new(4)),
        )
        .unwrap();
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = connection.send_http(request).await.unwrap();
        assert_eq!(response.request().unwrap().uri().as_str(), "/original");
        assert!(
            response
                .request()
                .unwrap()
                .extensions()
                .contains::<OriginalMarker>()
        );
        let mut output = BytesMut::new();
        while let Some(data) = response.next_data().await.unwrap() {
            output.extend_from_slice(&data);
        }
        assert_eq!(output, b"hello world".as_slice());
        drop(response);
        assert!(connection.is_reusable());
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn typed_client_reconstructs_whole_message_204() {
    let (client_io, server_io) = tokio::io::duplex(128);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        let mut original = BytesMut::new();
        while let Some(data) = transaction.next_data().await.unwrap() {
            original.extend_from_slice(&data);
        }
        assert_eq!(original, b"complete".as_slice());
        transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::NO_MODIFICATION_NEEDED,
                None,
            ))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };

    let client = async move {
        let body = Body::from_stream(stream::unfold(false, |sent| async move {
            (!sent).then_some((Ok::<_, Infallible>(Bytes::from_static(b"complete")), true))
        }));
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/original")
            .body(body)
            .unwrap();
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "early"),
            &[
                Header::new("Host", b"icap.test").unwrap(),
                Header::new("Allow", b"204").unwrap(),
            ],
            request,
            None,
        )
        .unwrap();
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = connection.send_http(request).await.unwrap();
        assert_eq!(response.next_data().await.unwrap().unwrap(), "complete");
        assert!(response.next_data().await.unwrap().is_none());
        drop(response);
        assert!(connection.is_reusable());
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn typed_client_enforces_replay_byte_and_frame_bounds() {
    let (client_io, _server_io) = tokio::io::duplex(4096);
    let request = HttpRequest::builder()
        .method("POST")
        .uri("/known")
        .body(Body::from("four"))
        .unwrap();
    let request = ClientRequest::reqmod(
        request_line(Method::Reqmod, "early"),
        &[
            Header::new("Host", b"icap.test").unwrap(),
            Header::new("Allow", b"204").unwrap(),
        ],
        request,
        None,
    )
    .unwrap()
    .with_replay_limits(ReplayLimits::new().with_max_bytes(3));
    let mut connection = ClientConnection::new(ServiceInput::new(client_io));
    let Err(error) = connection.send_http(request).await else {
        panic!("known oversized replay body was accepted");
    };
    assert_eq!(error.kind(), ErrorKind::ReplayLimitExceeded);
    assert!(connection.is_reusable());

    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "x");
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "x");
        assert!(transaction.next_data().await.unwrap().is_none());
        transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::NO_MODIFICATION_NEEDED,
                None,
            ))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };
    let client = async move {
        let body = Body::from_stream(stream::iter([
            Ok::<_, Infallible>(Bytes::from_static(b"x")),
            Ok::<_, Infallible>(Bytes::from_static(b"x")),
        ]));
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/exact")
            .body(body)
            .unwrap();
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "early"),
            &[
                Header::new("Host", b"icap.test").unwrap(),
                Header::new("Allow", b"204").unwrap(),
            ],
            request,
            None,
        )
        .unwrap()
        .with_replay_limits(ReplayLimits::new().with_max_bytes(2).with_max_frames(2));
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = connection.send_http(request).await.unwrap();
        assert_eq!(response.next_data().await.unwrap().unwrap(), "x");
        assert_eq!(response.next_data().await.unwrap().unwrap(), "x");
        assert!(response.next_data().await.unwrap().is_none());
    };
    tokio::join!(server, client);

    let (client_io, _server_io) = tokio::io::duplex(4096);
    let body = Body::from_stream(stream::unfold(0_u8, |index| async move {
        (index < 2).then_some((Ok::<_, Infallible>(Bytes::from_static(b"x")), index + 1))
    }));
    let request = HttpRequest::builder()
        .method("POST")
        .uri("/fragmented")
        .body(body)
        .unwrap();
    let request = ClientRequest::reqmod(
        request_line(Method::Reqmod, "early"),
        &[
            Header::new("Host", b"icap.test").unwrap(),
            Header::new("Allow", b"204").unwrap(),
        ],
        request,
        None,
    )
    .unwrap()
    .with_replay_limits(ReplayLimits::new().with_max_frames(1));
    let mut connection = ClientConnection::new(ServiceInput::new(client_io));
    let Err(error) = connection.send_http(request).await else {
        panic!("over-fragmented replay body was accepted");
    };
    assert_eq!(error.kind(), ErrorKind::ReplayLimitExceeded);
    assert!(!connection.is_reusable());
}

#[tokio::test]
async fn exact_preview_fill_reports_complete_body() {
    let (client_io, server_io) = tokio::io::duplex(128);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "abc");
        assert!(transaction.next_data().await.unwrap().is_none());
        assert_eq!(transaction.body_end(), Some(BodyEnd::Complete));
        transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::NO_MODIFICATION_NEEDED,
                None,
            ))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };

    let client = async move {
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/original")
            .body(Body::from("abc"))
            .unwrap();
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "early"),
            &[Header::new("Host", b"icap.test").unwrap()],
            request,
            Some(Preview::new(3)),
        )
        .unwrap();
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = connection.send_http(request).await.unwrap();
        assert_eq!(response.next_data().await.unwrap().unwrap(), "abc");
        assert!(response.next_data().await.unwrap().is_none());
        drop(response);
        assert!(connection.is_reusable());
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn typed_client_streams_a_body_bearing_early_response() {
    let (client_io, server_io) = tokio::io::duplex(64);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let transaction = connection.accept().await.unwrap().unwrap();
        let parts = EncapsulatedParts::new(
            Some(Bytes::from_static(b"GET /adapted HTTP/1.1\r\n\r\n")),
            None,
            EncapsulatedKind::RequestBody,
        )
        .unwrap();
        let mut writer = transaction
            .respond_early(response(MethodKind::Reqmod, StatusCode::OK, Some(parts)))
            .await
            .unwrap();
        writer.write_data(b"early adapted").await.unwrap();
        writer.finish().await.unwrap();
    };

    let client = async move {
        let source_dropped = Arc::new(AtomicBool::new(false));
        let delayed = stream::unfold(DropFlag(Arc::clone(&source_dropped)), |marker| async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Some((
                Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"late"))),
                marker,
            ))
        });
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/scan")
            .body(Body::from_frame_stream(delayed))
            .unwrap();
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "early"),
            &[Header::new("Host", b"icap.test").unwrap()],
            request,
            None,
        )
        .unwrap();
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = timeout(Duration::from_secs(1), connection.send_http(request))
            .await
            .expect("client did not monitor the early response")
            .unwrap();
        assert!(source_dropped.load(Ordering::Relaxed));
        assert_eq!(
            response
                .encapsulated()
                .and_then(Encapsulated::request)
                .unwrap()
                .uri()
                .as_str(),
            "/adapted",
        );
        assert_eq!(
            response.next_data().await.unwrap().unwrap(),
            "early adapted"
        );
        assert!(response.next_data().await.unwrap().is_none());
        drop(response);
        assert!(!connection.is_reusable());
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn typed_client_rejects_non_error_reqmod_response() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        while transaction.next_data().await.unwrap().is_some() {}
        let parts = EncapsulatedParts::new(
            None,
            Some(Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n")),
            EncapsulatedKind::NullBody,
        )
        .unwrap();
        transaction
            .respond(response(MethodKind::Reqmod, StatusCode::OK, Some(parts)))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };

    let client = async move {
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/scan")
            .body(Body::from("original"))
            .unwrap();
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "echo"),
            &[Header::new("Host", b"icap.test").unwrap()],
            request,
            None,
        )
        .unwrap();
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let error = connection.send_http(request).await.unwrap_err();
        assert!(matches!(
            error.kind(),
            rama_icap::http::ErrorKind::InvalidSequence(_)
        ));
        assert!(!connection.is_reusable());
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn reqmod_response_inherits_only_http_request_extensions() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        while transaction.next_data().await.unwrap().is_some() {}
        let parts = EncapsulatedParts::new(
            None,
            Some(Bytes::from_static(b"HTTP/1.1 403 Forbidden\r\n\r\n")),
            EncapsulatedKind::NullBody,
        )
        .unwrap();
        transaction
            .respond(response(MethodKind::Reqmod, StatusCode::OK, Some(parts)))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };

    let client = async move {
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/scan")
            .body(Body::from("original"))
            .unwrap();
        request.extensions().insert(OriginalMarker);
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "echo"),
            &[Header::new("Host", b"icap.test").unwrap()],
            request,
            None,
        )
        .unwrap();
        let io = ServiceInput::new(client_io);
        io.extensions().insert(IcapTransportMarker);
        let mut connection = ClientConnection::new(io);
        let response = connection.send_http(request).await.unwrap();
        let adapted = response.response().unwrap();
        assert!(adapted.extensions().contains::<OriginalMarker>());
        assert!(!adapted.extensions().contains::<IcapTransportMarker>());
        drop(response);
        assert!(connection.is_reusable());
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn typed_client_exposes_verified_partial_completion() {
    let (client_io, server_io) = tokio::io::duplex(128);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "ab");
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "cd");
        assert!(transaction.next_data().await.unwrap().is_none());
        let parts = EncapsulatedParts::new(
            None,
            Some(Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n")),
            EncapsulatedKind::ResponseBody,
        )
        .unwrap();
        let mut writer = transaction
            .respond(response(
                MethodKind::Respmod,
                StatusCode::PARTIAL_CONTENT,
                Some(parts),
            ))
            .await
            .unwrap();
        writer.write_data(b"XY").await.unwrap();
        writer.finish_partial(3).await.unwrap();
    };

    let client = async move {
        let request = HttpRequest::builder()
            .method("GET")
            .uri("/resource")
            .body(())
            .unwrap();
        let original_body = Body::from_frame_stream(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"ab"))),
            Ok(Frame::data(Bytes::from_static(b"cdef"))),
        ]));
        let original = rama_http_types::Response::builder()
            .status(200)
            .body(original_body)
            .unwrap();
        let request = ClientRequest::respmod(
            request_line(Method::Respmod, "partial"),
            &[
                Header::new("Allow", b"204, 206").unwrap(),
                Header::new("Host", b"icap.test").unwrap(),
            ],
            &request,
            original,
            Some(Preview::new(4)),
        )
        .unwrap();
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = connection.send_http(request).await.unwrap();
        let mut data = BytesMut::new();
        while let Some(frame) = response.next_frame().await.unwrap() {
            data.extend_from_slice(&frame.into_data().unwrap());
        }
        assert_eq!(data, b"XYdef".as_slice());
        assert_eq!(
            response.body_end(),
            Some(BodyEnd::PartialContent {
                use_original_body: 3,
            }),
        );
        assert_eq!(response.original_body_offset_is_verified(), Some(true));
        assert_eq!(
            response
                .encapsulated()
                .and_then(Encapsulated::response)
                .unwrap()
                .status(),
            200,
        );
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn typed_client_reports_dynamic_206_verification() {
    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let peer = async move {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n0\r\n\r\n") {
            let mut buf = [0; 512];
            let read = peer_io.read(&mut buf).await.unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buf[..read]);
        }
        let http_head = b"HTTP/1.1 200 OK\r\n\r\n";
        let response = format!(
            "ICAP/1.0 206 Partial Content\r\n\
             ISTag: \"dynamic-offset\"\r\n\
             Encapsulated: res-hdr=0, res-body={}\r\n\r\n",
            http_head.len(),
        );
        peer_io.write_all(response.as_bytes()).await.unwrap();
        peer_io.write_all(http_head).await.unwrap();
        peer_io
            .write_all(b"1\r\nX\r\n0; use-original-body=3\r\n\r\n")
            .await
            .unwrap();
    };

    let client = async move {
        let original_body = Body::from_stream(stream::unfold(0_u8, |index| async move {
            match index {
                0 => Some((Ok::<_, Infallible>(Bytes::from_static(b"abc")), 1)),
                1 => Some((Ok::<_, Infallible>(Bytes::from_static(b"def")), 2)),
                _ => None,
            }
        }));
        let request_head = HttpRequest::builder()
            .method("GET")
            .uri("/resource")
            .body(())
            .unwrap();
        let original = rama_http_types::Response::builder()
            .status(200)
            .body(original_body)
            .unwrap();
        let request = ClientRequest::respmod(
            request_line(Method::Respmod, "partial"),
            &[
                Header::new("Allow", b"206").unwrap(),
                Header::new("Host", b"icap.test").unwrap(),
            ],
            &request_head,
            original,
            Some(Preview::new(3)),
        )
        .unwrap();
        let connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = connection.send_http_owned(request).await.unwrap();
        assert_eq!(response.next_data().await.unwrap().unwrap(), "X");
        assert_eq!(response.original_body_offset_is_verified(), None);
        assert_eq!(response.next_data().await.unwrap().unwrap(), "def");
        assert_eq!(response.original_body_offset_is_verified(), Some(true));
        assert!(response.next_data().await.unwrap().is_none());
    };

    tokio::join!(peer, client);
}

#[tokio::test]
async fn borrowed_206_keeps_transport_healthy_after_local_error() {
    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let peer = async move {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n0\r\n\r\n") {
            let mut buf = [0; 512];
            let read = peer_io.read(&mut buf).await.unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buf[..read]);
        }
        let http_head = b"HTTP/1.1 200 OK\r\n\r\n";
        let response = format!(
            "ICAP/1.0 206 Partial Content\r\n\
             ISTag: \"borrowed-offset\"\r\n\
             Encapsulated: res-hdr=0, res-body={}\r\n\r\n",
            http_head.len(),
        );
        peer_io.write_all(response.as_bytes()).await.unwrap();
        peer_io.write_all(http_head).await.unwrap();
        peer_io
            .write_all(b"1\r\nX\r\n0; use-original-body=3\r\n\r\n")
            .await
            .unwrap();
    };

    let client = async move {
        let original_body = Body::from_stream(stream::iter([
            Ok(Bytes::from_static(b"abc")),
            Ok(Bytes::from_static(b"def")),
            Err(std::io::Error::other("local body failure")),
        ]));
        let request_head = HttpRequest::builder()
            .method("GET")
            .uri("/resource")
            .body(())
            .unwrap();
        let original = rama_http_types::Response::builder()
            .status(200)
            .body(original_body)
            .unwrap();
        let request = ClientRequest::respmod(
            request_line(Method::Respmod, "partial"),
            &[
                Header::new("Allow", b"206").unwrap(),
                Header::new("Host", b"icap.test").unwrap(),
            ],
            &request_head,
            original,
            Some(Preview::new(3)),
        )
        .unwrap();
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = connection.send_http(request).await.unwrap();
        assert_eq!(response.next_data().await.unwrap().unwrap(), "X");
        assert_eq!(response.next_data().await.unwrap().unwrap(), "def");
        assert_eq!(response.original_body_offset_is_verified(), Some(true));
        response.next_data().await.unwrap_err();
        drop(response);
        assert!(connection.is_reusable());
    };

    tokio::join!(peer, client);
}

#[tokio::test]
async fn borrowed_204_keeps_transport_healthy_after_local_error() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "abc");
        assert!(transaction.next_data().await.unwrap().is_none());
        transaction
            .respond(response(
                MethodKind::Reqmod,
                StatusCode::NO_MODIFICATION_NEEDED,
                None,
            ))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };

    let client = async move {
        let body = Body::from_stream(stream::iter([
            Ok(Bytes::from_static(b"abc")),
            Err(std::io::Error::other("local body failure")),
        ]));
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/original")
            .body(body)
            .unwrap();
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "early"),
            &[
                Header::new("Allow", b"204").unwrap(),
                Header::new("Host", b"icap.test").unwrap(),
            ],
            request,
            Some(Preview::new(3)),
        )
        .unwrap();
        let mut connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = connection.send_http(request).await.unwrap();
        assert_eq!(response.next_data().await.unwrap().unwrap(), "abc");
        response.next_data().await.unwrap_err();
        drop(response);
        assert!(connection.is_reusable());
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn typed_client_rejects_unselected_206_original_offset() {
    async fn probe(offset: u64, with_trailers: bool) {
        let (client_io, mut peer_io) = tokio::io::duplex(4096);
        let peer = async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n0\r\n\r\n") && !request.ends_with(b"\r\n0; ieof\r\n\r\n")
            {
                let mut buf = [0; 512];
                let read = peer_io.read(&mut buf).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buf[..read]);
            }

            let http_head = b"HTTP/1.1 200 OK\r\n\r\n";
            let response = format!(
                "ICAP/1.0 206 Partial Content\r\n\
                 ISTag: \"invalid-offset\"\r\n\
                 Encapsulated: res-hdr=0, res-body={}\r\n\r\n",
                http_head.len(),
            );
            peer_io.write_all(response.as_bytes()).await.unwrap();
            peer_io.write_all(http_head).await.unwrap();
            peer_io.write_all(b"1\r\nX\r\n").await.unwrap();
            peer_io
                .write_all(format!("0; use-original-body={offset}\r\n\r\n").as_bytes())
                .await
                .unwrap();
        };

        let client = async move {
            let mut frames = vec![Frame::data(Bytes::from_static(b"abc"))];
            if with_trailers {
                let mut trailers = rama_http_types::HeaderMap::new();
                trailers.insert("x-original", "end".parse().unwrap());
                frames.push(Frame::trailers(trailers));
            }
            let original_body =
                Body::from_frame_stream(stream::iter(frames.into_iter().map(Ok::<_, Infallible>)));
            let request_head = HttpRequest::builder()
                .method("GET")
                .uri("/resource")
                .body(())
                .unwrap();
            let original = rama_http_types::Response::builder()
                .status(200)
                .body(original_body)
                .unwrap();
            let request = ClientRequest::respmod(
                request_line(Method::Respmod, "partial"),
                &[
                    Header::new("Allow", b"204, 206").unwrap(),
                    Header::new("Host", b"icap.test").unwrap(),
                ],
                &request_head,
                original,
                Some(Preview::new(3)),
            )
            .unwrap();
            let mut connection = ClientConnection::new(ServiceInput::new(client_io));
            let mut response = connection.send_http(request).await.unwrap();
            assert_eq!(response.next_data().await.unwrap().unwrap(), "X");
            response.next_frame().await.unwrap_err();
            drop(response);
            assert!(!connection.is_reusable());
        };

        tokio::join!(peer, client);
    }

    for offset in [3, 4] {
        for with_trailers in [false, true] {
            probe(offset, with_trailers).await;
        }
    }
}

async fn owned_response_health_probe(consume: bool, externally_broken: bool) -> ConnectionHealth {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        let parts = transaction.request().encapsulated().unwrap().clone();
        while transaction.next_data().await.unwrap().is_some() {}
        let mut writer = transaction
            .respond(response(MethodKind::Reqmod, StatusCode::OK, Some(parts)))
            .await
            .unwrap();
        writer.write_data(b"adapted").await.unwrap();
        writer.finish().await.unwrap();
    };

    let client = async move {
        let connection = ClientConnection::new(ServiceInput::new(client_io));
        connection.extensions().insert(IcapTransportMarker);
        let extensions = connection.extensions().clone();
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/scan")
            .body(Body::from("original"))
            .unwrap();
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "echo"),
            &[Header::new("Host", b"icap.test").unwrap()],
            request,
            None,
        )
        .unwrap();
        let response = connection.send_http_owned(request).await.unwrap();
        assert_eq!(
            extensions
                .get_ref::<ConnectionHealthWatcher>()
                .unwrap()
                .health(),
            ConnectionHealth::Healthy,
        );
        assert!(response.extensions().contains::<IcapTransportMarker>());
        response.extensions().insert(IcapResponseMarker);
        assert!(!extensions.contains::<IcapResponseMarker>());
        if externally_broken {
            extensions
                .get_ref::<ConnectionHealthWatcher>()
                .unwrap()
                .mark_broken();
        }
        let request = response.into_request().unwrap();
        if consume {
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "adapted",
            );
        } else {
            drop(request);
        }
        extensions
            .get_ref::<ConnectionHealthWatcher>()
            .unwrap()
            .health()
    };

    let ((), health) = tokio::join!(server, client);
    health
}

#[tokio::test]
async fn owned_response_leaves_shared_health_healthy_at_eof() {
    assert_eq!(
        owned_response_health_probe(true, false).await,
        ConnectionHealth::Healthy,
    );
}

#[tokio::test]
async fn owned_response_does_not_overwrite_external_broken_health() {
    assert_eq!(
        owned_response_health_probe(true, true).await,
        ConnectionHealth::Broken,
    );
}

#[tokio::test]
async fn dropped_owned_response_keeps_connection_broken() {
    assert_eq!(
        owned_response_health_probe(false, false).await,
        ConnectionHealth::Broken,
    );
}

#[tokio::test]
async fn owned_response_releases_bodyless_adapted_connection() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let transaction = connection.accept().await.unwrap().unwrap();
        let parts = EncapsulatedParts::new(
            Some(Bytes::from_static(b"GET /adapted HTTP/1.1\r\n\r\n")),
            None,
            EncapsulatedKind::NullBody,
        )
        .unwrap();
        transaction
            .respond(response(MethodKind::Reqmod, StatusCode::OK, Some(parts)))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    };

    let client = async move {
        let connection = ClientConnection::new(ServiceInput::new(client_io));
        let extensions = connection.extensions().clone();
        let request = HttpRequest::builder()
            .method("GET")
            .uri("/original")
            .body(Body::empty())
            .unwrap();
        let request = ClientRequest::reqmod(
            request_line(Method::Reqmod, "echo"),
            &[Header::new("Host", b"icap.test").unwrap()],
            request,
            None,
        )
        .unwrap();
        let response = connection.send_http_owned(request).await.unwrap();
        assert_eq!(
            extensions
                .get_ref::<ConnectionHealthWatcher>()
                .unwrap()
                .health(),
            ConnectionHealth::Healthy,
        );
        let request = response.into_request().unwrap();
        assert_eq!(request.uri().as_str(), "/adapted");
        assert!(
            request
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn owned_response_releases_verified_206_before_replay_end() {
    let (client_io, server_io) = tokio::io::duplex(256);
    let released = Arc::new(Notify::new());
    let server_released = Arc::clone(&released);
    let server = async move {
        let mut connection = ServerConnection::new(ServiceInput::new(server_io));
        let mut transaction = connection.accept().await.unwrap().unwrap();
        assert_eq!(transaction.next_data().await.unwrap().unwrap(), "abcd");
        assert!(transaction.next_data().await.unwrap().is_none());
        let parts = EncapsulatedParts::new(
            None,
            Some(Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n")),
            EncapsulatedKind::ResponseBody,
        )
        .unwrap();
        let mut writer = transaction
            .respond(response(
                MethodKind::Respmod,
                StatusCode::PARTIAL_CONTENT,
                Some(parts),
            ))
            .await
            .unwrap();
        writer.write_data(b"XY").await.unwrap();
        writer.finish_partial(3).await.unwrap();
        assert!(connection.accept().await.unwrap().is_none());
        server_released.notify_one();
    };

    let client = async move {
        let request = HttpRequest::builder()
            .method("GET")
            .uri("/resource")
            .body(())
            .unwrap();
        let original = rama_http_types::Response::builder()
            .status(200)
            .body(Body::from("abcdef"))
            .unwrap();
        let request = ClientRequest::respmod(
            request_line(Method::Respmod, "partial"),
            &[
                Header::new("Allow", b"206").unwrap(),
                Header::new("Host", b"icap.test").unwrap(),
            ],
            &request,
            original,
            Some(Preview::new(4)),
        )
        .unwrap();
        let connection = ClientConnection::new(ServiceInput::new(client_io));
        let mut response = connection.send_http_owned(request).await.unwrap();
        assert_eq!(response.next_data().await.unwrap().unwrap(), "XY");
        assert_eq!(response.next_data().await.unwrap().unwrap(), "def");
        assert_eq!(response.original_body_offset_is_verified(), Some(true));
        timeout(Duration::from_secs(1), released.notified())
            .await
            .expect("verified 206 retained its completed ICAP transport");
        assert!(response.next_data().await.unwrap().is_none());
    };

    tokio::join!(server, client);
}
