//! A response carrying [`ResetStream`] resets its h2 stream with that
//! reason (the connection stays usable); h1 sends the response as is.

#![expect(clippy::unwrap_used, reason = "test fixtures")]

use rama_core::extensions::ExtensionsRef as _;
use rama_core::{ServiceInput, rt::Executor, service::service_fn};
use rama_http::{Body, Request, Response, StatusCode, Version};
use rama_http_core::{
    client::conn,
    h2::{Reason, client as h2_client},
    server,
    service::RamaHttpService,
};
use rama_http_types::proto::h2::ext::ResetStream;
use std::{convert::Infallible, time::Duration};
use tokio::time::timeout;

const REFUSE_HEADER: &str = "x-refuse";

async fn handler(req: Request) -> Result<Response, Infallible> {
    let refuse = req.headers().contains_key(REFUSE_HEADER);
    let resp = Response::builder()
        .status(if refuse {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::OK
        })
        .body(Body::empty())
        .unwrap();
    if refuse {
        resp.extensions()
            .insert(ResetStream(Reason::REFUSED_STREAM));
    }
    Ok(resp)
}

#[tokio::test]
async fn h2_server_resets_stream_with_requested_reason() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(
        server::conn::http2::Builder::new(Executor::new()).serve_connection(
            ServiceInput::new(server_io),
            RamaHttpService::new(service_fn(handler)),
        ),
    );
    let (client, conn) = h2_client::handshake(ServiceInput::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn);

    let send = |refuse: bool| {
        let client = client.clone();
        let mut req = rama_http_types::Request::builder()
            .uri("http://example.test/")
            .version(Version::HTTP_2);
        if refuse {
            req = req.header(REFUSE_HEADER, "1");
        }
        let req = req.body(()).unwrap();
        async move {
            let mut client = client.ready().await.unwrap();
            let (resp, _) = client.send_request(req, true).unwrap();
            timeout(Duration::from_secs(5), resp).await.unwrap()
        }
    };

    let err = send(true).await.expect_err("stream must be reset");
    assert_eq!(err.reason(), Some(Reason::REFUSED_STREAM), "got: {err:?}");

    let ok = send(false).await.expect("connection must stay usable");
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn h1_server_sends_response_carrying_reset_stream() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(server::conn::http1::Builder::new().serve_connection(
        ServiceInput::new(server_io),
        RamaHttpService::new(service_fn(handler)),
    ));
    let (mut sender, conn) = conn::http1::handshake(ServiceInput::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn);

    let req = Request::builder()
        .uri("/")
        .header("host", "example.test")
        .header(REFUSE_HEADER, "1")
        .body(Body::empty())
        .unwrap();
    let resp = timeout(Duration::from_secs(5), sender.send_request(req))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}
