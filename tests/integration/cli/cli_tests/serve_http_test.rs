use std::{io::Write as _, sync::Arc};

use rama::{
    Layer as _, Service,
    error::OpaqueError,
    futures::StreamExt as _,
    http::{
        Body, BodyExtractExt, Method, Request, Response, StatusCode, Version,
        client::EasyHttpWebClient,
        header::{ACCEPT_ENCODING, CONTENT_ENCODING},
        headers::{ContentLength, HeaderMapExt, encoding::AcceptEncoding},
        layer::decompression::DecompressionLayer,
        service::client::HttpClientExt,
    },
    net::tls::client::ServerVerifyMode,
    rt::Executor,
    service::BoxService,
    tls::boring::client::TlsConnectorDataBuilder,
};

use super::utils;
use flate2::{Compression, write::GzEncoder};

#[ignore]
#[tokio::test]
async fn test_http_tests() {
    utils::init_tracing();
    let _guard = utils::RamaService::serve_http_test(63133, false);
    run_http_tests("http://127.0.0.1:63133").await;
}

#[ignore]
#[tokio::test]
async fn test_http_tests_over_tls() {
    utils::init_tracing();
    let _guard = utils::RamaService::serve_http_test(63134, true);
    run_http_tests("https://127.0.0.1:63134").await;
}

async fn run_http_tests(base_uri: &'static str) {
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(Some(Arc::new(
            TlsConnectorDataBuilder::new_http_auto()
                .with_server_verify_mode(ServerVerifyMode::Disable),
        )))
        .with_default_http_connector(Executor::default())
        .build_client()
        .boxed();

    for http_version in [Version::HTTP_10, Version::HTTP_11, Version::HTTP_2] {
        run_http_test_endpoint_method(client.clone(), base_uri, http_version).await;
        run_http_test_endpoint_request_compression(client.clone(), base_uri, http_version).await;
        run_http_test_endpoint_response_compression(client.clone(), base_uri, http_version).await;
        run_http_test_endpoint_response_stream(client.clone(), base_uri, http_version).await;
        run_http_test_endpoint_response_stream_compression(client.clone(), base_uri, http_version)
            .await;
        run_http_test_endpoint_sse(client.clone(), base_uri, http_version).await;
    }
}

async fn run_http_test_endpoint_method(
    client: BoxService<Request, Response, OpaqueError>,
    base_uri: &'static str,
    http_version: Version,
) {
    for method in [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::TRACE,
        Method::DELETE,
        Method::PATCH,
        Method::from_bytes(b"COFFEE").unwrap(),
    ] {
        let resp = client
            .request(method.clone(), format!("{base_uri}/method"))
            .version(http_version)
            .send()
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, resp.status());
        let ContentLength(content_length) = resp.headers().typed_get().unwrap();
        let expected_payload = method.to_string();
        assert_eq!(expected_payload.len(), content_length as usize);
        assert_eq!(expected_payload, resp.try_into_string().await.unwrap());
    }
    assert!(
        client
            .connect(format!("{base_uri}/method"))
            .version(http_version)
            .send()
            .await
            .unwrap()
            .status()
            .is_client_error()
    );
}

async fn run_http_test_endpoint_request_compression(
    client: BoxService<Request, Response, OpaqueError>,
    base_uri: &'static str,
    http_version: Version,
) {
    for method in [Method::POST, Method::PUT, Method::PATCH] {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"Hello?").unwrap();
        let body = encoder.finish().unwrap();
        let req = Request::builder()
            .uri(format!("{base_uri}/request-compression"))
            .version(http_version)
            .method(method)
            .header(CONTENT_ENCODING, "gzip")
            .body(Body::from(body))
            .unwrap();

        let resp = client.serve(req).await.unwrap();

        assert_eq!(StatusCode::OK, resp.status());
        let ContentLength(content_length) = resp.headers().typed_get().unwrap();
        assert_eq!(6, content_length);
        assert_eq!("Hello?", resp.try_into_string().await.unwrap());
    }
}

async fn run_http_test_endpoint_response_compression(
    client: BoxService<Request, Response, OpaqueError>,
    base_uri: &'static str,
    http_version: Version,
) {
    let client = DecompressionLayer::new().into_layer(client);

    for maybe_accept_encoding in [
        None,
        Some(AcceptEncoding::new_deflate()),
        Some(AcceptEncoding::new_deflate().with_br(true)),
        Some(AcceptEncoding::new_gzip()),
        Some(AcceptEncoding::new_zstd()),
        Some(AcceptEncoding::new_zstd().with_gzip(true)),
        Some(AcceptEncoding::new_br()),
        Some(AcceptEncoding::default()),
    ] {
        let req = client
            .get(format!("{base_uri}/response-compression"))
            .version(http_version);

        let req = if let Some(accept_encoding) =
            maybe_accept_encoding.and_then(|ae| ae.maybe_to_header_value())
        {
            req.header(ACCEPT_ENCODING, accept_encoding)
        } else {
            req
        };

        let resp = req.send().await.unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        let payload = resp.try_into_string().await.unwrap();
        assert!(payload.starts_with("# Ethical principles of hacking"));
        assert!(payload.contains("All information should be free"));
        assert!(payload.ends_with(
            "the Chaos Computer Club (CCC).
"
        ));
    }
}

async fn run_http_test_endpoint_response_stream(
    client: BoxService<Request, Response, OpaqueError>,
    base_uri: &'static str,
    http_version: Version,
) {
    let resp = client
        .get(format!("{base_uri}/response-stream"))
        .version(http_version)
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    assert!(!resp.headers().contains_key("content-length"));

    let payload = resp.try_into_string().await.unwrap();
    assert!(payload.contains("<title>Chunked transfer encoding test</title>"));
    assert!(payload.contains("This is a chunked response after 100 ms"));
    assert!(payload.contains("all chunks are sent to a client.</h5></body></html>"));
}

async fn run_http_test_endpoint_response_stream_compression(
    client: BoxService<Request, Response, OpaqueError>,
    base_uri: &'static str,
    http_version: Version,
) {
    let client = DecompressionLayer::new().into_layer(client);

    for maybe_accept_encoding in [
        None,
        Some(AcceptEncoding::new_deflate()),
        Some(AcceptEncoding::new_deflate().with_br(true)),
        Some(AcceptEncoding::new_gzip()),
        Some(AcceptEncoding::new_zstd()),
        Some(AcceptEncoding::new_zstd().with_gzip(true)),
        Some(AcceptEncoding::new_br()),
        Some(AcceptEncoding::default()),
    ] {
        let req = client
            .get(format!("{base_uri}/response-stream-compression"))
            .version(http_version);

        let req = if let Some(accept_encoding) =
            maybe_accept_encoding.and_then(|ae| ae.maybe_to_header_value())
        {
            req.header(ACCEPT_ENCODING, accept_encoding)
        } else {
            req
        };

        let resp = req.send().await.unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        assert!(!resp.headers().contains_key("content-length"));

        let payload = resp.try_into_string().await.unwrap_or_else(|err| {
            panic!("decompression faile for {maybe_accept_encoding:?}: {err}")
        });

        assert!(payload.contains("<title>Chunked transfer encoding test</title>"));
        assert!(payload.contains("This is a chunked response after 100 ms"));
        assert!(payload.contains("all chunks are sent to a client.</h5></body></html>"));
    }
}

async fn run_http_test_endpoint_sse(
    client: BoxService<Request, Response, OpaqueError>,
    base_uri: &'static str,
    http_version: Version,
) {
    let resp = client
        .get(format!("{base_uri}/sse"))
        .version(http_version)
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let mut stream = resp.into_body().into_string_data_event_stream();

    for expected_event in [
        "Wake up slowly, enjoy morning light",
        "Make loose plans, feel excited",
        "Do one thing, celebrate it",
        "Go to bed, feeling okay",
    ] {
        let event = stream.next().await.unwrap().unwrap();
        let data = event.into_data().unwrap();
        assert_eq!(expected_event, data);
    }

    assert!(stream.next().await.is_none());
}
