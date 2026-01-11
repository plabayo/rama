use std::sync::{
    Arc,
    atomic::{self, AtomicUsize},
};

use crate::tests::compression::{
    SomeData, Svc, UNCOMPRESSED_MIN_BODY_SIZE, test_client, test_server,
    util::{self, mock_io_client},
};

use rama::{
    Layer as _,
    http::{
        Uri,
        grpc::{Streaming, codec::CompressionEncoding},
        layer::map_response_body::MapResponseBodyLayer,
        server::HttpServer,
    },
    rt::Executor,
    stream::StreamExt as _,
};

util::parametrized_tests! {
    client_enabled_server_enabled,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn client_enabled_server_enabled(encoding: CompressionEncoding) {
    let svc = test_server::TestServer::new(Svc::default()).with_send_compressed(encoding);

    let response_bytes_counter = Arc::new(AtomicUsize::new(0));

    let server = {
        let response_bytes_counter = response_bytes_counter.clone();
        let grpc_svc = MapResponseBodyLayer::new(move |body| util::CountBytesBody {
            inner: body,
            counter: response_bytes_counter.clone(),
        })
        .into_layer(svc);

        HttpServer::h2(Executor::default()).service(grpc_svc)
    };

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_accept_compressed(encoding);

    let res = client.compress_output_server_stream(()).await.unwrap();

    let expected = match encoding {
        CompressionEncoding::Gzip => "gzip",
        CompressionEncoding::Zstd => "zstd",
        CompressionEncoding::Deflate => "deflate",
        _ => panic!("unexpected encoding {encoding:?}"),
    };
    assert_eq!(res.metadata().get("grpc-encoding").unwrap(), expected);

    let mut stream: Streaming<SomeData> = res.into_inner();

    stream
        .next()
        .await
        .expect("stream empty")
        .expect("item was error");
    assert!(response_bytes_counter.load(atomic::Ordering::SeqCst) < UNCOMPRESSED_MIN_BODY_SIZE);

    stream
        .next()
        .await
        .expect("stream empty")
        .expect("item was error");
    assert!(response_bytes_counter.load(atomic::Ordering::SeqCst) < UNCOMPRESSED_MIN_BODY_SIZE);
}

util::parametrized_tests! {
    client_disabled_server_enabled,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
}

async fn client_disabled_server_enabled(encoding: CompressionEncoding) {
    let svc = test_server::TestServer::new(Svc::default()).with_send_compressed(encoding);

    let response_bytes_counter = Arc::new(AtomicUsize::new(0));

    let server = {
        let response_bytes_counter = response_bytes_counter.clone();
        let grpc_svc = MapResponseBodyLayer::new(move |body| util::CountBytesBody {
            inner: body,
            counter: response_bytes_counter.clone(),
        })
        .into_layer(svc);

        HttpServer::auto(Executor::default()).service(grpc_svc)
    };

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    );

    let res = client.compress_output_server_stream(()).await.unwrap();

    assert!(res.metadata().get("grpc-encoding").is_none());

    let mut stream: Streaming<SomeData> = res.into_inner();

    stream
        .next()
        .await
        .expect("stream empty")
        .expect("item was error");
    assert!(response_bytes_counter.load(atomic::Ordering::SeqCst) > UNCOMPRESSED_MIN_BODY_SIZE);
}

util::parametrized_tests! {
    client_enabled_server_disabled,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn client_enabled_server_disabled(encoding: CompressionEncoding) {
    let svc = test_server::TestServer::new(Svc::default());

    let response_bytes_counter = Arc::new(AtomicUsize::new(0));

    let server = {
        let response_bytes_counter = response_bytes_counter.clone();
        let grpc_svc = MapResponseBodyLayer::new(move |body| util::CountBytesBody {
            inner: body,
            counter: response_bytes_counter.clone(),
        })
        .into_layer(svc);

        HttpServer::auto(Executor::default()).service(grpc_svc)
    };

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_accept_compressed(encoding);

    let res = client.compress_output_server_stream(()).await.unwrap();

    assert!(res.metadata().get("grpc-encoding").is_none());

    let mut stream: Streaming<SomeData> = res.into_inner();

    stream
        .next()
        .await
        .expect("stream empty")
        .expect("item was error");
    assert!(response_bytes_counter.load(atomic::Ordering::SeqCst) > UNCOMPRESSED_MIN_BODY_SIZE);
}
