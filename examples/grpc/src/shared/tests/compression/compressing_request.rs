use std::sync::{
    Arc,
    atomic::{self, AtomicUsize},
};

use rama::{
    Layer as _,
    http::{
        self, StreamingBody, Uri,
        grpc::{Code, codec::CompressionEncoding},
        server::HttpServer,
    },
    layer::MapInputLayer,
    rt::Executor,
};

use crate::tests::compression::{
    SomeData, Svc, UNCOMPRESSED_MIN_BODY_SIZE, test_client, test_server,
    util::{self, measure_request_body_size_layer, mock_io_client},
};

util::parametrized_tests! {
    client_enabled_server_enabled,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn client_enabled_server_enabled(encoding: CompressionEncoding) {
    let svc = test_server::TestServer::new(Svc::default()).with_accept_compressed(encoding);

    let request_bytes_counter = Arc::new(AtomicUsize::new(0));

    #[derive(Clone)]
    struct AssertRightEncoding {
        encoding: CompressionEncoding,
    }

    impl AssertRightEncoding {
        fn new(encoding: CompressionEncoding) -> Self {
            Self { encoding }
        }

        fn call<B: StreamingBody>(self, req: http::Request<B>) -> http::Request<B> {
            let expected = match self.encoding {
                CompressionEncoding::Gzip => "gzip",
                CompressionEncoding::Zstd => "zstd",
                CompressionEncoding::Deflate => "deflate",
                _ => panic!("unexpected encoding {:?}", self.encoding),
            };
            assert_eq!(req.headers().get("grpc-encoding").unwrap(), expected);

            req
        }
    }

    let server = {
        let request_bytes_counter = request_bytes_counter.clone();
        let grpc_svc = (
            MapInputLayer::new(move |req| AssertRightEncoding::new(encoding).call(req)),
            measure_request_body_size_layer(request_bytes_counter),
        )
            .into_layer(svc);

        HttpServer::auto(Executor::default()).service(grpc_svc)
    };

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_send_compressed(encoding);

    for _ in 0..3 {
        client
            .compress_input_unary(SomeData {
                data: [0_u8; UNCOMPRESSED_MIN_BODY_SIZE].to_vec(),
            })
            .await
            .unwrap();
        let bytes_sent = request_bytes_counter.load(atomic::Ordering::SeqCst);
        assert!(bytes_sent < UNCOMPRESSED_MIN_BODY_SIZE);
    }
}

util::parametrized_tests! {
    client_enabled_server_enabled_multi_encoding,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn client_enabled_server_enabled_multi_encoding(encoding: CompressionEncoding) {
    let svc = test_server::TestServer::new(Svc::default())
        .with_accept_compressed(CompressionEncoding::Gzip)
        .with_accept_compressed(CompressionEncoding::Zstd)
        .with_accept_compressed(CompressionEncoding::Deflate);

    let request_bytes_counter = Arc::new(AtomicUsize::new(0));

    fn assert_right_encoding<B>(req: http::Request<B>) -> http::Request<B> {
        let supported_encodings = ["gzip", "zstd", "deflate"];
        let req_encoding = req.headers().get("grpc-encoding").unwrap();
        assert!(supported_encodings.iter().any(|e| e == req_encoding));

        req
    }

    let server = {
        let request_bytes_counter = request_bytes_counter.clone();
        let grpc_svc = (
            MapInputLayer::new(assert_right_encoding),
            measure_request_body_size_layer(request_bytes_counter),
        )
            .into_layer(svc);

        HttpServer::h2(Executor::default()).service(grpc_svc)
    };

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_send_compressed(encoding);

    for _ in 0..3 {
        client
            .compress_input_unary(SomeData {
                data: [0_u8; UNCOMPRESSED_MIN_BODY_SIZE].to_vec(),
            })
            .await
            .unwrap();
        let bytes_sent = request_bytes_counter.load(atomic::Ordering::SeqCst);
        assert!(bytes_sent < UNCOMPRESSED_MIN_BODY_SIZE);
    }
}

util::parametrized_tests! {
    client_enabled_server_disabled,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn client_enabled_server_disabled(encoding: CompressionEncoding) {
    let svc = test_server::TestServer::new(Svc::default());

    let server = HttpServer::auto(Executor::default()).service(svc);

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_send_compressed(encoding);

    let status = client
        .compress_input_unary(SomeData {
            data: [0_u8; UNCOMPRESSED_MIN_BODY_SIZE].to_vec(),
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), Code::Unimplemented);
    let expected = match encoding {
        CompressionEncoding::Gzip => "gzip",
        CompressionEncoding::Zstd => "zstd",
        CompressionEncoding::Deflate => "deflate",
        _ => panic!("unexpected encoding {encoding:?}"),
    };
    assert_eq!(
        status.message(),
        format!("Content is compressed with `{expected}` which isn't supported")
    );

    assert_eq!(
        status.metadata().get("grpc-accept-encoding").unwrap(),
        "identity"
    );
}

// TOOD: support layers for grpc services

// util::parametrized_tests! {
//     client_mark_compressed_without_header_server_enabled,
//     zstd: CompressionEncoding::Zstd,
//     gzip: CompressionEncoding::Gzip,
//     deflate: CompressionEncoding::Deflate,
// }

// async fn client_mark_compressed_without_header_server_enabled(encoding: CompressionEncoding) {
//     let (client, server) = tokio::io::duplex(UNCOMPRESSED_MIN_BODY_SIZE * 10);

//     let svc = test_server::TestServer::new(Svc::default()).with_accept_compressed(encoding);

//     tokio::spawn({
//         async move {
//             HttpServer::auto(Executor::default())
//                 .serve(ServiceInput::new(server), svc)
//                 .await
//                 .unwrap();
//         }
//     });

//     fn remove_metadata<T>(mut req: Request<T>) -> Request<T> {
//         req.metadata_mut().remove("grpc-encoding");
//         req
//     }

//     let mut client = MapInputLayer::new(remove_metadata).into_layer(
//         test_client::TestClient::new(mock_io_client(client))
//             .with_send_compressed(CompressionEncoding::Gzip),
//     );

//     let status = client
//         .compress_input_unary(SomeData {
//             data: [0_u8; UNCOMPRESSED_MIN_BODY_SIZE].to_vec(),
//         })
//         .await
//         .unwrap_err();

//     assert_eq!(status.code(), Code::Internal);
//     assert_eq!(
//         status.message(),
//         "protocol error: received message with compressed-flag but no grpc-encoding was specified"
//     );
// }
