use std::sync::{
    Arc,
    atomic::{self, AtomicUsize},
};

use rama::{
    Layer,
    http::{
        self, StreamingBody, Uri,
        grpc::{Request, Streaming, codec::CompressionEncoding},
        layer::map_response_body::MapResponseBodyLayer,
        server::HttpServer,
    },
    layer::MapInputLayer,
    rt::Executor,
    stream::{self, StreamExt as _},
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
    let svc = test_server::TestServer::new(Svc::default())
        .with_accept_compressed(encoding)
        .with_send_compressed(encoding);

    let request_bytes_counter = Arc::new(AtomicUsize::new(0));
    let response_bytes_counter = Arc::new(AtomicUsize::new(0));

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
        let response_bytes_counter = response_bytes_counter.clone();

        let grpc_svc = (
            MapInputLayer::new(move |req| AssertRightEncoding::new(encoding).call(req)),
            measure_request_body_size_layer(request_bytes_counter),
            MapResponseBodyLayer::new(move |body| util::CountBytesBody {
                inner: body,
                counter: response_bytes_counter.clone(),
            }),
        )
            .into_layer(svc);

        HttpServer::h2(Executor::default()).service(grpc_svc)
    };

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_send_compressed(encoding)
    .with_accept_compressed(encoding);

    let data = [0_u8; UNCOMPRESSED_MIN_BODY_SIZE].to_vec();
    let stream = stream::iter(vec![SomeData { data: data.clone() }, SomeData { data }]);
    let req = Request::new(stream);

    let res = client
        .compress_input_output_bidirectional_stream(req)
        .await
        .unwrap();

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

    stream
        .next()
        .await
        .expect("stream empty")
        .expect("item was error");

    assert!(request_bytes_counter.load(atomic::Ordering::SeqCst) < UNCOMPRESSED_MIN_BODY_SIZE);
    assert!(response_bytes_counter.load(atomic::Ordering::SeqCst) < UNCOMPRESSED_MIN_BODY_SIZE);
}
