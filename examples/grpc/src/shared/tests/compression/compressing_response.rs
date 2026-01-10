use std::sync::{
    Arc,
    atomic::{self, AtomicUsize},
};

use rama::{
    Layer as _, Service,
    http::{
        self, Uri,
        grpc::{Code, Request, Streaming, codec::CompressionEncoding},
        layer::map_response_body::MapResponseBodyLayer,
        server::HttpServer,
    },
    layer::{MapOutputLayer, layer_fn},
    rt::Executor,
    stream::{self, StreamExt as _},
};

use crate::tests::compression::{
    SomeData, Svc, UNCOMPRESSED_MIN_BODY_SIZE, test_client, test_server,
    util::{self, mock_io_client},
};

util::parametrized_tests! {
    client_enabled_server_enabled,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn client_enabled_server_enabled(encoding: CompressionEncoding) {
    #[derive(Clone, Copy)]
    struct AssertCorrectAcceptEncoding<S> {
        service: S,
        encoding: CompressionEncoding,
    }

    impl<S, B> Service<http::Request<B>> for AssertCorrectAcceptEncoding<S>
    where
        S: Service<http::Request<B>>,
        B: Send + 'static,
    {
        type Output = S::Output;
        type Error = S::Error;

        async fn serve(&self, req: http::Request<B>) -> Result<Self::Output, Self::Error> {
            let expected = match self.encoding {
                CompressionEncoding::Gzip => "gzip",
                CompressionEncoding::Zstd => "zstd",
                CompressionEncoding::Deflate => "deflate",
                _ => panic!("unexpected encoding {:?}", self.encoding),
            };
            assert_eq!(
                req.headers()
                    .get("grpc-accept-encoding")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                format!("{expected},identity")
            );
            self.service.serve(req).await
        }
    }

    let svc = test_server::TestServer::new(Svc::default()).with_send_compressed(encoding);

    let response_bytes_counter = Arc::new(AtomicUsize::new(0));

    let server = {
        let response_bytes_counter = response_bytes_counter.clone();
        let grpc_svc = (
            layer_fn(|service| AssertCorrectAcceptEncoding { service, encoding }),
            MapResponseBodyLayer::new(move |body| util::CountBytesBody {
                inner: body,
                counter: response_bytes_counter.clone(),
            }),
        )
            .into_layer(svc);

        HttpServer::auto(Executor::default()).service(grpc_svc)
    };

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_accept_compressed(encoding);

    let expected = match encoding {
        CompressionEncoding::Gzip => "gzip",
        CompressionEncoding::Zstd => "zstd",
        CompressionEncoding::Deflate => "deflate",
        _ => panic!("unexpected encoding {encoding:?}"),
    };

    for _ in 0..3 {
        let res = client.compress_output_unary(()).await.unwrap();
        assert_eq!(res.metadata().get("grpc-encoding").unwrap(), expected);
        let bytes_sent = response_bytes_counter.load(atomic::Ordering::SeqCst);
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

    let response_bytes_counter = Arc::new(AtomicUsize::new(0));

    let server = {
        let response_bytes_counter = response_bytes_counter.clone();
        // no compression enable on the server so responses should not be compressed
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

    let res = client.compress_output_unary(()).await.unwrap();

    assert!(res.metadata().get("grpc-encoding").is_none());

    let bytes_sent = response_bytes_counter.load(atomic::Ordering::SeqCst);
    assert!(bytes_sent > UNCOMPRESSED_MIN_BODY_SIZE);
}

#[tokio::test(flavor = "multi_thread")]
async fn client_enabled_server_disabled_multi_encoding() {
    let svc = test_server::TestServer::new(Svc::default());

    let response_bytes_counter = Arc::new(AtomicUsize::new(0));

    let server = {
        let response_bytes_counter = response_bytes_counter.clone();
        // no compression enable on the server so responses should not be compressed
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
    .with_accept_compressed(CompressionEncoding::Gzip)
    .with_accept_compressed(CompressionEncoding::Zstd)
    .with_accept_compressed(CompressionEncoding::Deflate);

    let res = client.compress_output_unary(()).await.unwrap();

    assert!(res.metadata().get("grpc-encoding").is_none());

    let bytes_sent = response_bytes_counter.load(atomic::Ordering::SeqCst);
    assert!(bytes_sent > UNCOMPRESSED_MIN_BODY_SIZE);
}

util::parametrized_tests! {
    client_disabled,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn client_disabled(encoding: CompressionEncoding) {
    #[derive(Clone, Copy)]
    struct AssertCorrectAcceptEncoding<S>(S);

    impl<S, B> Service<http::Request<B>> for AssertCorrectAcceptEncoding<S>
    where
        S: Service<http::Request<B>>,
        B: Send + 'static,
    {
        type Output = S::Output;
        type Error = S::Error;

        async fn serve(&self, req: http::Request<B>) -> Result<Self::Output, Self::Error> {
            assert!(req.headers().get("grpc-accept-encoding").is_none());
            self.0.serve(req).await
        }
    }

    let svc = test_server::TestServer::new(Svc::default()).with_send_compressed(encoding);

    let response_bytes_counter = Arc::new(AtomicUsize::new(0));

    let server = {
        let response_bytes_counter = response_bytes_counter.clone();
        let grpc_svc = (
            layer_fn(AssertCorrectAcceptEncoding),
            MapResponseBodyLayer::new(move |body| util::CountBytesBody {
                inner: body,
                counter: response_bytes_counter.clone(),
            }),
        )
            .into_layer(svc);

        HttpServer::auto(Executor::default()).service(grpc_svc)
    };

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    );

    let res = client.compress_output_unary(()).await.unwrap();

    assert!(res.metadata().get("grpc-encoding").is_none());

    let bytes_sent = response_bytes_counter.load(atomic::Ordering::SeqCst);
    assert!(bytes_sent > UNCOMPRESSED_MIN_BODY_SIZE);
}

util::parametrized_tests! {
    server_replying_with_unsupported_encoding,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn server_replying_with_unsupported_encoding(encoding: CompressionEncoding) {
    let svc = test_server::TestServer::new(Svc::default()).with_send_compressed(encoding);

    fn add_weird_content_encoding<B>(mut response: http::Response<B>) -> http::Response<B> {
        response
            .headers_mut()
            .insert("grpc-encoding", "br".parse().unwrap());
        response
    }

    let grpc_svc = MapOutputLayer::new(add_weird_content_encoding).into_layer(svc);

    let server = HttpServer::h2(Executor::default()).service(grpc_svc);

    let client = test_client::TestClient::new(
        mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_accept_compressed(encoding);
    let status = client.compress_output_unary(()).await.unwrap_err();

    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(
        status.message(),
        "Content is compressed with `br` which isn't supported"
    );
}

util::parametrized_tests! {
    disabling_compression_on_single_response,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn disabling_compression_on_single_response(encoding: CompressionEncoding) {
    let svc = test_server::TestServer::new(Svc {
        disable_compressing_on_response: true,
    })
    .with_send_compressed(encoding);

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

    let res = client.compress_output_unary(()).await.unwrap();

    let expected = match encoding {
        CompressionEncoding::Gzip => "gzip",
        CompressionEncoding::Zstd => "zstd",
        CompressionEncoding::Deflate => "deflate",
        _ => panic!("unexpected encoding {encoding:?}"),
    };
    assert_eq!(res.metadata().get("grpc-encoding").unwrap(), expected);

    let bytes_sent = response_bytes_counter.load(atomic::Ordering::SeqCst);
    assert!(bytes_sent > UNCOMPRESSED_MIN_BODY_SIZE);
}

util::parametrized_tests! {
    disabling_compression_on_response_but_keeping_compression_on_stream,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn disabling_compression_on_response_but_keeping_compression_on_stream(
    encoding: CompressionEncoding,
) {
    let svc = test_server::TestServer::new(Svc {
        disable_compressing_on_response: true,
    })
    .with_send_compressed(encoding);

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
    disabling_compression_on_response_from_client_stream,
    zstd: CompressionEncoding::Zstd,
    gzip: CompressionEncoding::Gzip,
    deflate: CompressionEncoding::Deflate,
}

async fn disabling_compression_on_response_from_client_stream(encoding: CompressionEncoding) {
    let svc = test_server::TestServer::new(Svc {
        disable_compressing_on_response: true,
    })
    .with_send_compressed(encoding);

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

    let req = Request::new(Box::pin(stream::empty()));

    let res = client.compress_output_client_stream(req).await.unwrap();

    let expected = match encoding {
        CompressionEncoding::Gzip => "gzip",
        CompressionEncoding::Zstd => "zstd",
        CompressionEncoding::Deflate => "deflate",
        _ => panic!("unexpected encoding {encoding:?}"),
    };
    assert_eq!(res.metadata().get("grpc-encoding").unwrap(), expected);
    let bytes_sent = response_bytes_counter.load(atomic::Ordering::SeqCst);
    assert!(bytes_sent > UNCOMPRESSED_MIN_BODY_SIZE);
}
