use rama::{
    http::{
        Uri,
        grpc::{Code, codec::CompressionEncoding},
        server::HttpServer,
    },
    rt::Executor,
    telemetry::tracing,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn hello_world_client_server_flow() {
    let svc = crate::hello_world::greeter_server::GreeterServer::new(
        crate::hello_world::RamaGreeter::default(),
    );

    let server = HttpServer::auto(Executor::default()).service(svc);

    let client = crate::hello_world::greeter_client::GreeterClient::new(
        super::mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    );

    let crate::hello_world::HelloReply { message } = client
        .say_hello(crate::hello_world::HelloRequest {
            name: "Test".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!("Hello Test!", message);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn hello_world_client_server_flow_with_compression_mismatch() {
    let svc = crate::hello_world::greeter_server::GreeterServer::new(
        crate::hello_world::RamaGreeter::default(),
    )
    .with_accept_compressed(CompressionEncoding::Deflate)
    .with_send_compressed(CompressionEncoding::Gzip);

    let server = HttpServer::auto(Executor::default()).service(svc);

    let client = crate::hello_world::greeter_client::GreeterClient::new(
        super::mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_accept_compressed(CompressionEncoding::Deflate)
    .with_send_compressed(CompressionEncoding::Gzip);

    let err_code = client
        .say_hello(crate::hello_world::HelloRequest {
            name: "Test".to_owned(),
        })
        .await
        .unwrap_err()
        .code();

    assert_eq!(Code::Unimplemented, err_code);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn hello_world_client_server_flow_with_compression_mix() {
    let svc = crate::hello_world::greeter_server::GreeterServer::new(
        crate::hello_world::RamaGreeter::default(),
    )
    .with_accept_compressed(CompressionEncoding::Deflate)
    .with_send_compressed(CompressionEncoding::Gzip);

    let server = HttpServer::auto(Executor::default()).service(svc);

    let client = crate::hello_world::greeter_client::GreeterClient::new(
        super::mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_accept_compressed(CompressionEncoding::Gzip)
    .with_send_compressed(CompressionEncoding::Deflate);

    let crate::hello_world::HelloReply { message } = client
        .say_hello(crate::hello_world::HelloRequest {
            name: "Test".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!("Hello Test!", message);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn hello_world_client_server_flow_with_compression_deflate() {
    hello_world_client_server_flow_with_compression(CompressionEncoding::Deflate).await;
}

#[tokio::test]
#[tracing_test::traced_test]
async fn hello_world_client_server_flow_with_compression_gzip() {
    hello_world_client_server_flow_with_compression(CompressionEncoding::Gzip).await;
}

#[tokio::test]
#[tracing_test::traced_test]
async fn hello_world_client_server_flow_with_compression_zstd() {
    hello_world_client_server_flow_with_compression(CompressionEncoding::Zstd).await;
}

async fn hello_world_client_server_flow_with_compression(encoding: CompressionEncoding) {
    let svc = crate::hello_world::greeter_server::GreeterServer::new(
        crate::hello_world::RamaGreeter::default(),
    )
    .with_accept_compressed(encoding)
    .with_send_compressed(encoding);

    let server = HttpServer::auto(Executor::default()).service(svc);

    let client = crate::hello_world::greeter_client::GreeterClient::new(
        super::mock_io_client(move || server.clone()),
        Uri::from_static("http://[::1]:50051"),
    )
    .with_accept_compressed(encoding)
    .with_send_compressed(encoding);

    let crate::hello_world::HelloReply { message } = client
        .say_hello(crate::hello_world::HelloRequest {
            name: "Test".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!("Hello Test!", message);
}
