use rama::{
    ServiceInput,
    http::{
        Uri,
        grpc::{Code, codec::CompressionEncoding},
        server::HttpServer,
    },
    telemetry::tracing,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn hello_world_client_server_flow() {
    let (client, server) = tokio::io::duplex(256);

    let svc = crate::hello_world::greeter_server::GreeterServer::new(
        crate::hello_world::RamaGreeter::default(),
    );

    tokio::spawn(async move {
        HttpServer::auto(Default::default())
            .serve(ServiceInput::new(server), svc)
            .await
            .unwrap();
    });

    let client = crate::hello_world::greeter_client::GreeterClient::new(
        super::mock_io_client(client),
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
    let (client, server) = tokio::io::duplex(256);

    let svc = crate::hello_world::greeter_server::GreeterServer::new(
        crate::hello_world::RamaGreeter::default(),
    )
    .with_accept_compressed(CompressionEncoding::Deflate)
    .with_send_compressed(CompressionEncoding::Gzip);

    tokio::spawn(async move {
        HttpServer::auto(Default::default())
            .serve(ServiceInput::new(server), svc)
            .await
            .unwrap();
    });

    let client = crate::hello_world::greeter_client::GreeterClient::new(
        super::mock_io_client(client),
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
    let (client, server) = tokio::io::duplex(256);

    let svc = crate::hello_world::greeter_server::GreeterServer::new(
        crate::hello_world::RamaGreeter::default(),
    )
    .with_accept_compressed(CompressionEncoding::Deflate)
    .with_send_compressed(CompressionEncoding::Gzip);

    tokio::spawn(async move {
        HttpServer::auto(Default::default())
            .serve(ServiceInput::new(server), svc)
            .await
            .unwrap();
    });

    let client = crate::hello_world::greeter_client::GreeterClient::new(
        super::mock_io_client(client),
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
    let (client, server) = tokio::io::duplex(256);

    let svc = crate::hello_world::greeter_server::GreeterServer::new(
        crate::hello_world::RamaGreeter::default(),
    )
    .with_accept_compressed(encoding)
    .with_send_compressed(encoding);

    tokio::spawn(async move {
        HttpServer::auto(Default::default())
            .serve(ServiceInput::new(server), svc)
            .await
            .unwrap();
    });

    let client = crate::hello_world::greeter_client::GreeterClient::new(
        super::mock_io_client(client),
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
