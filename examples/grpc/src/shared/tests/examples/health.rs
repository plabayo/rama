use std::time::Duration;

use rama::{
    http::{
        Uri,
        grpc::{
            Code, Request,
            protobuf::ProstCodec,
            service::{
                GrpcRouter,
                health::{
                    pb::{
                        HealthCheckRequest, HealthCheckResponse, HealthListRequest,
                        HealthListResponse, health_client::HealthClient,
                    },
                    server::health_reporter,
                },
            },
        },
        server::HttpServer,
        uri::PathAndQuery,
    },
    rt::Executor,
    stream::StreamExt,
    telemetry::tracing,
};
use tokio::time::Instant;

use crate::{
    hello_world::{RamaGreeter, greeter_server::GreeterServer},
    twiddle_hello_world_service_status,
};

#[tokio::test]
#[tracing_test::traced_test]
#[ignore]
async fn health_server_via_router() {
    let greeter = RamaGreeter::default();

    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<GreeterServer<RamaGreeter>>()
        .await;

    tokio::spawn(twiddle_hello_world_service_status(health_reporter.clone()));

    let grpc_svc = GrpcRouter::default()
        .with_service(GreeterServer::new(greeter))
        .with_service(health_service);

    let server = HttpServer::auto(Executor::default()).service(grpc_svc);

    // hello world capabilities

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

    let transport = client.into_transport();

    // health capabilities

    let client = HealthClient::new(transport, Uri::from_static("http://[::1]:50051"));

    for (idx, expected_code) in [Code::Cancelled, Code::Unknown, Code::Cancelled]
        .into_iter()
        .enumerate()
    {
        if idx != 0 {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let HealthCheckResponse { status } = client
            .check(HealthCheckRequest {
                service: "helloworld.Greeter".to_owned(),
            })
            .await
            .unwrap()
            .into_inner();

        assert_eq!(expected_code as i32, status);
    }

    let HealthListResponse { statuses } = client
        .list(HealthListRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        Some(HealthCheckResponse {
            status: Code::Cancelled as i32
        }),
        statuses.get("helloworld.Greeter").cloned()
    );

    let mut watch_stream = client
        .watch(HealthCheckRequest {
            service: "helloworld.Greeter".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut start = Instant::now();

    for (idx, expected_code) in [
        Code::Cancelled,
        Code::Unknown,
        Code::Cancelled,
        Code::Unknown,
    ]
    .into_iter()
    .enumerate()
    {
        if idx == 1 {
            assert!(start.elapsed() <= Duration::from_millis(350));
            start = Instant::now();
        } else if idx >= 2 {
            assert!(start.elapsed() >= Duration::from_millis(((idx - 1) as u64) * 250 - 100));
        }

        let HealthCheckResponse { status } = watch_stream.next().await.unwrap().unwrap();
        assert_eq!(expected_code as i32, status);
    }

    // unknown service / method / path

    let grpc_client = client.into_inner();

    for paq in [
        "",
        "/foo",
        "/foo/bar",
        "/?foo",
        "/helloworld.Greeter/Hallotjes",
    ] {
        let status = grpc_client
            .unary::<HealthCheckRequest, HealthCheckResponse, _>(
                Request::new(HealthCheckRequest {
                    service: "helloworld.Greeter".to_owned(),
                }),
                PathAndQuery::from_static(paq),
                ProstCodec::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(Code::Unimplemented, status.code(), "paq = '{paq}'");
    }
}
