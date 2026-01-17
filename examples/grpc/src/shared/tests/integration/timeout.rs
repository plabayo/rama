use std::time::Duration;

use rama::{
    Layer as _,
    http::{
        client::EasyHttpWebClient,
        grpc::{
            Code, Request, Response, Status,
            service::{GrpcTimeoutLayer, RecoverErrorLayer},
        },
        server::HttpServer,
    },
    layer::ConsumeErrLayer,
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
};

use crate::tests::integration::pb::{Input, Output, test_client::TestClient, test_server};

#[tokio::test]
#[tracing_test::traced_test]
async fn cancelation_on_timeout() {
    let addr = run_service_in_background(Duration::from_secs(1), Duration::from_secs(100)).await;

    let client = TestClient::new(
        EasyHttpWebClient::default(),
        format!("http://{addr}").parse().unwrap(),
    );

    let mut req = Request::new(Input {});
    req.metadata_mut()
        // 500 ms
        .insert("grpc-timeout", "500m".parse().unwrap());

    let res = client.unary_call(req).await;

    let err = res.unwrap_err();
    assert!(err.message().contains("Timeout expired"));
    assert_eq!(err.code(), Code::Cancelled);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn picks_server_timeout_if_thats_sorter() {
    let addr = run_service_in_background(Duration::from_secs(1), Duration::from_millis(100)).await;

    let client = TestClient::new(
        EasyHttpWebClient::default(),
        format!("http://{addr}").parse().unwrap(),
    );

    let mut req = Request::new(Input {});
    req.metadata_mut()
        // 10 hours
        .insert("grpc-timeout", "10H".parse().unwrap());

    let res = client.unary_call(req).await;
    let err = res.unwrap_err();
    assert!(err.message().contains("Timeout expired"));
    assert_eq!(err.code(), Code::Cancelled);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn picks_client_timeout_if_thats_sorter() {
    let addr = run_service_in_background(Duration::from_secs(1), Duration::from_secs(100)).await;

    let client = TestClient::new(
        EasyHttpWebClient::default(),
        format!("http://{addr}").parse().unwrap(),
    );

    let mut req = Request::new(Input {});
    req.metadata_mut()
        // 100 ms
        .insert("grpc-timeout", "100m".parse().unwrap());

    let res = client.unary_call(req).await;
    let err = res.unwrap_err();
    assert_eq!(err.code(), Code::Cancelled);
    assert!(err.message().contains("Timeout expired"));
}

async fn run_service_in_background(latency: Duration, server_timeout: Duration) -> SocketAddress {
    struct Svc {
        latency: Duration,
    }

    impl test_server::Test for Svc {
        async fn unary_call(&self, _req: Request<Input>) -> Result<Response<Output>, Status> {
            tokio::time::sleep(self.latency).await;
            Ok(Response::new(Output {}))
        }
    }

    let svc = test_server::TestServer::new(Svc { latency });

    let listener = TcpListener::bind(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let grpc_svc = (
        ConsumeErrLayer::default(),
        RecoverErrorLayer::new(),
        GrpcTimeoutLayer::new(server_timeout),
    )
        .into_layer(svc);

    tokio::spawn(async move {
        listener
            .serve(HttpServer::h2(Executor::default()).service(grpc_svc))
            .await;
    });

    addr.into()
}
