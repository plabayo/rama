use std::time::Duration;

use rama::{
    Layer as _,
    graceful::Shutdown,
    http::{
        HeaderName, HeaderValue,
        client::EasyHttpWebClient,
        grpc::{Request, Response, Status},
        layer::{set_header::SetRequestHeaderLayer, trace::TraceLayer},
        server::HttpServer,
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
};
use tokio::sync::oneshot;

use crate::tests::integration::pb::{Input, Output, test_client::TestClient, test_server};

#[tokio::test]
#[tracing_test::traced_test]
async fn connect_supports_standard_rama_http_layers() {
    struct Svc;

    impl test_server::Test for Svc {
        async fn unary_call(&self, req: Request<Input>) -> Result<Response<Output>, Status> {
            match req.metadata().get("x-test") {
                Some(_) => Ok(Response::new(Output {})),
                None => Err(Status::internal("user-agent header is missing")),
            }
        }
    }

    let (tx, rx) = oneshot::channel();
    let svc = test_server::TestServer::new(Svc);

    let graceful = Shutdown::new(async { drop(rx.await) });
    let exec = Executor::graceful(graceful.guard());

    let listener = TcpListener::bind(SocketAddress::local_ipv4(0), exec)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let jh = graceful.spawn_task_fn(async move |guard| {
        listener
            .serve(HttpServer::h2(Executor::graceful(guard)).service(svc))
            .await;
    });

    let client = TestClient::new(
        (
            SetRequestHeaderLayer::overriding(
                HeaderName::from_static("x-test"),
                HeaderValue::from_static("test-header"),
            ),
            TraceLayer::new_for_grpc(),
        )
            .into_layer(EasyHttpWebClient::default()),
        format!("http://{addr}").parse().unwrap(),
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    client.unary_call(Request::new(Input {})).await.unwrap();

    tx.send(()).unwrap();
    jh.await.unwrap();
}
