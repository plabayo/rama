use std::time::Duration;

use tokio::sync::oneshot;

use rama::{
    Layer as _,
    graceful::Shutdown,
    http::{
        client::EasyHttpWebClient,
        conn::H2ClientContextParams,
        grpc::{Request, Response, Status},
        server::HttpServer,
    },
    layer::AddInputExtensionLayer,
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
};

use crate::tests::integration::pb::{Input, Output, test_client::TestClient, test_server};

struct Svc;

impl test_server::Test for Svc {
    async fn unary_call(&self, _: Request<Input>) -> Result<Response<Output>, Status> {
        Ok(Response::new(Output {}))
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn http2_keepalive_does_not_cause_panics() {
    let svc = test_server::TestServer::new(Svc {});
    let (tx, rx) = oneshot::channel::<()>();

    let graceful = Shutdown::new(async { drop(rx.await) });
    let exec = Executor::graceful(graceful.guard());

    let listener = TcpListener::bind(SocketAddress::local_ipv4(0), exec)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let jh = graceful.spawn_task_fn(async move |guard| {
        let mut server = HttpServer::h2(Executor::graceful(guard.clone()));
        server
            .h2_mut()
            .set_keep_alive_interval(Duration::from_secs(10));

        listener.serve(server.service(svc)).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = TestClient::new(
        EasyHttpWebClient::default(),
        format!("http://{addr}").parse().unwrap(),
    );

    let res = client.unary_call(Request::new(Input {})).await;

    assert!(res.is_ok());

    tx.send(()).unwrap();
    jh.await.unwrap();
}

#[tokio::test]
#[tracing_test::traced_test]
async fn http2_keepalive_does_not_cause_panics_on_client_side() {
    let svc = test_server::TestServer::new(Svc {});
    let (tx, rx) = oneshot::channel::<()>();

    let graceful = Shutdown::new(async { drop(rx.await) });
    let exec = Executor::graceful(graceful.guard());
    let listener = TcpListener::bind(SocketAddress::local_ipv4(0), exec)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let jh = graceful.spawn_task_fn(async move |guard| {
        let mut server = HttpServer::h2(Executor::graceful(guard.clone()));
        server
            .h2_mut()
            .set_keep_alive_interval(Duration::from_secs(5));

        listener.serve(server.service(svc)).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = TestClient::new(
        AddInputExtensionLayer::new(H2ClientContextParams {
            keep_alive_interval: Some(Duration::from_secs(5)),
            ..Default::default()
        })
        .into_layer(EasyHttpWebClient::default()),
        format!("http://{addr}").parse().unwrap(),
    );

    let res = client.unary_call(Request::new(Input {})).await;

    assert!(res.is_ok());

    tx.send(()).unwrap();
    jh.await.unwrap();
}
