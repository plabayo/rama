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
    layer::{AddInputExtensionLayer, MapInputLayer},
    net::{
        address::SocketAddress,
        socket::core::{SockRef, TcpKeepalive},
    },
    rt::Executor,
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing,
};

use crate::tests::integration::pb::{
    Input, Output,
    test_client::{self},
    test_server,
};

/// This test checks that the max header list size is respected, and that
/// it allows for error messages up to that size.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_http_max_header_list_size_and_long_errors() {
    struct Svc;

    // The default value is 16k.
    const N: usize = 20_000;

    fn long_message() -> String {
        "a".repeat(N)
    }

    impl test_server::Test for Svc {
        async fn unary_call(&self, _: Request<Input>) -> Result<Response<Output>, Status> {
            Err(Status::internal(long_message()))
        }
    }

    let svc = test_server::TestServer::new(Svc);
    let (tx, rx) = oneshot::channel::<()>();

    let graceful = Shutdown::new(async { drop(rx.await) });
    let exec = Executor::graceful(graceful.guard());

    let listener = TcpListener::bind(SocketAddress::local_ipv4(0), exec)
        .await
        .unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());

    let jh = graceful.spawn_task_fn(async move |guard| {
        let mut http_server = HttpServer::h2(Executor::graceful(guard.clone()));
        http_server.h2_mut().set_max_pending_accept_reset_streams(0);

        let tcp_service = MapInputLayer::new(|stream: TcpStream| {
            stream.stream.set_nodelay(true).unwrap();
            let sock_ref = SockRef::from(&stream.stream);
            let keep_alive = TcpKeepalive::new().with_time(Duration::from_secs(1));
            sock_ref.set_tcp_keepalive(&keep_alive).unwrap();
            stream
        })
        .into_layer(http_server.service(svc));

        listener.serve(tcp_service).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = test_client::TestClient::new(
        AddInputExtensionLayer::new(H2ClientContextParams {
            max_header_list_size: Some(u32::try_from(N * 2).unwrap()),
            ..Default::default()
        })
        .into_layer(EasyHttpWebClient::default()),
        addr.parse().unwrap(),
    );

    let err = client.unary_call(Request::new(Input {})).await.unwrap_err();

    assert_eq!(err.message(), long_message());

    tx.send(()).unwrap();

    jh.await.unwrap();
}
