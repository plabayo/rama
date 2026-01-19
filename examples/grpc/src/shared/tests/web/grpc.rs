use std::time::Duration;

use rama::{
    Layer as _, Service,
    error::BoxError,
    futures::{join, try_join},
    http::{
        self,
        client::EasyHttpWebClient,
        grpc::{Code, Response, Status, Streaming, web::GrpcWebLayer},
        layer::required_header::AddRequiredRequestHeadersLayer,
        server::HttpServer,
    },
    net::address::SocketAddress,
    rt::Executor,
    service::BoxService,
    stream::{self, StreamExt as _},
    tcp::server::TcpListener,
    telemetry::tracing,
};

use super::{Svc, pb::*};

#[tokio::test]
#[tracing_test::traced_test]
async fn smoke_unary() {
    let (c1, c2, c3, c4) = spawn().await;

    let (r1, r2, r3, r4) = try_join!(
        c1.unary_call(input()),
        c2.unary_call(input()),
        c3.unary_call(input()),
        c4.unary_call(input()),
    )
    .expect("responses");

    assert!(meta(&r1) == meta(&r2) && meta(&r2) == meta(&r3) && meta(&r3) == meta(&r4));
    assert!(data(&r1) == data(&r2) && data(&r2) == data(&r3) && data(&r3) == data(&r4));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn smoke_client_stream() {
    let (c1, c2, c3, c4) = spawn().await;

    let input_stream = || stream::iter(vec![input(), input()]);

    let (r1, r2, r3, r4) = try_join!(
        c1.client_stream(input_stream()),
        c2.client_stream(input_stream()),
        c3.client_stream(input_stream()),
        c4.client_stream(input_stream()),
    )
    .expect("responses");

    assert!(meta(&r1) == meta(&r2) && meta(&r2) == meta(&r3) && meta(&r3) == meta(&r4));
    assert!(data(&r1) == data(&r2) && data(&r2) == data(&r3) && data(&r3) == data(&r4));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn smoke_server_stream() {
    let (c1, c2, c3, c4) = spawn().await;

    let (r1, r2, r3, r4) = try_join!(
        c1.server_stream(input()),
        c2.server_stream(input()),
        c3.server_stream(input()),
        c4.server_stream(input()),
    )
    .expect("responses");

    assert!(meta(&r1) == meta(&r2) && meta(&r2) == meta(&r3) && meta(&r3) == meta(&r4));

    let r1 = stream(r1).await;
    let r2 = stream(r2).await;
    let r3 = stream(r3).await;
    let r4 = stream(r4).await;

    assert!(r1 == r2 && r2 == r3 && r3 == r4);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn smoke_error() {
    let (c1, c2, c3, c4) = spawn().await;

    let boom = Input {
        id: 1,
        desc: "boom".to_owned(),
    };

    let (r1, r2, r3, r4) = join!(
        c1.unary_call(boom.clone()),
        c2.unary_call(boom.clone()),
        c3.unary_call(boom.clone()),
        c4.unary_call(boom.clone()),
    );

    let s1 = r1.unwrap_err();
    let s2 = r2.unwrap_err();
    let s3 = r3.unwrap_err();
    let s4 = r4.unwrap_err();

    assert!(status(&s1) == status(&s2) && status(&s2) == status(&s3) && status(&s3) == status(&s4))
}

async fn bind() -> (TcpListener, String) {
    let addr = SocketAddress::local_ipv4(0);
    let lis = TcpListener::bind(addr, Executor::default())
        .await
        .expect("listener");
    let url = format!("http://{}", lis.local_addr().unwrap());

    (lis, url)
}

async fn grpc(accept_h1: bool) -> (impl Future<Output = ()>, String) {
    let (listener, url) = bind().await;

    let http_svc = test_server::TestServer::new(Svc);

    let fut = async move {
        if accept_h1 {
            listener
                .serve(HttpServer::auto(Executor::default()).service(http_svc))
                .await;
        } else {
            listener
                .serve(HttpServer::h2(Executor::default()).service(http_svc))
                .await;
        }
    };

    (fut, url)
}

async fn grpc_web(accept_h1: bool) -> (impl Future<Output = ()>, String) {
    let (listener, url) = bind().await;

    let http_svc = GrpcWebLayer::new().into_layer(test_server::TestServer::new(Svc));

    let fut = async move {
        if accept_h1 {
            listener
                .serve(HttpServer::auto(Executor::default()).service(http_svc))
                .await;
        } else {
            listener
                .serve(HttpServer::h2(Executor::default()).service(http_svc))
                .await;
        }
    };

    (fut, url)
}

type WebClient = BoxService<http::Request, http::Response, BoxError>;

type Client = test_client::TestClient<WebClient>;

async fn spawn() -> (Client, Client, Client, Client) {
    let ((s1, u1), (s2, u2), (s3, u3), (s4, u4)) =
        join!(grpc(true), grpc(false), grpc_web(true), grpc_web(false));

    drop(tokio::spawn(async move { join!(s1, s2, s3, s4) }));

    tokio::time::sleep(Duration::from_millis(30)).await;

    (
        test_client::TestClient::new(
            Service::boxed(
                AddRequiredRequestHeadersLayer::new().into_layer(EasyHttpWebClient::default()),
            ),
            u1.parse().unwrap(),
        ),
        test_client::TestClient::new(
            Service::boxed(
                AddRequiredRequestHeadersLayer::new().into_layer(EasyHttpWebClient::default()),
            ),
            u2.parse().unwrap(),
        ),
        test_client::TestClient::new(
            Service::boxed(
                AddRequiredRequestHeadersLayer::new().into_layer(EasyHttpWebClient::default()),
            ),
            u3.parse().unwrap(),
        ),
        test_client::TestClient::new(
            Service::boxed(
                AddRequiredRequestHeadersLayer::new().into_layer(EasyHttpWebClient::default()),
            ),
            u4.parse().unwrap(),
        ),
    )
}

fn input() -> Input {
    Input {
        id: 1,
        desc: "one".to_owned(),
    }
}

fn meta<T>(r: &Response<T>) -> String {
    format!("{:?}", r.metadata())
}

fn data<T>(r: &Response<T>) -> &T {
    r.get_ref()
}

async fn stream<T>(r: Response<Streaming<T>>) -> Vec<T> {
    r.into_inner().collect::<Result<Vec<_>, _>>().await.unwrap()
}

fn status(s: &Status) -> (String, Code) {
    (format!("{:?}", s.metadata()), s.code())
}
