use super::utils;
use rama::{
    Context, Service,
    http::{Body, BodyExtractExt, Method, Request, client::HttpConnector},
    net::client::{ConnectorService, EstablishedClientConnection},
    unix::client::UnixConnector,
};

#[tokio::test]
#[ignore]
async fn test_unix_socket_http() {
    utils::init_tracing();

    let _runner = utils::ExampleRunner::interactive("unix_socket_http", None);

    let (request, svc) = async {
        for i in 0..5 {
            let request = Request::builder()
                .uri("http://localhost/ping")
                .method(Method::GET)
                .body(Body::empty())
                .expect("build request");

            match HttpConnector::new(UnixConnector::fixed("/tmp/rama_example_unix_http.socket"))
                .connect(Context::default(), request)
                .await
            {
                Ok(EstablishedClientConnection { conn, req, .. }) => return Some((req, conn)),
                Err(e) => {
                    eprintln!("unix connect error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
                }
            }
        }
        None
    }
    .await
    .unwrap();

    let response = svc
        .serve(Context::default(), request)
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();
    assert_eq!("pong", response);
}
