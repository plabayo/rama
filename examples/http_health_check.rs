use rama::{http::server::HttpServer, rt::Executor, service::service_fn};

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen("127.0.0.1:8080", service_fn(|| async move { Ok(()) }))
        .await
        .unwrap();
}
