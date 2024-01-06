use rama::{
    http::{response::Html, server::HttpServer, Request},
    rt::Executor,
    service::service_fn,
};

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            "127.0.0.1:8080",
            service_fn(|req: Request| async move {
                Ok(Html(format!("<p>Hello <em>{}</em>!</p>", req.uri().path())))
            }),
        )
        .await
        .unwrap();
}
