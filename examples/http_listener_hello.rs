use rama::{
    http::{response::Json, server::HttpServer, Request},
    rt::Executor,
    service::service_fn,
};
use serde_json::json;

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            "127.0.0.1:8080",
            service_fn(|req: Request| async move {
                Ok(Json(json!({
                    "method": req.method().as_str(),
                    "path": req.uri().path(),
                })))
            }),
        )
        .await
        .unwrap();
}
