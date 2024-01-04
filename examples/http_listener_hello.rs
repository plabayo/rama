use rama::{
    http::{server::HttpServer, Body, Request, Response},
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
                let body = Body::from(format!("Hello {}!", req.uri().path()));
                Ok(Response::new(body))
            }),
        )
        .await
        .unwrap();
}
