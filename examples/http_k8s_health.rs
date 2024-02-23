use rama::{
    http::{server::HttpServer, service::web::k8s_health_builder},
    rt::Executor,
};

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    let startup_time = std::time::Instant::now();
    HttpServer::auto(exec)
        .listen(
            "127.0.0.1:8080",
            // by default the k8s health service is always ready and alive,
            // optionally you can define your own conditional closures to define
            // more accurate health checks
            k8s_health_builder()
                .ready(move || {
                    // simulate a service only ready after 10s for w/e reason
                    let uptime = startup_time.elapsed().as_secs();
                    uptime > 10
                })
                .build(),
        )
        .await
        .unwrap();
}
