use rama::{
    error::BoxError,
    http::{
        grpc::service::{GrpcRouter, health::server::health_reporter},
        server::HttpServer,
    },
    net::address::SocketAddress,
    rt::Executor,
};
use rama_grpc_examples::{
    hello_world::{RamaGreeter, greeter_server::GreeterServer},
    twiddle_hello_world_service_status,
};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let greeter = RamaGreeter::default();

    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<GreeterServer<RamaGreeter>>()
        .await;

    tokio::spawn(twiddle_hello_world_service_status(health_reporter.clone()));

    let grpc_svc = GrpcRouter::default()
        .with_service(GreeterServer::new(greeter))
        .with_service(health_service);

    HttpServer::auto(Executor::default())
        .listen(SocketAddress::local_ipv6(50051), grpc_svc)
        .await?;

    Ok(())
}
