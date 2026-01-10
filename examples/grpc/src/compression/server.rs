use rama::{
    error::BoxError,
    http::{grpc::codec::CompressionEncoding, server::HttpServer},
    net::address::SocketAddress,
    rt::Executor,
};
use rama_grpc_examples::hello_world::{RamaGreeter, greeter_server::GreeterServer};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let greeter = RamaGreeter::default();

    let service = GreeterServer::new(greeter)
        .with_send_compressed(CompressionEncoding::Gzip)
        .with_accept_compressed(CompressionEncoding::Gzip);

    HttpServer::auto(Executor::default())
        .listen(SocketAddress::local_ipv6(50051), service)
        .await?;

    Ok(())
}
