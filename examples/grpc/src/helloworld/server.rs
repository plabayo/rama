use rama::{error::BoxError, http::server::HttpServer, net::address::SocketAddress};
use rama_grpc_examples::hello_world::{RamaGreeter, greeter_server::GreeterServer};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let greeter = RamaGreeter::default();

    HttpServer::auto(Default::default())
        .listen(
            SocketAddress::local_ipv6(50051),
            GreeterServer::new(greeter),
        )
        .await?;

    Ok(())
}
