use rama::{
    error::BoxError,
    extensions::ExtensionsRef,
    http::{
        grpc::{Request, Response, Status},
        server::HttpServer,
    },
    net::{address::SocketAddress, stream::SocketInfo},
};
use rama_grpc_examples::hello_world::{
    HelloReply, HelloRequest,
    greeter_server::{Greeter, GreeterServer},
};

#[derive(Default)]
pub struct MyGreeter {}

impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!(
            "Got a request from {:?}",
            request
                .extensions()
                .get::<SocketInfo>()
                .map(|info| info.peer_addr())
        );

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let greeter = MyGreeter::default();

    HttpServer::auto(Default::default())
        .listen(
            SocketAddress::local_ipv6(50051),
            GreeterServer::new(greeter),
        )
        .await?;

    Ok(())
}
