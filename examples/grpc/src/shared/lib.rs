//! shared by all Grpc examples + tests for core logic

#![allow(clippy::disallowed_types)] // for interfacing with protobuf it is easier to allow things like std HashMap

pub mod hello_world {
    rama::http::grpc::include_proto!("helloworld");

    use self::greeter_server::Greeter;
    use rama::{
        extensions::ExtensionsRef as _,
        http::grpc::{Request, Response, Status},
        net::stream::SocketInfo,
    };

    #[derive(Default)]
    pub struct RamaGreeter {}

    impl Greeter for RamaGreeter {
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
}

pub mod gcp {
    pub mod pubsub {
        rama::http::grpc::include_proto!("google.pubsub.v1");
    }
}

pub mod echo {
    rama::http::grpc::include_proto!("grpc.examples.echo");
}

#[cfg(test)]
pub mod tests;
