//! shared by all Grpc examples + tests for core logic

#![allow(clippy::disallowed_types)] // for interfacing with protobuf it is easier to allow things like std HashMap

use std::time::Duration;

use rama::http::grpc::service::health::server::HealthReporter;

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

/// This function (somewhat improbably) flips the status of a service every second, in order
/// that the effect of `tonic_health::HealthReporter::watch` can be easily observed.
pub async fn twiddle_hello_world_service_status(reporter: HealthReporter) {
    let mut iter = 0u64;
    loop {
        iter += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;

        if iter.is_multiple_of(2) {
            reporter
                .set_serving::<self::hello_world::greeter_server::GreeterServer<self::hello_world::RamaGreeter>>()
                .await;
        } else {
            reporter
                .set_not_serving::<self::hello_world::greeter_server::GreeterServer<self::hello_world::RamaGreeter>>()
                .await;
        };
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
