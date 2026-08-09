//! An example showing how to serve a gRPC service which speaks JSON instead of protobuf,
//! defined inline in Rust without a `.proto` file or a build script.
//!
//! The service itself is defined in [`echo`], next to this example, and shared with the
//! `grpc_json_echo_client` example which calls it.
//!
//! Its sibling `grpc_echo` serves the very same `Echo` service the classic way: a `.proto`
//! contract compiled by a build script into protobuf stubs. Run both to compare.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin grpc_json_echo_server --features=grpc,http-full
//! ```
//!
//! The server listens on `127.0.0.1:62071`. Call it with the client example:
//!
//! ```sh
//! cargo run -p rama-examples --bin grpc_json_echo_client --features=grpc,http-full
//! ```
//!
//! # Call it from the shell
//!
//! gRPC prefixes every message with a 5-byte header (1 compression flag byte + 4 length
//! bytes), which is why the request body below is the 19-byte JSON document preceded by
//! `\x00\x00\x00\x00\x13`. The response comes back framed the same way:
//!
//! ```sh
//! printf '\x00\x00\x00\x00\x13{"message":"hello"}' | curl -s --http2-prior-knowledge \
//!     -H 'content-type: application/grpc' --data-binary @- --output - \
//!     http://127.0.0.1:62071/rama.examples.echo.v1.Echo/UnaryEcho | xxd
//! ```

use rama::{
    error::BoxError,
    http::{
        grpc::{Request, Response, Status},
        server::HttpServer,
    },
    net::address::SocketAddress,
    rt::Executor,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

mod echo;
use echo::{EchoRequest, EchoResponse, echo_server};

const ADDR: SocketAddress = SocketAddress::local_ipv4(62071);

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    tracing::info!("json grpc echo server listening on {ADDR}");
    HttpServer::auto(Executor::default())
        .listen(ADDR, echo_server::EchoServer::new(EchoService))
        .await?;

    Ok(())
}

/// Our implementation of the generated `Echo` service trait.
struct EchoService;

impl echo_server::Echo for EchoService {
    /// Server streaming methods return a stream of their own, which the trait needs named.
    type ServerStreamingEchoStream =
        rama::stream::Iter<std::vec::IntoIter<Result<EchoResponse, Status>>>;

    async fn unary_echo(
        &self,
        request: Request<EchoRequest>,
    ) -> Result<Response<EchoResponse>, Status> {
        let message = request.into_inner().message;
        tracing::info!(%message, "unary_echo");
        Ok(Response::new(EchoResponse { message }))
    }

    async fn server_streaming_echo(
        &self,
        request: Request<EchoRequest>,
    ) -> Result<Response<Self::ServerStreamingEchoStream>, Status> {
        let message = request.into_inner().message;
        tracing::info!(%message, "server_streaming_echo");

        let messages: Vec<_> = message
            .split_whitespace()
            .map(|word| {
                Ok(EchoResponse {
                    message: word.to_owned(),
                })
            })
            .collect();

        Ok(Response::new(rama::stream::iter(messages)))
    }
}
