//! End to end test of a service defined with [`crate::define_service`] and served with a
//! [`super::JsonCodec`]

#![expect(
    unreachable_pub,
    reason = "message types have to be at least as public as the stubs generated from them"
)]

use rama_core::stream;
use rama_net::uri::Uri;
use serde::{Deserialize, Serialize};

use super::{JsonCodec, JsonFormat, SerdeCodec};
use crate::{Request, Response, Status};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoRequest {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoResponse {
    pub message: String,
}

crate::define_service! {
    package = "rama.grpc.test.echo.v1";
    codec = JsonCodec;

    /// Echoes back what it is given.
    service Echo {
        /// Echo a message once.
        rpc UnaryEcho(EchoRequest) -> EchoResponse;
        /// Echo a message once per word it contains.
        rpc ServerStreamingEcho(EchoRequest) -> stream EchoResponse;
    }
}

struct EchoService;

impl echo_server::Echo for EchoService {
    type ServerStreamingEchoStream = stream::Iter<std::vec::IntoIter<Result<EchoResponse, Status>>>;

    async fn unary_echo(
        &self,
        request: Request<EchoRequest>,
    ) -> Result<Response<EchoResponse>, Status> {
        Ok(Response::new(EchoResponse {
            message: request.into_inner().message,
        }))
    }

    async fn server_streaming_echo(
        &self,
        request: Request<EchoRequest>,
    ) -> Result<Response<Self::ServerStreamingEchoStream>, Status> {
        let message = request.into_inner().message;
        let messages: Vec<_> = message
            .split_whitespace()
            .map(|word| {
                Ok(EchoResponse {
                    message: word.to_owned(),
                })
            })
            .collect();
        Ok(Response::new(stream::iter(messages)))
    }
}

fn client() -> echo_client::EchoClient<echo_server::EchoServer<EchoService>> {
    echo_client::EchoClient::new(
        echo_server::EchoServer::new(EchoService),
        Uri::from_static("http://127.0.0.1"),
    )
}

#[tokio::test]
async fn unary_round_trip() {
    let response = client()
        .unary_echo(Request::new(EchoRequest {
            message: "hello rama".to_owned(),
        }))
        .await
        .unwrap();

    assert_eq!(response.into_inner().message, "hello rama");
}

#[tokio::test]
async fn server_streaming_round_trip() {
    let mut stream = client()
        .server_streaming_echo(Request::new(EchoRequest {
            message: "hello rama".to_owned(),
        }))
        .await
        .unwrap()
        .into_inner();

    let mut messages = Vec::new();
    while let Some(response) = stream.message().await.unwrap() {
        messages.push(response.message);
    }

    assert_eq!(messages, ["hello", "rama"]);
}

// The same service, with the codec spelled out instead of going through the [`JsonCodec`]
// alias. A generic codec needs all of its type parameters, so the message types are left
// to be inferred with `_`: `SerdeCodec<JsonFormat>` would not compile.
crate::define_service! {
    package = "rama.grpc.test.generic.v1";
    codec = SerdeCodec<JsonFormat, _, _>;

    service GenericEcho {
        rpc UnaryEcho(EchoRequest) -> EchoResponse;
    }
}

struct GenericEchoService;

impl generic_echo_server::GenericEcho for GenericEchoService {
    async fn unary_echo(
        &self,
        request: Request<EchoRequest>,
    ) -> Result<Response<EchoResponse>, Status> {
        Ok(Response::new(EchoResponse {
            message: request.into_inner().message,
        }))
    }
}

#[tokio::test]
async fn generic_codec_round_trip() {
    let response = generic_echo_client::GenericEchoClient::new(
        generic_echo_server::GenericEchoServer::new(GenericEchoService),
        Uri::from_static("http://127.0.0.1"),
    )
    .unary_echo(Request::new(EchoRequest {
        message: "hello rama".to_owned(),
    }))
    .await
    .unwrap();

    assert_eq!(response.into_inner().message, "hello rama");
}
