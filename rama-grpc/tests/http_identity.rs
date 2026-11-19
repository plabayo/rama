#![cfg(feature = "protobuf")]

use rama_core::service::service_fn;
use rama_grpc::{client::Grpc, protobuf::ProstCodec};
use rama_http::{Body, Request, Response, header};
use std::convert::Infallible;

#[tokio::test]
async fn grpc_request_uses_the_application_identity() {
    for expected in [header::RAMA_ID_HEADER_VALUE.to_str().unwrap(), "App/1"] {
        if expected == "App/1" {
            header::set_identity(expected).unwrap();
        }
        let client = Grpc::new(
            service_fn(move |req: Request| async move {
                assert_eq!(req.headers()[header::USER_AGENT], expected);
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "7")
                        .body(Body::empty())
                        .unwrap(),
                )
            }),
            "https://example.test".parse().unwrap(),
        );
        let result = client
            .unary(
                rama_grpc::Request::new(()),
                "/pkg.Service/Method",
                ProstCodec::<(), ()>::new(),
            )
            .await;
        assert_eq!(
            result.unwrap_err().code(),
            rama_grpc::Code::PermissionDenied
        );
    }
}
