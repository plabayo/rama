use std::pin::Pin;

use rama::{
    futures::stream::{self, Stream},
    http::grpc::{Request, Response, Status, Streaming},
    stream::StreamExt,
    telemetry::tracing,
};

use pb::{Input, Output, test_server::Test};

pub mod pb {
    rama::http::grpc::include_proto!("web");
}

mod grpc;
mod grpc_web;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + Sync + 'static>>;
pub struct Svc;

impl Test for Svc {
    async fn unary_call(&self, req: Request<Input>) -> Result<Response<Output>, Status> {
        let req = req.into_inner();

        tracing::info!("{req:?}");

        if &req.desc == "boom" {
            Err(Status::invalid_argument("invalid boom"))
        } else {
            Ok(Response::new(Output {
                id: req.id,
                desc: req.desc,
            }))
        }
    }

    type ServerStreamStream = BoxStream<Output>;

    async fn server_stream(
        &self,
        req: Request<Input>,
    ) -> Result<Response<Self::ServerStreamStream>, Status> {
        let req = req.into_inner();

        Ok(Response::new(Box::pin(stream::iter(vec![1, 2]).map(
            move |n| {
                Ok(Output {
                    id: req.id,
                    desc: format!("{}-{}", n, req.desc),
                })
            },
        ))))
    }

    async fn client_stream(
        &self,
        req: Request<Streaming<Input>>,
    ) -> Result<Response<Output>, Status> {
        let out = Output {
            id: 0,
            desc: "".into(),
        };

        Ok(Response::new(
            req.into_inner()
                .fold(out, |mut acc, input| {
                    let input = input.unwrap();
                    acc.id += input.id;
                    acc.desc += &input.desc;
                    acc
                })
                .await,
        ))
    }
}

pub mod util {
    pub mod base64 {
        use base64::{
            alphabet,
            engine::{
                DecodePaddingMode,
                general_purpose::{GeneralPurpose, GeneralPurposeConfig},
            },
        };

        pub const STANDARD: GeneralPurpose = GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new()
                .with_encode_padding(true)
                .with_decode_padding_mode(DecodePaddingMode::Indifferent),
        );
    }
}
