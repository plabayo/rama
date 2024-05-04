use std::process::Child;

use rama::{
    error::BoxError,
    http::{
        client::HttpClient,
        layer::{
            decompression::DecompressionLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
        },
        Request, Response,
    },
    service::{util::backoff::ExponentialBackoff, BoxService, Service, ServiceBuilder},
};

pub struct ExampleServer(Child);

impl std::ops::Drop for ExampleServer {
    fn drop(&mut self) {
        let Ok(_) = self.0.kill() else {
            println!("faild kill a process. ");
            return;
        };
    }
}

pub fn run_example_server(example_name: &str) -> ExampleServer {
    ExampleServer(
        escargot::CargoBuild::new()
            .arg("--all-features")
            .example(example_name)
            .manifest_path("Cargo.toml")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .spawn()
            .unwrap(),
    )
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, rama::error::BoxError>
where
    E: Into<rama::error::BoxError>,
    Body: rama::http::dep::http_body::Body<Data = bytes::Bytes> + Send + Sync + 'static,
    Body::Error: Into<BoxError>,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}

pub fn client<S>() -> BoxService<S, Request, Response, BoxError>
where
    S: Send + Sync + 'static,
{
    ServiceBuilder::new()
        .map_result(map_internal_client_error)
        .layer(TraceLayer::new_for_http())
        .layer(DecompressionLayer::new())
        .layer(RetryLayer::new(
            ManagedPolicy::default().with_backoff(ExponentialBackoff::default()),
        ))
        .service(HttpClient::new())
        .boxed()
}
