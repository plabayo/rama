use std::process::Child;

use http::response::Parts;
use http_body_util::BodyExt;
use rama::{
    error::BoxError,
    http::{client::HttpClient, Request},
    service::{Context, Service},
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
    let temp = assert_fs::TempDir::new().unwrap();
    ExampleServer(
        escargot::CargoBuild::new()
            .arg("--all-features")
            .example(example_name)
            .manifest_path("Cargo.toml")
            .target_dir(temp.path())
            .run()
            .unwrap()
            .command()
            .spawn()
            .unwrap(),
    )
}

pub async fn recive_as_string(request: Request<String>) -> Result<(Parts, String), BoxError> {
    let client = HttpClient::new();
    let res = client.serve(Context::default(), request).await?;

    let (parts, res_body) = res.into_parts();
    let collected_bytes = res_body.collect().await?;
    let bytes = collected_bytes.to_bytes();
    let res_str = String::from_utf8_lossy(&bytes);
    Ok((parts, res_str.to_string()))
}


