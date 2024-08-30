use super::utils;
use rama::{http::BodyExtractExt, service::Context};
use serde::Serialize;

#[tokio::test]
#[ignore]
async fn test_example_http_form() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_form");

    #[derive(Serialize)]
    struct Data {
        name: &'static str,
        age: i32,
    }

    let response = runner
        .post("http://127.0.0.1:62002/form")
        .form(&Data {
            name: "John",
            age: 32,
        })
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!("John is 32 years old.", response);
}
