use super::utils;
use rama::http::BodyExtractExt;
use rama::http::service::client::multipart::{Form, Part};

#[tokio::test]
#[ignore]
async fn test_example_http_multipart() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_multipart", None);

    let form = Form::new().text("username", "glen").part(
        "attachment",
        Part::bytes(b"hello rama".as_slice())
            .with_file_name("note.txt")
            .with_mime_str("text/plain")
            .unwrap(),
    );

    let response = runner
        .post("http://127.0.0.1:62028/upload")
        .multipart(form)
        .send()
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert!(response.contains("field=username"));
    assert!(response.contains("size=4")); // "glen"
    assert!(response.contains("field=attachment"));
    assert!(response.contains("file_name=Some(\"note.txt\")"));
    assert!(response.contains("size=10")); // "hello rama"
}
