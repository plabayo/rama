mod test_server;

#[tokio::test]
async fn test_http_listener_hello() -> Result<(), reqwest::Error> {
    let mut _example = test_server::run_example_server("http_listener_hello", 40001);

    let get = reqwest::get("http://127.0.0.1:40001/path").await?;
    assert_eq!(get.text().await?, r#"{"method":"GET","path":"/path"}"#);

    let client = reqwest::Client::new();
    let post = client
        .post("http://127.0.0.1:40001/")
        .body("body")
        .send()
        .await?;
    assert_eq!(post.text().await?, r#"{"method":"POST","path":"/"}"#);

    Ok(())
}
