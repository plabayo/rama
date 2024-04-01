mod test_server;

#[tokio::test]
async fn test_get_http_conn_state() -> Result<(), reqwest::Error> {
    let _example = test_server::run_example_server("http_conn_state", 40002);
    for i in 1..3 {
        let get = reqwest::get("http://127.0.0.1:40002/").await?;
        let is_alive = "yes";
        let conn_index = i;
        let conn_count = i;
        let request_count = 1;
        let str = format!(
            r##"
            <html>
                <head>
                    <title>Rama — Http Conn State</title>
                </head>
                <body>
                    <h1>Metrics</h1>
                    <p>Alive: {is_alive}
                    <p>Connection <code>{conn_index}</code> of <code>{conn_count}</code></p>
                    <p>Request Count: <code>{request_count}</code></p>
                </body>
            </html>"##
        );
        assert_eq!(get.text().await?, str);
    }


    Ok(())
}

