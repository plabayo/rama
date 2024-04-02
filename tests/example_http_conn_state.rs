mod test_server;

use rama::{error::BoxError, http::Request};

use crate::test_server::recive_as_string;

#[tokio::test]
async fn test_http_conn_state() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_conn_state");

    let get_request = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:40002/")
        .body(String::new())
        .unwrap();

    let res_str = recive_as_string(get_request).await?;
    let test_str = format!(
        r##"
            <html>
                <head>
                    <title>Rama — Http Conn State</title>
                </head>
                <body>
                    <h1>Metrics</h1>
                    <p>Alive: yes
                    <p>Connection <code>2</code> of <code>2</code></p>
                    <p>Request Count: <code>1</code></p>
                </body>
            </html>"##
    );
    assert_eq!(res_str, test_str);

    Ok(())
}
