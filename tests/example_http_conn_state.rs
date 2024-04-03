mod test_server;

use rama::{error::BoxError, http::Request};

use crate::test_server::recive_as_string;

#[tokio::test]
async fn test_http_conn_state() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_conn_state");

    let get_request = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:40000/")
        .body(String::new())
        .unwrap();

    let (_, res_str) = recive_as_string(get_request).await?;
    let head = r##"
            <html>
                <head>
                    <title>Rama — Http Conn State</title>
                </head>
                <body>
                    <h1>Metrics</h1>
                    <p>Alive: yes
                    <p>Connection <code>"##;
    let bottom = r##"</code> of <code>2</code></p>
                    <p>Request Count: <code>1</code></p>
                </body>
            </html>"##;
    
    
    let test1_str = format!("{}{}{}", head, 1, bottom);
    let test2_str = format!("{}{}{}", head, 2, bottom);
    match res_str{
        str if str == test1_str || str == test2_str => {},
        _ => panic!(),
    }

    Ok(())
}
