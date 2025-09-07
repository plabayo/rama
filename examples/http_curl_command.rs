//! This example demonstrates how to use the http curl command
//!
//! ```sh
//! cargo run --example http_curl_command --features=compression,http-full
//! ```
//!
//! # Expected output
//!
//! EVENTUALLY, you should see two outputs - one being an outputted CURL command, and the other being the response from the server once the curl command is executed. 
//! As of now, this is a driver program for issue #509, and is being used for development purposes.

// rama provides everything out of the box to build a complete web service.

use rama::http::Request;
use rama::http::request_headers_to_curl_command;

#[tokio::main]
async fn main() {
    let req = Request::builder().uri("http://example.com").header("accept", "application/json").body("testing").unwrap();   
    let curl_command = request_headers_to_curl_command(req).unwrap();
    println!("request: {:?}", curl_command);
}