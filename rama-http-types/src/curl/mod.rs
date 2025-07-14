
use http::Request;
use rama_error::OpaqueError;

pub fn request_headers_to_curl_command(request: Request<()>) -> Result<String, OpaqueError> {
    println!("request: {:?}", request);
    Ok("".to_string())
}
