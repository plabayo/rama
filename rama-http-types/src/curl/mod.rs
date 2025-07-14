use http::{HeaderMap, HeaderValue, Method, Request, Uri, Version};
use rama_error::OpaqueError;

// TODO: make sealed(private) trait, and add sealed(private) impl for Request<T>
pub trait IntoCurlHeadersCommand {
    fn to_curl_command(&self) -> Result<String, OpaqueError>;
}

impl<T> IntoCurlHeadersCommand for Request<T> {
    fn to_curl_command(&self) -> Result<String, OpaqueError> {
        let method = self.method();
        let uri = self.uri();
        let version = self.version();
        let headers = self.headers();

        generate_curl_command(method, uri, version, headers)
    }
}

pub fn request_headers_to_curl_command(request: impl IntoCurlHeadersCommand) -> Result<String, OpaqueError> {
    request.to_curl_command()
}

fn generate_curl_command(method: &Method, uri: &Uri, version: Version, headers: &HeaderMap<HeaderValue>) -> Result<String, OpaqueError>{
    let mut cmd = format!("curl -X {} '{}'", method, uri);

    match version {
        Version::HTTP_09 => cmd.push_str(" --http0.9"),
        Version::HTTP_10 => cmd.push_str(" --http1.0"),
        Version::HTTP_11 => cmd.push_str(" --http1.1"),
        Version::HTTP_2 => cmd.push_str(" --http2"),
        Version::HTTP_3 => cmd.push_str(" --http3"),
        _ => panic!("Unexpected HTTP version!"),
    }

    for (name, value) in headers.iter() {
        let val = match value.to_str() {
            Ok(s) => s,
            Err(_) => continue, // skip invalid UTF-8 headers
        };
        cmd.push_str(&format!(r#" -H "{}: {}""#, name.as_str(), val));
    }

    Ok(cmd)
}