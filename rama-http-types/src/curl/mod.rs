use crate::{HeaderMap, HeaderValue, Method, Request, Uri, Version, Body};
use http::{Extensions};
use rama_error::OpaqueError;
// use rama_net::address::ProxyAddress;

pub fn request_headers_to_curl_command<B>(request: Request<B>) -> Result<String, OpaqueError> {
    let method = request.method();
    let uri = request.uri();
    let version = request.version();
    let headers = request.headers();
    let extensions = request.extensions();
    
    generate_curl_command(method, uri, version, headers, extensions)
}

pub async fn request_to_curl_command<B: Into<Body>>(request: Request<B>) -> Result<String, OpaqueError> {
    let method: &Method = request.method();
    let uri = request.uri();
    let version = request.version();
    let headers = request.headers();
    let extensions = request.extensions();
    
    let mut cmd = generate_curl_command(method, uri, version, headers, extensions)?;
    

    let b: B = request.body().;
    println!("{:?}", b);
    // grab the bytes, then turn into UTF-8 (lossy avoids errors)
    // let bytes = b.as_ref();
    // let s = String::from_utf8_lossy(bytes);
    // cmd.push_str(&format!(" --data '{}'", s));


    Ok(cmd)
}


fn generate_curl_command(method: &Method, uri: &Uri, version: Version, headers: &HeaderMap<HeaderValue>, extensions: &Extensions) -> Result<String, OpaqueError>{
    let mut cmd = format!("curl -X {} '{}'", method, uri);

    match version {
        Version::HTTP_09 => cmd.push_str(" --http0.9"),
        Version::HTTP_10 => cmd.push_str(" --http1.0"),
        Version::HTTP_11 => cmd.push_str(" --http1.1"),
        Version::HTTP_2 => cmd.push_str(" --http2"),
        Version::HTTP_3 => cmd.push_str(" --http3"),
        _ => {return Err(OpaqueError::from_display("Unexpected HTTP version!"))},
    }

    for (name, value) in headers.iter() {
        let val = match value.to_str() {
            Ok(s) => s,
            Err(_) => continue, // skip invalid UTF-8 headers
        };
        cmd.push_str(&format!(r#" -H '{}: {}'"#, name.as_str(), val));
    }

    // if let Some(proxy) = extensions.get::<ProxyAddress>() {
    //     cmd.push_str(&format!(" --proxy '{}'", proxy.as_str()));
    // }

    Ok(cmd)
}