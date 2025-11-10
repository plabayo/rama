use rama::{
    error::{ErrorContext as _, OpaqueError},
    extensions::ExtensionsMut,
    http::{
        Body, Method, Request, Uri, Version, conn::TargetHttpVersion,
        proto::h1::headers::original::OriginalHttp1Headers,
    },
};

use super::SendCommand;

pub(super) fn build(cfg: &SendCommand) -> Result<Request, OpaqueError> {
    let mut request = Request::new(Body::empty());

    // TODO support data input

    let uri: Uri = expand_url(&cfg.uri)
        .parse()
        .context("parse uri as http URI")?;
    *request.uri_mut() = uri;

    if let Some(http_version) = match (
        cfg.http_09,
        cfg.http_10,
        cfg.http_11,
        cfg.http_2,
        cfg.http_3,
    ) {
        (true, false, false, false, false) => Some(Version::HTTP_09),
        (false, true, false, false, false) => Some(Version::HTTP_10),
        (false, false, true, false, false) => Some(Version::HTTP_11),
        (false, false, false, true, false) => Some(Version::HTTP_2),
        (false, false, false, false, true) => Some(Version::HTTP_3),
        (false, false, false, false, false) => None,
        _ => Err(OpaqueError::from_display(
            "--http0.9, --http1.0, --http1.1, --http2, --http3 are mutually exclusive",
        ))?,
    } {
        *request.version_mut() = http_version;
        request
            .extensions_mut()
            .insert(TargetHttpVersion(http_version));
    }

    *request.method_mut() = if let Some(ref method) = cfg.request {
        method
            .trim()
            .to_uppercase()
            .parse()
            .context("parse HTTP request method")?
    } else if cfg
        .data
        .as_ref()
        .map(|v| v.iter().any(|d| !d.is_empty()))
        .unwrap_or_default()
    {
        Method::POST
    } else {
        Method::GET
    };

    for header in &cfg.header {
        request
            .headers_mut()
            .insert(header.name.header_name().clone(), header.value.clone());
    }
    request
        .extensions_mut()
        .insert(OriginalHttp1Headers::from_iter(
            cfg.header.iter().map(|header| header.name.clone()),
        ));

    Ok(request)
}

/// Expand a URL string to a full URL,
/// e.g. `example.com` -> `http://example.com`
fn expand_url(url: &str) -> String {
    if url.is_empty() {
        "http://localhost".to_owned()
    } else if let Some(stripped_url) = url.strip_prefix(':') {
        if stripped_url.is_empty() {
            "http://localhost".to_owned()
        } else if stripped_url
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or_default()
        {
            format!("http://localhost{url}")
        } else {
            format!("http://localhost{stripped_url}")
        }
    } else if !url.contains("://") {
        format!("http://{url}")
    } else {
        url.to_owned()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_expand_url() {
        for (url, expected) in [
            ("example.com", "http://example.com"),
            ("http://example.com", "http://example.com"),
            ("https://example.com", "https://example.com"),
            ("example.com:8080", "http://example.com:8080"),
            (":8080/foo", "http://localhost:8080/foo"),
            (":8080", "http://localhost:8080"),
            ("", "http://localhost"),
        ] {
            assert_eq!(expand_url(url), expected);
        }
    }
}
