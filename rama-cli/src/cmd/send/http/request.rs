use rama::{
    bytes::Bytes,
    error::{ErrorContext as _, OpaqueError},
    extensions::ExtensionsMut,
    futures::{StreamExt, stream},
    http::{
        Body, Method, Request, Uri, Version,
        conn::TargetHttpVersion,
        headers::{ContentType, HeaderMapExt},
        proto::h1::headers::original::OriginalHttp1Headers,
    },
    net::mode::{ConnectIpMode, DnsResolveIpMode},
    stream::io::ReaderStream,
    utils::str::NATIVE_NEWLINE,
};

use super::SendCommand;

pub(super) async fn build(cfg: &SendCommand, is_ws: bool) -> Result<Request, OpaqueError> {
    let mut request = Request::new(Body::empty());

    let input = build_data_input(cfg).await?;
    if input.is_some() && is_ws {
        return Err(OpaqueError::from_display("input not allowed in WS mode"));
    }

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
    } else if input.is_some() {
        Method::POST
    } else if is_ws && request.version() == Version::HTTP_2 {
        Method::CONNECT
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

    if cfg.verbose {
        request.extensions_mut().insert(super::client::VerboseLogs);
    }

    match (cfg.ipv4, cfg.ipv6) {
        (true, true) => Err(OpaqueError::from_display(
            "--ipv4, --ipv6 are mutually exclusive",
        ))?,
        (true, false) => {
            request
                .extensions_mut()
                .insert(DnsResolveIpMode::SingleIpV4);
            request.extensions_mut().insert(ConnectIpMode::Ipv4);
        }
        (false, true) => {
            request
                .extensions_mut()
                .insert(DnsResolveIpMode::SingleIpV6);
            request.extensions_mut().insert(ConnectIpMode::Ipv6);
        }
        (false, false) => (), // allow both ipv4 and ipv6, nothing to do this is the default
    }

    if let Some((body, ct)) = input {
        request.headers_mut().typed_insert(ct);
        *request.body_mut() = body;
    }

    Ok(request)
}

async fn build_data_input(cfg: &SendCommand) -> Result<Option<(Body, ContentType)>, OpaqueError> {
    let (ct, separator) = match (cfg.binary, cfg.json) {
        (true, false) => (ContentType::octet_stream(), None),
        (false, true) => (ContentType::json(), Some(NATIVE_NEWLINE)),
        (false, false) => (ContentType::form_url_encoded(), Some("&")),
        _ => Err(OpaqueError::from_display(
            "--binary, --json are mutually exclusive",
        ))?,
    };

    let Some(data) = cfg.data.as_deref() else {
        return Ok(None);
    };
    if data.is_empty() {
        return Ok(None);
    }

    let mut stream = stream::empty().boxed();

    for (index, data) in data.iter().enumerate() {
        if index > 0
            && let Some(separator) = separator
        {
            let b = Bytes::from_static(separator.as_bytes());
            stream = stream
                .chain(stream::once(async move { Ok(b) }).boxed())
                .boxed();
        }
        if let Some(fin) = data.strip_prefix('@') {
            let fin = fin.trim_end();
            if fin == "-" {
                stream = stream
                    .chain(ReaderStream::new(tokio::io::stdin()).boxed())
                    .boxed()
            } else {
                stream = stream
                    .chain(
                        ReaderStream::new(
                            tokio::fs::OpenOptions::new()
                                .read(true)
                                .open(fin)
                                .await
                                .context(format!("read input file: {fin}"))?,
                        )
                        .boxed(),
                    )
                    .boxed();
            }
        } else {
            let b = Bytes::copy_from_slice(data.as_bytes());
            stream = stream
                .chain(stream::once(async move { Ok(b) }).boxed())
                .boxed();
        }
    }

    let body = Body::from_stream(stream);

    Ok(Some((body, ct)))
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
