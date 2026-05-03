use rama::{
    bytes::Bytes,
    error::{BoxError, ErrorContext as _, ErrorExt, extra::OpaqueError},
    extensions::ExtensionsRef,
    futures::{StreamExt, stream},
    http::{
        Body, HeaderValue, Method, Request, Uri, Version,
        conn::TargetHttpVersion,
        header::{CONTENT_LENGTH, CONTENT_TYPE},
        headers::{ContentType, HeaderMapExt},
        proto::h1::headers::original::OriginalHttp1Headers,
        service::client::multipart,
    },
    net::mode::{ConnectIpMode, DnsResolveIpMode},
    stream::io::ReaderStream,
    utils::str::NATIVE_NEWLINE,
};

use super::SendCommand;

pub(super) async fn build(cfg: &SendCommand, is_ws: bool) -> Result<Request, BoxError> {
    let mut request = Request::new(Body::empty());

    let input = build_data_input(cfg).await?;
    if input.is_some() && is_ws {
        return Err(OpaqueError::from_static_str("input not allowed in WS mode").into_box_error());
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
        _ => Err(OpaqueError::from_static_str(
            "--http0.9, --http1.0, --http1.1, --http2, --http3 are mutually exclusive",
        ))?,
    } {
        *request.version_mut() = http_version;
        request.extensions().insert(TargetHttpVersion(http_version));
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
    request.extensions().insert(OriginalHttp1Headers::from_iter(
        cfg.header.iter().map(|header| header.name.clone()),
    ));

    if cfg.verbose {
        request.extensions().insert(super::client::VerboseLogs);
    }

    match (cfg.ipv4, cfg.ipv6) {
        (true, true) => Err(OpaqueError::from_static_str(
            "--ipv4, --ipv6 are mutually exclusive",
        ))?,
        (true, false) => {
            request.extensions().insert(DnsResolveIpMode::SingleIpV4);
            request.extensions().insert(ConnectIpMode::Ipv4);
        }
        (false, true) => {
            request.extensions().insert(DnsResolveIpMode::SingleIpV6);
            request.extensions().insert(ConnectIpMode::Ipv6);
        }
        (false, false) => (), // allow both ipv4 and ipv6, nothing to do this is the default
    }

    if let Some(input) = input {
        match input {
            DataInput::Body { body, content_type } => {
                request.headers_mut().typed_insert(content_type);
                *request.body_mut() = body;
            }
            DataInput::Multipart {
                body,
                content_type,
                content_length,
            } => {
                request.headers_mut().insert(CONTENT_TYPE, content_type);
                if let Some(len) = content_length {
                    request
                        .headers_mut()
                        .insert(CONTENT_LENGTH, HeaderValue::from(len));
                } else {
                    // Streaming form — drop any user-supplied
                    // Content-Length so the chunked body isn't shipped with
                    // a stale fixed length.
                    request.headers_mut().remove(CONTENT_LENGTH);
                }
                *request.body_mut() = body;
            }
        }
    }

    Ok(request)
}

enum DataInput {
    Body {
        body: Body,
        content_type: ContentType,
    },
    Multipart {
        body: Body,
        content_type: HeaderValue,
        content_length: Option<u64>,
    },
}

async fn build_data_input(cfg: &SendCommand) -> Result<Option<DataInput>, BoxError> {
    if let Some(specs) = cfg.form_data.as_deref().filter(|v| !v.is_empty()) {
        if cfg.data.is_some() || cfg.json || cfg.binary {
            return Err(OpaqueError::from_static_str(
                "--form-data is mutually exclusive with --data, --json, --binary",
            )
            .into_box_error());
        }
        let mut form = multipart::Form::new();
        for spec in specs {
            form = form
                .with_field_spec(spec)
                .await
                .context("parse --form-data")?;
        }
        let content_type = form.content_type();
        let content_length = form.content_length();
        return Ok(Some(DataInput::Multipart {
            body: form.into_body(),
            content_type,
            content_length,
        }));
    }

    let (ct, separator) = match (cfg.binary, cfg.json) {
        (true, false) => (ContentType::octet_stream(), None),
        (false, true) => (ContentType::json(), Some(NATIVE_NEWLINE)),
        (false, false) => (ContentType::form_url_encoded(), Some("&")),
        _ => Err(OpaqueError::from_static_str(
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

    Ok(Some(DataInput::Body {
        body,
        content_type: ct,
    }))
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
