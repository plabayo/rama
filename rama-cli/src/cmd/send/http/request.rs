use rama::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt, ErrorContext as _},
    extensions::ExtensionsRef,
    futures::{StreamExt, stream},
    http::{
        Body, HeaderValue, Method, Request, StreamingBody, Version,
        conn::TargetHttpVersion,
        header::{ALT_USED, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT},
        headers::{ContentType, HeaderMapExt},
        service::client::multipart,
    },
    net::{
        Protocol,
        mode::{ConnectIpMode, DnsResolveIpMode},
    },
    stream::io::ReaderStream,
    ua::profile::{
        format::canonical::ValueId,
        model::runtime_hints::RequestInitiator,
        selection::variants::{VariantPins, bootstrap::ConnectionBootstrapRequest},
    },
    utils::str::NATIVE_NEWLINE,
};

use super::{SendCommand, WarmupRequest};
use crate::cmd::send::{EmulationProfiles, arg::EmulationHex};

pub(super) async fn build(cfg: &SendCommand, is_ws: bool) -> Result<Request, BoxError> {
    let mut request = Request::new(Body::empty());

    let initiator = cfg
        .emulate_initiator
        .or_else(|| (is_ws && cfg.emulate.is_some()).then_some(RequestInitiator::Ws));
    if let Some(initiator) = initiator {
        if is_ws != matches!(initiator, RequestInitiator::Ws) {
            return Err(BoxError::from_static_str(
                "WebSocket emulation requires a ws flow and a ws:// or wss:// URI",
            ));
        }
        request.extensions().insert(initiator);
    }

    let input = build_data_input(cfg).await?;
    if input.is_some() && is_ws {
        return Err(BoxError::from_static_str("input not allowed in WS mode"));
    }

    *request.uri_mut() = crate::cmd::uri::parse_user_uri(&cfg.uri)?;
    if is_ws && cfg.http_3 && !request.uri().scheme().is_some_and(Protocol::is_secure) {
        return Err(BoxError::from_static_str(
            "WebSocket over HTTP/3 requires a wss:// URI (HTTP/3 always uses TLS)",
        ));
    }

    apply_preferences(cfg, &mut request)?;

    *request.method_mut() = if let Some(ref method) = cfg.request {
        method
            .trim()
            .to_uppercase()
            .parse()
            .context("parse HTTP request method")?
    } else if input.is_some() {
        Method::POST
    } else if is_ws && matches!(request.version(), Version::HTTP_2 | Version::HTTP_3) {
        // Extended CONNECT: RFC 8441 (HTTP/2) and RFC 9220 (HTTP/3).
        Method::CONNECT
    } else {
        Method::GET
    };

    for header in &cfg.header {
        request
            .headers_mut()
            .append(header.name.clone(), header.value.clone());
    }
    if let Some(input) = input {
        match input {
            DataInput::Body { body, content_type } => {
                if !request.headers().contains_key(CONTENT_TYPE) {
                    request.headers_mut().typed_insert(content_type);
                }
                // Re-sync Content-Length with the body we're about to
                // ship. Pure in-memory `--data` items take the fast path
                // in `build_data_input` and arrive here as a sized
                // `Body::from(Vec<u8>)` whose `size_hint` is exact;
                // stdin/file-backed mixes arrive as a `Body::from_stream`
                // with unknown length, in which case we drop any pre-set
                // CL header so we don't ship stale framing.
                if let Some(len) = body.size_hint().exact() {
                    request
                        .headers_mut()
                        .insert(CONTENT_LENGTH, HeaderValue::from(len));
                } else {
                    request.headers_mut().remove(CONTENT_LENGTH);
                }
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

/// Apply the command's transport preferences to an independently built request.
pub(super) fn apply_preferences(cfg: &SendCommand, request: &mut Request) -> Result<(), BoxError> {
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
        _ => Err(BoxError::from_static_str(
            "--http0.9, --http1.0, --http1.1, --http2, --http3 are mutually exclusive",
        ))?,
    } {
        *request.version_mut() = http_version;
        request.extensions().insert(TargetHttpVersion(http_version));
    }

    if cfg.verbose {
        request.extensions().insert(super::client::VerboseLogs);
    }

    match (cfg.ipv4, cfg.ipv6) {
        (true, true) => Err(BoxError::from_static_str(
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

    Ok(())
}

/// Build the preliminary navigation without copying the main body or credentials.
/// Retain explicit User-Agent selection and Alt-Used route metadata on both operations.
pub(super) fn warmup(
    cfg: &SendCommand,
    request: &Request,
    variant: EmulationHex,
) -> Result<Request, BoxError> {
    if !cfg.http_3
        || !matches!(&cfg.emulate, Some(EmulationProfiles::File(_)))
        || !request.uri().scheme().is_some_and(Protocol::is_secure)
    {
        return Err(BoxError::from_static_str(
            "connection warmup requires a captured archive and explicit secure HTTP/3",
        ));
    }
    let authority = request
        .uri()
        .authority()
        .context("warmup origin authority")?;
    let mut warmup = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{authority}/"))
        .version(Version::HTTP_3)
        .body(Body::empty())?;
    // Keep the caller's profile selector and current route, without other headers.
    if let Some(user_agent) = request.headers().get(USER_AGENT) {
        warmup.headers_mut().insert(USER_AGENT, user_agent.clone());
    }
    for value in request.headers().get_all(ALT_USED) {
        warmup.headers_mut().append(ALT_USED, value.clone());
    }
    // Preserve routing/security preferences, replacing only this operation's UA pins.
    warmup.extensions().extend(request.extensions());
    warmup
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_3));
    warmup.extensions().insert(RequestInitiator::Navigate);
    warmup.extensions().insert(VariantPins {
        connection: Some(ValueId(variant.0)),
        request: None,
    });
    warmup.extensions().insert(WarmupRequest);
    warmup
        .extensions()
        .insert(ConnectionBootstrapRequest::new());
    Ok(warmup)
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
            return Err(BoxError::from_static_str(
                "--form-data is mutually exclusive with --data, --json, --binary",
            ));
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
        _ => Err(BoxError::from_static_str(
            "--binary, --json are mutually exclusive",
        ))?,
    };

    let Some(data) = cfg.data.as_deref() else {
        return Ok(None);
    };
    if data.is_empty() {
        return Ok(None);
    }

    // Fast path: when every `--data` item is a literal (no `@file` or
    // `@-` references), concatenate into a single `Bytes` and ship as a
    // sized body. This lets the request advertise an exact
    // `Content-Length` and avoids chunked transfer for the common case.
    if data.iter().all(|d| !d.starts_with('@')) {
        let mut buf = Vec::new();
        for (index, item) in data.iter().enumerate() {
            if index > 0
                && let Some(separator) = separator
            {
                buf.extend_from_slice(separator.as_bytes());
            }
            buf.extend_from_slice(item.as_bytes());
        }
        return Ok(Some(DataInput::Body {
            body: Body::from(buf),
            content_type: ct,
        }));
    }

    // Slow path: at least one `@file` / `@-` source is present; we don't
    // know the total size up-front, so stream the data.
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
                            tokio::fs::File::open(fin)
                                .await
                                .context("read input file")
                                .context_str_field("path", fin)?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Parser, error::ErrorKind};

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        cfg: SendCommand,
    }

    fn config(args: &[&str]) -> SendCommand {
        TestCli::try_parse_from(
            ["rama-request-test"]
                .into_iter()
                .chain(args.iter().copied())
                .chain(["http://example.test/body"]),
        )
        .unwrap()
        .cfg
    }

    #[test]
    fn warmup_arguments_require_h3_and_the_main_connection_pin() {
        assert!(config(&[]).emulate_warmup_connection_variants.is_empty());
        let hex = "00".repeat(32);
        let next = "01".repeat(32);
        for (http3, main_pin) in [(true, true), (false, true), (true, false)] {
            let mut arguments = vec![
                "rama-request-test",
                "--emulate=profile.json",
                "--emulate-seed",
                &hex,
                "--emulate-connection-key",
                &hex,
                "--emulate-request-key",
                &hex,
                "--emulate-warmup-connection-variant",
                &hex,
            ];
            if http3 {
                arguments.push("--http3");
            }
            if main_pin {
                arguments.extend(["--emulate-connection-variant", &hex]);
            }
            arguments.extend(["--emulate-warmup-connection-variant", &next]);
            arguments.push("https://example.test/");
            let parsed = TestCli::try_parse_from(arguments);
            if http3 && main_pin {
                assert_eq!(
                    parsed.unwrap().cfg.emulate_warmup_connection_variants,
                    vec![EmulationHex([0; 32]), EmulationHex([1; 32])]
                );
            } else {
                assert_eq!(
                    parsed.unwrap_err().kind(),
                    ErrorKind::MissingRequiredArgument
                );
            }
        }
    }

    #[tokio::test]
    async fn connection_warmup_is_a_separate_same_origin_navigation() {
        for is_ws in [false, true] {
            let mut arguments = vec![
                "--http3",
                "--header",
                "User-Agent: selected-browser",
                "--header",
                "Authorization: Bearer main-only",
                "--header",
                "Cookie: session=main-only",
            ];
            if !is_ws {
                arguments.extend(["--data", "main body"]);
            }
            let mut cfg = config(&arguments);
            cfg.uri = if is_ws {
                "wss://example.test:8443/api/ws?value=1"
            } else {
                "https://example.test:8443/api/data?value=1"
            }
            .into();
            cfg.emulate = Some(EmulationProfiles::File("profile.json".into()));
            let mut request = build(&cfg, is_ws).await.unwrap();
            request.extensions().insert(VariantPins {
                connection: Some(ValueId([8; 32])),
                request: Some(ValueId([9; 32])),
            });
            let preliminary = warmup(&cfg, &request, EmulationHex([7; 32])).unwrap();

            assert_eq!(preliminary.uri().to_string(), "https://example.test:8443/");
            assert_eq!(preliminary.method(), Method::GET);
            assert_eq!(preliminary.version(), Version::HTTP_3);
            assert_eq!(preliminary.headers().len(), 1);
            assert_eq!(preliminary.headers()[USER_AGENT], "selected-browser");
            assert_eq!(preliminary.body().size_hint().exact(), Some(0));
            assert!(preliminary.extensions().contains::<WarmupRequest>());
            assert!(
                preliminary
                    .extensions()
                    .contains::<ConnectionBootstrapRequest>()
            );
            assert_eq!(
                preliminary
                    .extensions()
                    .get_ref::<VariantPins>()
                    .unwrap()
                    .connection,
                Some(ValueId([7; 32]))
            );
            assert_eq!(
                preliminary.extensions().get_ref::<RequestInitiator>(),
                Some(&RequestInitiator::Navigate)
            );

            assert!(
                preliminary
                    .extensions()
                    .get_ref::<VariantPins>()
                    .unwrap()
                    .request
                    .is_none()
            );
            assert_eq!(
                preliminary.extensions().get_ref::<TargetHttpVersion>(),
                Some(&TargetHttpVersion(Version::HTTP_3))
            );

            // Route metadata is explicit caller input. Retain each value without
            // copying the main body's credentials or inventing an absent route.
            request
                .headers_mut()
                .append(ALT_USED, HeaderValue::from_static("[2001:db8::1]:9443"));
            request
                .headers_mut()
                .append(ALT_USED, HeaderValue::from_static("route.current.test:443"));
            let routed = warmup(&cfg, &request, EmulationHex([7; 32])).unwrap();
            assert_eq!(routed.headers().len(), 3);
            assert_eq!(
                routed.headers().get_all(ALT_USED),
                request.headers().get_all(ALT_USED)
            );
            assert_eq!(routed.body().size_hint().exact(), Some(0));
            assert!(!routed.headers().contains_key("authorization"));
            assert!(!routed.headers().contains_key("cookie"));
            assert_eq!(
                request
                    .extensions()
                    .get_ref::<VariantPins>()
                    .unwrap()
                    .request,
                Some(ValueId([9; 32]))
            );

            assert_eq!(request.headers()["authorization"], "Bearer main-only");
            assert_eq!(request.headers()["cookie"], "session=main-only");
            assert_eq!(
                request.method(),
                if is_ws { Method::CONNECT } else { Method::POST }
            );
            assert_eq!(
                request.body().size_hint().exact(),
                Some(if is_ws { 0 } else { 9 })
            );
            assert!(!request.extensions().contains::<WarmupRequest>());
            if is_ws {
                assert_eq!(
                    request.extensions().get_ref::<RequestInitiator>(),
                    Some(&RequestInitiator::Ws)
                );
            }

            cfg.emulate = Some(EmulationProfiles::Embedded);
            warmup(&cfg, &request, EmulationHex([7; 32])).unwrap_err();
            cfg.emulate = Some(EmulationProfiles::File("profile.json".into()));
            cfg.http_3 = false;
            warmup(&cfg, &request, EmulationHex([7; 32])).unwrap_err();
            cfg.http_3 = true;
            *request.uri_mut() = "http://example.test:8443/".parse().unwrap();
            warmup(&cfg, &request, EmulationHex([7; 32])).unwrap_err();
        }
    }

    #[tokio::test]
    async fn repeated_request_headers_preserve_each_value_in_order() {
        for version in ["--http1.0", "--http1.1", "--http2", "--http3"] {
            for is_ws in [false, true] {
                let mut cfg = config(&[
                    version,
                    "--header",
                    "X-Repeat: first",
                    "--header",
                    "X-Other: between",
                    "--header",
                    "x-repeat: second",
                    "--header",
                    "X-Repeat: third",
                    "--header",
                    "x-other: last",
                ]);
                if is_ws {
                    cfg.uri = "wss://example.test/socket".into();
                }
                let request = build(&cfg, is_ws).await.unwrap();
                for (name, expected) in [
                    ("x-repeat", vec!["first", "second", "third"]),
                    ("x-other", vec!["between", "last"]),
                ] {
                    let actual: Vec<_> = request
                        .headers()
                        .get_all(name)
                        .iter()
                        .map(|value| value.to_str().unwrap())
                        .collect();
                    assert_eq!(actual, expected, "{version}, ws={is_ws}, {name}");
                }
            }
        }
    }

    #[tokio::test]
    async fn request_content_type_explicit_header_survives_data_sources_and_defaults() {
        let directory = rama::utils::fs::tempdir().unwrap();
        let file = directory.path().join("payload");
        tokio::fs::write(&file, b"payload").await.unwrap();
        for input in [
            String::from("payload"),
            format!("@{}", file.display()),
            String::from("@-"),
        ] {
            for shorthand in [None, Some("--json"), Some("--binary")] {
                let mut args = vec![
                    "--data",
                    input.as_str(),
                    "--header",
                    "Content-Type: text/plain;charset=UTF-8",
                    "--header",
                    "Content-Length: 99",
                    "--header",
                    "Content-Length: 100",
                ];
                if let Some(flag) = shorthand {
                    args.push(flag);
                }
                let request = build(&config(&args), false).await.unwrap();
                assert_eq!(request.headers()[CONTENT_TYPE], "text/plain;charset=UTF-8");
                if input.starts_with('@') {
                    assert!(!request.headers().contains_key(CONTENT_LENGTH));
                } else {
                    assert_eq!(request.headers()[CONTENT_LENGTH], "7");
                    assert_eq!(request.headers().get_all(CONTENT_LENGTH).iter().count(), 1);
                }
            }
        }
    }

    #[tokio::test]
    async fn request_content_type_defaults_and_multipart_boundary_remain_generated() {
        for (shorthand, expected) in [
            (None, "application/x-www-form-urlencoded"),
            (Some("--json"), "application/json"),
            (Some("--binary"), "application/octet-stream"),
        ] {
            let mut args = vec!["--data", "payload"];
            if let Some(flag) = shorthand {
                args.push(flag);
            }
            let request = build(&config(&args), false).await.unwrap();
            assert_eq!(request.headers()[CONTENT_TYPE], expected);
        }
        let request = build(
            &config(&[
                "--form-data",
                "field=value",
                "--header",
                "Content-Type: text/plain",
                "--header",
                "Content-Type: application/json",
            ]),
            false,
        )
        .await
        .unwrap();
        assert_eq!(request.headers().get_all(CONTENT_TYPE).iter().count(), 1);
        let content_type = request.headers()[CONTENT_TYPE].to_str().unwrap();
        assert!(
            content_type.starts_with("multipart/form-data; boundary="),
            "{content_type}"
        );
    }
}
