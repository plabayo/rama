//! rama http client

use clap::Args;
use rama::{
    Layer, Service,
    cli::args::RequestArgsBuilder,
    error::{BoxError, ErrorContext, OpaqueError, error},
    extensions::ExtensionsMut,
    graceful::{self, Shutdown, ShutdownGuard},
    http::{
        Request, Response, StatusCode, StreamingBody, Version,
        body::util::BodyExt,
        client::{
            EasyHttpWebClient,
            proxy::layer::{HttpProxyAddressLayer, SetProxyAuthHttpHeaderLayer},
        },
        conn::TargetHttpVersion,
        convert::curl,
        layer::{
            auth::AddAuthorizationLayer,
            decompression::DecompressionLayer,
            follow_redirect::{FollowRedirectLayer, policy::Limited},
            required_header::AddRequiredRequestHeadersLayer,
            timeout::TimeoutLayer,
            traffic_writer::WriterMode,
        },
        service::web::response::IntoResponse,
    },
    layer::{HijackLayer, MapResultLayer},
    net::{
        address::ProxyAddress,
        tls::{KeyLogIntent, client::ServerVerifyMode},
        user::{Basic, Bearer, ProxyCredential},
    },
    rt::Executor,
    service::service_fn,
    telemetry::tracing::level_filters::LevelFilter,
    tls::boring::client::{EmulateTlsProfileLayer, TlsConnectorDataBuilder},
    ua::{
        layer::emulate::{
            UserAgentEmulateHttpConnectModifierLayer, UserAgentEmulateHttpRequestModifier,
            UserAgentEmulateLayer, UserAgentSelectFallback,
        },
        profile::UserAgentDatabase,
    },
};

use std::{io::IsTerminal, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use terminal_prompt::Terminal;
use tokio::sync::oneshot;

mod writer;

#[derive(Args, Debug, Clone)]
/// rama http client
pub struct CliCommandHttp {
    #[arg(required = true)]
    uri: String,

    #[arg(short = 'L', long)]
    /// If the server reports that the requested page has moved to a different location
    /// (indicated with a Location: header and a 3XX response code),
    /// this option makes curl redo the request to the new place.
    /// If used together with --show-headers, headers from all requested pages are shown.
    ///
    /// Limit the amount of redirects to follow by using the --max-redirs option.
    location: bool,

    #[arg(long, default_value_t = 50)]
    /// the maximum number of redirects to follow (set to -1 to put no limit)
    max_redirs: isize,

    #[arg(long, short = 'X')]
    /// Change the method to use when starting the transfer.
    request: Option<String>,

    #[arg(long, short = 'x')]
    /// upstream proxy to use (can also be specified using PROXY env variable)
    proxy: Option<String>,

    #[arg(long, short = 'U')]
    /// upstream proxy user credentials to use (or overwrite)
    proxy_user: Option<String>,

    #[arg(long, short = 'u')]
    /// client authentication: `USER[:PASS]` | TOKEN,
    /// if basic and no password is given it will be promped
    user: Option<String>,

    #[arg(short = 'k', long)]
    /// skip Tls certificate verification
    insecure: bool,

    #[arg(long)]
    /// the desired tls version to use (automatically defined by default, choices are: 1.0, 1.1, 1.2 and 1.3)
    tls_max: Option<String>,

    #[arg(long, default_value_t = false)]
    /// Force rama to use TLS version 1.0 or later when connecting to a remote TLS server.
    tls_v10: bool,

    #[arg(long, default_value_t = false)]
    /// Force rama to use TLS version 1.1 or later when connecting to a remote TLS server.
    tls_v11: bool,

    #[arg(long, default_value_t = false)]
    /// Force rama to use TLS version 1.2 or later when connecting to a remote TLS server.
    tls_v12: bool,

    #[arg(long, default_value_t = false)]
    /// Force rama to use TLS version 1.3 or later when connecting to a remote TLS server.
    tls_v13: bool,

    #[arg(long)]
    /// the client tls key file path to use
    cert_key: Option<PathBuf>,

    #[arg(long, short = 'm')]
    /// Set the maximum time in seconds that you allow each transfer to take.
    /// Prevents your batch jobs from hanging for hours due to slow networks or links going down.
    ///
    /// This option accepts decimal values.
    max_time: Option<f64>,

    #[arg(long)]
    /// Maximum time in seconds that you allow rama's connection to take.
    /// This only limits the connection phase, so if rama connects within the given period it continues -
    /// if not it exits.
    ///
    /// This option accepts decimal values
    ///  The decimal value needs to be provided using a dot (.) as decimal separator -
    /// not the local version even if it might be using another separator.
    ///
    /// The connection phase is considered complete when the DNS lookup and requested TCP,
    /// TLS or QUIC handshakes are done.
    connect_timeout: Option<f64>,

    #[arg(short = 'i', long)]
    /// Show response headers in the output. HTTP response headers can include
    /// things like server name, cookies, date of the document, HTTP version and more.
    ///
    /// For request headers use the `-v` / `--verbose` flag.
    show_headers: bool,

    #[arg(short = 'v', long)]
    /// print verbose output, alias for --all --print hHbB
    verbose: bool,

    #[arg(long)]
    /// do not send request but instead print equivalent curl command
    curl: bool,

    #[arg(long, short = 'o')]
    /// Write output to the given file instead of stdout
    output: Option<String>,

    #[arg(long)]
    /// emulate the provided user-agent
    ///
    /// (or a random one if no user-agent header is defined)
    emulate: bool,

    #[arg(long = "http0.9")]
    /// force http_version to http/0.9
    ///
    /// Mutually exclusive with --http1.0, --http1.1, --http2, --http3
    http_09: bool,

    #[arg(long = "http1.0")]
    /// force http_version to http/1.0
    ///
    /// Mutually exclusive with --http1.0, --http1.1, --http2, --http3
    http_10: bool,

    #[arg(long = "http1.1")]
    /// force http_version to http/1.1
    ///
    /// Mutually exclusive with --http0.9, --http1.0, --http2, --http3
    http_11: bool,

    #[arg(long = "http2")]
    /// force http_version to http/2
    ///
    /// Mutually exclusive with --http0.9, --http1.0, --http1.1, --http3
    http_2: bool,

    #[arg(long = "http3")]
    /// force http_version to http/3
    ///
    /// Mutually exclusive with --http0.9, --http1.0, --http1.1, --http2
    http_3: bool,

    #[arg(long, short = 'H')]
    /// Extra header to include in information sent.
    /// When used within an HTTP request, it is added to the regular request headers.
    ///
    /// Some HTTP-based protocols such as websocket will add the
    /// headers required for that protocol automatically if not yet defined.
    header: Vec<String>,

    #[arg(long, short = 'H')]
    /// Extra header to include in the request when sending HTTP to a proxy.
    ///
    /// You may specify any number of extra headers.
    /// This is the equivalent option to --header but is for proxy communication
    /// only like in CONNECT requests when you want a separate header sent to the proxy
    /// to what is sent to the actual remote host.
    proxy_header: Vec<String>,

    /// Output trace output to the given file.
    trace: Option<PathBuf>,
}

// TODO in future:
// - http sessions (e.g. cookies)
// - fix bug in body print (we seem to print garbage)
//    - this might to do with fact that decompressor comes later

/// Run the HTTP client command.
pub async fn run(cfg: CliCommandHttp) -> Result<(), BoxError> {
    crate::trace::init_tracing(if cfg.debug {
        if cfg.verbose {
            LevelFilter::TRACE
        } else {
            LevelFilter::DEBUG
        }
    } else {
        LevelFilter::ERROR
    });

    let (tx, rx) = oneshot::channel();
    let (tx_final, rx_final) = oneshot::channel();

    let shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = graceful::default_signal() => {
                let _ = tx_final.send(Ok(()));
            }
            result = rx => {
                match result {
                    Ok(result) => {
                        let _ = tx_final.send(result);
                    }
                    Err(_) => {
                        let _ = tx_final.send(Ok(()));
                    }
                }
            }
        }
    });

    shutdown.spawn_task_fn(async move |guard| {
        let result = run_inner(guard, cfg).await;
        let _ = tx.send(result);
    });

    let _ = shutdown.shutdown_with_limit(Duration::from_secs(1)).await;

    rx_final.await?
}

async fn run_inner(guard: ShutdownGuard, cfg: CliCommandHttp) -> Result<(), BoxError> {
    let mut request_args_builder = if cfg.json {
        RequestArgsBuilder::new_json()
    } else if cfg.form {
        RequestArgsBuilder::new_form()
    } else {
        RequestArgsBuilder::new()
    };

    for arg in cfg.args.clone() {
        request_args_builder.parse_arg(arg);
    }

    let mut request = request_args_builder.build()?;

    let client = create_client(guard, cfg.clone()).await?;

    let forced_version = match (
        cfg.http_09,
        cfg.http_10,
        cfg.http_11,
        cfg.http_2,
        cfg.http_3,
    ) {
        (true, false, false, false, false) => Some(TargetHttpVersion(Version::HTTP_09)),
        (false, true, false, false, false) => Some(TargetHttpVersion(Version::HTTP_10)),
        (false, false, true, false, false) => Some(TargetHttpVersion(Version::HTTP_11)),
        (false, false, false, true, false) => Some(TargetHttpVersion(Version::HTTP_2)),
        (false, false, false, false, true) => Some(TargetHttpVersion(Version::HTTP_3)),
        (false, false, false, false, false) => None,
        _ => Err(OpaqueError::from_display(
            "--http0.9, --http1.0, --http1.1, --http2, --http3 are mutually exclusive",
        )
        .into_boxed())?,
    };

    if let Some(forced_version) = forced_version {
        request.extensions_mut().insert(forced_version);
    }

    let response = client.serve(request).await?;

    if cfg.check_status {
        let status = response.status();
        if status.is_client_error() {
            // TODO: we need ability to inject data (eg OS exit code) into errors, some kind of extensions,
            // because wrapping with an error and than trying `downcast_ref` does not work,
            // it just falls through, and calling `source` first is unreliable...
            return Err(
                OpaqueError::from_display(format!("client http error, status: {status}"))
                    .into_boxed(),
            );
        } else if status.is_server_error() {
            return Err(
                OpaqueError::from_display(format!("server http error, status: {status}"))
                    .into_boxed(),
            );
        }
    }

    Ok(())
}

async fn create_client(
    guard: ShutdownGuard,
    mut cfg: CliCommandHttp,
) -> Result<impl Service<Request, Response = Response, Error = BoxError>, BoxError> {
    let (request_writer_mode, response_writer_mode) = if cfg.curl {
        cfg.all = false;
        cfg.verbose = false;
        (None, None)
    } else if cfg.verbose {
        cfg.all = true;
        (Some(WriterMode::All), Some(WriterMode::All))
    } else if cfg.body {
        if cfg.headers {
            (None, Some(WriterMode::All))
        } else {
            (None, Some(WriterMode::Body))
        }
    } else if cfg.headers {
        (None, Some(WriterMode::Headers))
    } else {
        match &cfg.print {
            Some(mode) => parse_print_mode(mode)
                .map_err(OpaqueError::from_boxed)
                .context("parse CLI print option")?,
            None => {
                if std::io::stdout().is_terminal() {
                    (None, Some(WriterMode::All))
                } else {
                    (None, Some(WriterMode::Body))
                }
            }
        }
    };

    let writer_kind = match cfg.output.take() {
        Some(path) => writer::WriterKind::File(path.into()),
        None => writer::WriterKind::Stdout,
    };

    let executor = Executor::graceful(guard);
    let (request_writer, response_writer) = writer::create_traffic_writers(
        &executor,
        writer_kind,
        cfg.all,
        request_writer_mode,
        response_writer_mode,
    )
    .await?;

    let mut tls_config = if cfg.emulate {
        TlsConnectorDataBuilder::new()
    } else {
        TlsConnectorDataBuilder::new_http_auto()
    };
    tls_config.set_keylog_intent(KeyLogIntent::Environment);

    let mut proxy_tls_config = TlsConnectorDataBuilder::new();

    if cfg.insecure {
        tls_config.set_server_verify_mode(ServerVerifyMode::Disable);
        proxy_tls_config.set_server_verify_mode(ServerVerifyMode::Disable);
    }

    let inner_client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_boringssl_config(proxy_tls_config.into_shared_builder())
        .with_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config.into_shared_builder()))
        .with_custom_connector(UserAgentEmulateHttpConnectModifierLayer::default())
        .with_default_http_connector()
        .with_svc_req_inspector((
            UserAgentEmulateHttpRequestModifier::default(),
            request_writer,
        ))
        .build();

    // TODO: need to insert TLS separate from http:
    // - first tls is needed
    // - but http only is to be selected after handshake is done...

    let client_builder = (
        MapResultLayer::new(map_internal_client_error),
        cfg.emulate.then(|| {
            (
                UserAgentEmulateLayer::new(Arc::new(UserAgentDatabase::embedded()))
                    .try_auto_detect_user_agent(true)
                    .select_fallback(UserAgentSelectFallback::Random),
                EmulateTlsProfileLayer::new(),
            )
        }),
        (TimeoutLayer::new(if cfg.timeout > 0 {
            Duration::from_secs(cfg.timeout)
        } else {
            Duration::from_secs(180)
        })),
        FollowRedirectLayer::with_policy(Limited::new(if cfg.follow {
            cfg.max_redirects
        } else {
            0
        })),
        response_writer,
        DecompressionLayer::new(),
        cfg.auth
            .as_deref()
            .map(|auth| match cfg.auth_type.trim().to_lowercase().as_str() {
                "basic" => {
                    let mut basic = Basic::from_str(auth).context("parse basic str")?;
                    if auth.ends_with(':') && basic.password().is_empty() {
                        let mut terminal =
                            Terminal::open().context("open terminal for password prompting")?;
                        let password = terminal
                            .prompt_sensitive("password: ")
                            .context("prompt password from terminal")?;
                        basic.set_password(password);
                    }
                    Ok::<_, OpaqueError>(AddAuthorizationLayer::new(basic).as_sensitive(true))
                }
                "bearer" => Ok(AddAuthorizationLayer::new(
                    Bearer::try_from(auth).context("parse bearer str")?,
                )),
                unknown => panic!("unknown auth type: {unknown} (known: basic, bearer)"),
            })
            .transpose()?
            .unwrap_or_else(AddAuthorizationLayer::none),
        AddRequiredRequestHeadersLayer::default(),
        match cfg.proxy {
            None => HttpProxyAddressLayer::try_from_env_default()?,
            Some(proxy) => {
                let mut proxy_address: ProxyAddress =
                    proxy.parse().context("parse proxy address")?;
                if let Some(proxy_user) = cfg.proxy_user {
                    let credential = ProxyCredential::Basic(
                        proxy_user
                            .parse()
                            .context("parse basic proxy credentials")?,
                    );
                    proxy_address.credential = Some(credential);
                }
                HttpProxyAddressLayer::maybe(Some(proxy_address))
            }
        },
        SetProxyAuthHttpHeaderLayer::default(),
        HijackLayer::new(
            cfg.curl,
            service_fn(async |req: Request| {
                let Ok(req) = UserAgentEmulateHttpRequestModifier::new().serve(req).await else {
                    return Ok(
                        (StatusCode::INTERNAL_SERVER_ERROR, "failed to emulate UA").into_response()
                    );
                };

                let (parts, body) = req.into_parts();
                let payload = body.collect().await.unwrap().to_bytes();
                let curl_cmd = curl::cmd_string_for_request_parts_and_payload(&parts, &payload);

                #[allow(clippy::print_stdout)]
                {
                    println!("{curl_cmd}");
                }

                Ok::<_, OpaqueError>(StatusCode::OK.into_response())
            }),
        ),
    );

    Ok(client_builder.into_layer(inner_client))
}

fn parse_print_mode(mode: &str) -> Result<(Option<WriterMode>, Option<WriterMode>), BoxError> {
    let mut request_mode = None;
    let mut response_mode = None;

    for c in mode.chars() {
        match c {
            'h' => {
                response_mode = Some(match response_mode {
                    Some(mode) => match mode {
                        WriterMode::All | WriterMode::Body => WriterMode::All,
                        WriterMode::Headers => WriterMode::Headers,
                    },
                    None => WriterMode::Headers,
                });
            }
            'H' => {
                request_mode = Some(match request_mode {
                    Some(mode) => match mode {
                        WriterMode::All | WriterMode::Body => WriterMode::All,
                        WriterMode::Headers => WriterMode::Headers,
                    },
                    None => WriterMode::Headers,
                });
            }
            'b' => {
                response_mode = Some(match response_mode {
                    Some(mode) => match mode {
                        WriterMode::All | WriterMode::Headers => WriterMode::All,
                        WriterMode::Body => WriterMode::Body,
                    },
                    None => WriterMode::Body,
                });
            }
            'B' => {
                request_mode = Some(match request_mode {
                    Some(mode) => match mode {
                        WriterMode::All | WriterMode::Headers => WriterMode::All,
                        WriterMode::Body => WriterMode::Body,
                    },
                    None => WriterMode::Body,
                });
            }
            c => return Err(error!("unknown print mode character: {}", c).into()),
        }
    }

    Ok((request_mode, response_mode))
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, BoxError>
where
    E: Into<BoxError>,
    Body: StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
