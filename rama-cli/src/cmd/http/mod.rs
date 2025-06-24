//! rama http client

use clap::Args;
use rama::{
    Context, Layer, Service,
    cli::args::RequestArgsBuilder,
    error::{BoxError, ErrorContext, OpaqueError, error},
    graceful::{self, Shutdown, ShutdownGuard},
    http::{
        Request, Response,
        client::{
            EasyHttpWebClient,
            proxy::layer::{HttpProxyAddressLayer, SetProxyAuthHttpHeaderLayer},
        },
        layer::{
            auth::AddAuthorizationLayer,
            decompression::DecompressionLayer,
            follow_redirect::{FollowRedirectLayer, policy::Limited},
            required_header::AddRequiredRequestHeadersLayer,
            timeout::TimeoutLayer,
            traffic_writer::WriterMode,
        },
    },
    layer::MapResultLayer,
    net::{
        address::ProxyAddress,
        tls::{KeyLogIntent, client::ServerVerifyMode},
        user::{Basic, Bearer, ProxyCredential},
    },
    rt::Executor,
    telemetry::tracing::level_filters::LevelFilter,
    tls::boring::client::{EmulateTlsProfileLayer, TlsConnectorDataBuilder},
    ua::{
        emulate::{
            UserAgentEmulateHttpConnectModifier, UserAgentEmulateHttpRequestModifier,
            UserAgentEmulateLayer, UserAgentSelectFallback,
        },
        profile::UserAgentDatabase,
    },
};

use std::{io::IsTerminal, str::FromStr, sync::Arc, time::Duration};
use terminal_prompt::Terminal;
use tokio::sync::oneshot;

use crate::error::ErrorWithExitCode;

mod writer;

#[derive(Args, Debug, Clone)]
/// rama http client
pub struct CliCommandHttp {
    #[arg(short = 'j', long)]
    /// data items from the command line are serialized as a JSON object.
    /// The `Content-Type` and `Accept headers` are set to `application/json`
    /// (if not specified)
    ///
    /// (default)
    json: bool,

    #[arg(short = 'f', long)]
    /// data items from the command line are serialized as form fields.
    ///
    /// The `Content-Type` is set to `application/x-www-form-urlencoded` (if not specified).
    form: bool,

    #[arg(short = 'F', long)]
    /// follow 30 Location redirects
    follow: bool,

    #[arg(long, default_value_t = 30)]
    /// the maximum number of redirects to follow
    max_redirects: usize,

    #[arg(long, short = 'P')]
    /// upstream proxy to use (can also be specified using PROXY env variable)
    proxy: Option<String>,

    #[arg(long, short = 'U')]
    /// upstream proxy user credentials to use (or overwrite)
    proxy_user: Option<String>,

    #[arg(long, short = 'a')]
    /// client authentication: `USER[:PASS]` | TOKEN,
    /// if basic and no password is given it will be promped
    auth: Option<String>,

    #[arg(long, short = 'A', default_value = "basic")]
    /// the type of authentication to use (basic, bearer)
    auth_type: String,

    #[arg(short = 'k', long)]
    /// skip Tls certificate verification
    insecure: bool,

    #[arg(long)]
    /// the desired tls version to use (automatically defined by default, choices are: 1.2, 1.3)
    tls: Option<String>,

    #[arg(long)]
    /// the client tls key file path to use
    cert_key: Option<String>,

    #[arg(long, short = 't', default_value = "0")]
    /// the timeout in seconds for each connection (0 = default timeout of 180s)
    timeout: u64,

    #[arg(long)]
    /// fail if status code is not 2xx (4 if 4xx and 5 if 5xx)
    check_status: bool,

    #[arg(long, short = 'p')]
    /// define what the output should contain ('h'/'H' for headers, 'b'/'B' for body (response/request)
    print: Option<String>,

    #[arg(short = 'b', long)]
    /// print the response body (short for --print b)
    body: bool,

    #[arg(short = 'H', long)]
    /// print the response headers (short for --print h)
    headers: bool,

    #[arg(short = 'v', long)]
    /// print verbose output, alias for --all --print hHbB
    verbose: bool,

    #[arg(long)]
    /// show output for all requests/responses (including redirects)
    all: bool,

    #[arg(long, short = 'o')]
    /// write output to file instead of stdout
    output: Option<String>,

    #[arg(long)]
    /// print debug info
    debug: bool,

    #[arg(long, short = 'E')]
    /// emulate user agent
    emulate: bool,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    /// positional arguments to populate request headers and body
    ///
    /// These arguments come after any flags and in the order they are listed here.
    /// Only the URL is required.
    ///
    /// # METHOD
    ///
    /// The HTTP method to be used for the request (GET, POST, PUT, DELETE, ...).
    ///
    /// This argument can be omitted in which case HTTPie will use POST if there
    /// is some data to be sent, otherwise GET:
    ///
    ///     $ rama http example.org               # => GET
    ///
    ///     $ rama http example.org hello=world   # => POST
    ///
    /// # URL
    ///
    /// The request URL. Scheme defaults to 'http://' if the URL
    /// does not include one.
    ///
    /// You can also use a shorthand for localhost
    ///
    ///    $ rama http :3000    # => http://localhost:3000
    ///
    ///    $ rama http :/foo    # => http://localhost/foo
    ///
    /// # REQUEST_ITEM
    ///
    /// Optional key-value pairs to be included in the request. The separator used
    /// determines the type:
    ///
    /// ':' HTTP headers:
    ///
    ///     Referer:https://ramaproxy.org  Cookie:foo=bar  User-Agent:rama/0.2.0
    ///
    /// '==' URL parameters to be appended to the request URI:
    ///
    ///     search==rama
    ///
    /// '=' Data fields to be serialized into a JSON object or form data:
    ///
    ///     name=rama  language=Rust  description='CLI HTTP client'
    ///
    /// ':=' Non-string data fields:
    ///
    ///     awesome:=true  amount:=42  colors:='["red", "green", "blue"]'
    ///
    /// You can use a backslash to escape a colliding separator in the field name:
    ///
    ///     field-name-with\:colon=value
    args: Vec<String>,
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

    let request = request_args_builder.build()?;

    let client = create_client(guard, cfg.clone()).await?;

    let response = client.serve(Context::default(), request).await?;

    if cfg.check_status {
        let status = response.status();
        if status.is_client_error() {
            return Err(ErrorWithExitCode::new(
                4,
                OpaqueError::from_display(format!("client http error, status: {status}")),
            )
            .into());
        } else if status.is_server_error() {
            return Err(ErrorWithExitCode::new(
                5,
                OpaqueError::from_display(format!("server http error, status: {status}")),
            )
            .into());
        }
    }

    Ok(())
}

async fn create_client<S>(
    guard: ShutdownGuard,
    mut cfg: CliCommandHttp,
) -> Result<impl Service<S, Request, Response = Response, Error = BoxError>, BoxError>
where
    S: Clone + Send + Sync + 'static,
{
    let (request_writer_mode, response_writer_mode) = if cfg.verbose {
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
        .with_jit_req_inspector(UserAgentEmulateHttpConnectModifier::default())
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
                unknown => panic!("unknown auth type: {} (known: basic, bearer)", unknown),
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
    Body: rama::http::dep::http_body::Body<Data = rama::bytes::Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
