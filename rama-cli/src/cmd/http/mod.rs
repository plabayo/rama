//! rama http client

use clap::Args;
use rama::{
    cli::args::RequestArgsBuilder,
    error::{error, BoxError, ErrorContext, OpaqueError},
    http::{
        client::HttpClient,
        layer::{
            auth::AddAuthorizationLayer,
            decompression::DecompressionLayer,
            follow_redirect::{policy::Limited, FollowRedirectLayer},
            required_header::AddRequiredRequestHeadersLayer,
            timeout::TimeoutLayer,
            traffic_writer::WriterMode,
        },
        IntoResponse, Request, Response, StatusCode,
    },
    proxy::http::client::HttpProxyConnectorLayer,
    rt::Executor,
    service::{layer::HijackLayer, service_fn, Context, Service, ServiceBuilder},
    tcp::service::HttpConnector,
    tls::rustls::client::HttpsConnectorLayer,
    utils::graceful::{self, Shutdown, ShutdownGuard},
};
use std::{io::IsTerminal, time::Duration};
use terminal_prompt::Terminal;
use tokio::sync::oneshot;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::error::ErrorWithExitCode;

mod tls;
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
    /// the client tls certificate file path to use
    cert: Option<String>,

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
    /// print verbose output, alias for --all --print hHbB (not used in offline mode)
    verbose: bool,

    #[arg(long)]
    /// show output for all requests/responses (including redirects)
    all: bool,

    #[arg(long)]
    /// print the request instead of executing it
    offline: bool,

    #[arg(long, short = 'o')]
    /// write output to file instead of stdout
    output: Option<String>,

    #[arg(long)]
    /// print debug info
    debug: bool,

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
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(
                    if cfg.debug {
                        if cfg.verbose {
                            LevelFilter::TRACE
                        } else {
                            LevelFilter::DEBUG
                        }
                    } else {
                        LevelFilter::ERROR
                    }
                    .into(),
                )
                .from_env_lossy(),
        )
        .init();

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

    shutdown.spawn_task_fn(move |guard| async move {
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
    S: Send + Sync + 'static,
{
    let (request_writer_mode, response_writer_mode) = if cfg.offline {
        (Some(WriterMode::All), None)
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

    let client_builder = ServiceBuilder::new()
        .map_result(map_internal_client_error)
        .layer(TimeoutLayer::new(if cfg.timeout > 0 {
            Duration::from_secs(cfg.timeout)
        } else {
            Duration::from_secs(180)
        }))
        .layer(FollowRedirectLayer::with_policy(Limited::new(
            if cfg.follow { cfg.max_redirects } else { 0 },
        )))
        .layer(response_writer)
        .layer(DecompressionLayer::new())
        .layer(
            cfg.auth
                .as_deref()
                .map(|auth| {
                    let auth = auth.trim().trim_end_matches(':');
                    match cfg.auth_type.trim().to_lowercase().as_str() {
                        "basic" => match auth.split_once(':') {
                            Some((user, pass)) => AddAuthorizationLayer::basic(user, pass),
                            None => {
                                let mut terminal =
                                    Terminal::open().expect("open terminal for password prompting");
                                let password = terminal
                                    .prompt_sensitive("password: ")
                                    .expect("prompt password from terminal");
                                AddAuthorizationLayer::basic(auth, password.as_str())
                            }
                        },
                        "bearer" => AddAuthorizationLayer::bearer(auth),
                        unknown => panic!("unknown auth type: {} (known: basic, bearer)", unknown),
                    }
                })
                .unwrap_or_else(AddAuthorizationLayer::none),
        )
        .layer(AddRequiredRequestHeadersLayer::default())
        .layer(request_writer)
        .layer(HijackLayer::new(cfg.offline, service_fn(dummy_response)));

    let tls_client_config =
        tls::create_tls_client_config(cfg.insecure, cfg.tls, cfg.cert, cfg.cert_key).await?;

    Ok(client_builder.service(HttpClient::new(
        ServiceBuilder::new()
            .layer(HttpsConnectorLayer::auto().with_config(tls_client_config))
            .layer(HttpProxyConnectorLayer::from_env_default())
            .layer(HttpsConnectorLayer::tunnel())
            .service(HttpConnector::default()),
    )))
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

async fn dummy_response<S, Request>(_ctx: Context<S>, _req: Request) -> Result<Response, BoxError> {
    Ok(StatusCode::OK.into_response())
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, BoxError>
where
    E: Into<BoxError>,
    Body: rama::http::dep::http_body::Body<Data = bytes::Bytes> + Send + Sync + 'static,
    Body::Error: Into<BoxError>,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
