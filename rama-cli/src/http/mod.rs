use argh::FromArgs;
use rama::{
    error::{error, BoxError, ErrorContext},
    http::{
        client::HttpClient,
        header::{HOST, USER_AGENT},
        layer::{
            auth::AddAuthorizationLayer,
            decompression::DecompressionLayer,
            follow_redirect::{policy::Limited, FollowRedirectLayer},
            timeout::TimeoutLayer,
            traffic_printer::{PrintMode, TrafficPrinterLayer},
        },
        Body, BodyExtractExt, HeaderValue, IntoResponse, Method, Request, Response, StatusCode,
        Uri,
    },
    proxy::http::client::HttpProxyConnectorLayer,
    service::{layer::HijackLayer, service_fn, Context, Service, ServiceBuilder},
    tcp::service::HttpConnector,
    tls::rustls::client::HttpsConnectorLayer,
};
use std::time::Duration;
use terminal_prompt::Terminal;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod tls;

#[derive(FromArgs, PartialEq, Debug, Clone)]
/// rama http client (run usage for more info)
#[argh(subcommand, name = "http")]
pub struct CliCommandHttp {
    #[argh(switch, short = 'j')]
    /// data items from the command line are serialized as a JSON object.
    /// The Content-Type and Accept headers are set to application/json
    /// (if not specified)
    ///
    /// (default)
    json: bool,

    #[argh(switch, short = 'f')]
    /// data items from the command line are serialized as form fields.
    ///
    /// The Content-Type is set to application/x-www-form-urlencoded (if not specified).
    form: bool,

    #[argh(switch, short = 'F')]
    /// follow 30 Location redirects
    follow: bool,

    #[argh(option, default = "30")]
    /// the maximum number of redirects to follow
    max_redirects: usize,

    #[argh(option, short = 'a')]
    /// client authentication: `USER[:PASS]` | TOKEN, if basic and no password is given it will be promped
    auth: Option<String>,

    #[argh(option, short = 'A', default = "String::from(\"basic\")")]
    /// the type of authentication to use (basic, bearer)
    auth_type: String,

    #[argh(switch, short = 'k')]
    /// skip Tls certificate verification
    insecure: bool,

    #[argh(option)]
    /// the desired tls version to use (automatically defined by default, choices are: 1.2, 1.3)
    tls: Option<String>,

    #[argh(option)]
    /// the client tls certificate file path to use
    cert: Option<String>,

    #[argh(option)]
    /// the client tls key file path to use
    cert_key: Option<String>,

    #[argh(option, short = 't', default = "0")]
    /// the timeout in seconds for each connection (0 = default timeout of 180s)
    timeout: u64,

    #[argh(switch)]
    /// fail if status code is not 2xx (4 if 4xx and 5 if 5xx)
    check_status: bool,

    #[argh(option, short = 'p', default = "String::from(\"hb\")")]
    /// define what the output should contain ('h'/'H' for headers, 'b'/'B' for body (response/request)
    print: String,

    #[argh(switch, short = 'v')]
    /// print verbose output, alias for --all --print hHbB (not used in offline mode)
    verbose: bool,

    #[argh(switch)]
    /// show output for all requests/responses (including redirects)
    all: bool,

    #[argh(switch)]
    /// print the request instead of executing it
    offline: bool,

    #[argh(switch)]
    /// print debug info
    debug: bool,

    #[argh(positional, greedy)]
    args: Vec<String>,
}

// TODO in future:
// - http sessions (e.g. cookies)
// - fix bug in body print (we seem to print garbage)
//    - this might to do with fact that decompressor comes later

pub async fn run(cfg: CliCommandHttp) -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(
                    if cfg.debug {
                        LevelFilter::DEBUG
                    } else {
                        LevelFilter::ERROR
                    }
                    .into(),
                )
                .from_env_lossy(),
        )
        .init();

    if cfg.args.is_empty() {
        return Err("no url provided".into());
    }

    let mut args = &cfg.args[..];

    let method = match args[0].to_lowercase().as_str() {
        "get" => Some(Method::GET),
        "post" => Some(Method::POST),
        "put" => Some(Method::PUT),
        "delete" => Some(Method::DELETE),
        "patch" => Some(Method::PATCH),
        "head" => Some(Method::HEAD),
        "options" => Some(Method::OPTIONS),
        "usage" => {
            println!("{}", print_manual());
            return Ok(());
        }
        _ => None,
    };
    if method.is_some() {
        args = &args[1..];
        if args.is_empty() {
            return Err("no url provided".into());
        }
    }

    let url = &args[0];
    args = &args[1..];

    let url = if url.starts_with(':') {
        if url.starts_with(":/") {
            format!("http://localhost{}", &url[1..])
        } else {
            format!("http://localhost{}", url)
        }
    } else if !url.contains("://") {
        format!("http://{}", url)
    } else {
        url.to_string()
    };

    let url: Uri = url.parse().context("parse url")?;

    let mut builder = Request::builder().uri(url.clone());

    for arg in args {
        match arg.split_once(':') {
            Some((name, value)) => {
                builder = builder.header(name, value);
            }
            None => {
                // TODO
            }
        }
    }

    // insert user agent if not already set
    if !builder
        .headers_mut()
        .map(|h| h.contains_key(USER_AGENT))
        .unwrap_or_default()
    {
        // TODO: do not do this unless UA Emulation is disabled!
        builder = builder.header(
            USER_AGENT,
            format!("{}/{}", rama::utils::info::NAME, rama::utils::info::VERSION),
        );
    }

    // insert host header if missing
    if !builder
        .headers_mut()
        .map(|h| h.contains_key(HOST))
        .unwrap_or_default()
    {
        // TODO: host header should be modified by follow_redirect layer?!?!?!
        // as currently it will not be updated for redirects
        // Or perhaps we shall do this in a "Set-Required-Headers" middleware?! that can be used as last???
        let header = HeaderValue::from_str(url.host().context("get host from url")?)
            .context("parse host as header value")?;
        builder = builder.header(HOST, header);
    }

    let request = builder
        .method(method.clone().unwrap_or(Method::GET))
        .body(Body::empty())
        .context("build http request")?;

    let client = create_client(cfg.clone()).await?;

    let response = client.serve(Context::default(), request).await?;

    if cfg.check_status {
        let status = response.status();
        if status.is_client_error() {
            eprintln!("client error: {}", status);
            std::process::exit(4);
        } else if status.is_server_error() {
            eprintln!("server error: {}", status);
            std::process::exit(5);
        }
    }

    if method != Some(Method::HEAD) {
        // TODO Handle errors better, as there might not be a body...
        let body = response
            .try_into_string()
            .await
            .context("read response body as utf-8 string")?;

        println!("{}", body);
    }

    Ok(())
}

async fn create_client<S>(
    mut cfg: CliCommandHttp,
) -> Result<impl Service<S, Request, Response = Response, Error = BoxError>, BoxError>
where
    S: Send + Sync + 'static,
{
    let (request_print_mode, response_print_mode) = if cfg.offline {
        (Some(PrintMode::All), None)
    } else if cfg.verbose {
        cfg.all = true;
        (Some(PrintMode::All), Some(PrintMode::All))
    } else {
        parse_print_mode(&cfg.print)?
    };
    let traffic_print_layer = match (request_print_mode, response_print_mode) {
        (Some(request_mode), Some(response_mode)) => {
            TrafficPrinterLayer::bidirectional(request_mode, response_mode)
        }
        (Some(request_mode), None) => TrafficPrinterLayer::requests(request_mode),
        (None, Some(response_mode)) => TrafficPrinterLayer::responses(response_mode),
        (None, None) => TrafficPrinterLayer::none(),
    };
    let (all_traffic_print_layer, last_traffic_print_layer) = if cfg.all {
        (traffic_print_layer, TrafficPrinterLayer::none())
    } else {
        (TrafficPrinterLayer::none(), traffic_print_layer)
    };

    let client_builder = ServiceBuilder::new()
        .map_result(map_internal_client_error)
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
        .layer(last_traffic_print_layer)
        .layer(FollowRedirectLayer::with_policy(Limited::new(
            if cfg.follow { cfg.max_redirects } else { 0 },
        )))
        .layer(all_traffic_print_layer)
        .layer(TimeoutLayer::new(if cfg.timeout > 0 {
            Duration::from_secs(cfg.timeout)
        } else {
            Duration::from_secs(180)
        }))
        .layer(HijackLayer::new(cfg.offline, service_fn(dummy_response)));

    let tls_client_config =
        tls::create_tls_client_config(cfg.insecure, cfg.tls, cfg.cert, cfg.cert_key).await?;

    Ok(client_builder.service(HttpClient::new(
        ServiceBuilder::new()
            .layer(HttpsConnectorLayer::auto().with_config(tls_client_config))
            .layer(HttpProxyConnectorLayer::proxy_from_context())
            .layer(HttpsConnectorLayer::tunnel())
            .service(HttpConnector::default()),
    )))
}

fn parse_print_mode(mode: &str) -> Result<(Option<PrintMode>, Option<PrintMode>), BoxError> {
    let mut request_mode = None;
    let mut response_mode = None;

    for c in mode.chars() {
        match c {
            'h' => {
                response_mode = Some(match response_mode {
                    Some(mode) => match mode {
                        PrintMode::All | PrintMode::Body => PrintMode::All,
                        PrintMode::Headers => PrintMode::Headers,
                    },
                    None => PrintMode::Headers,
                });
            }
            'H' => {
                request_mode = Some(match request_mode {
                    Some(mode) => match mode {
                        PrintMode::All | PrintMode::Body => PrintMode::All,
                        PrintMode::Headers => PrintMode::Headers,
                    },
                    None => PrintMode::Headers,
                });
            }
            'b' => {
                response_mode = Some(match response_mode {
                    Some(mode) => match mode {
                        PrintMode::All | PrintMode::Headers => PrintMode::All,
                        PrintMode::Body => PrintMode::Body,
                    },
                    None => PrintMode::Body,
                });
            }
            'B' => {
                request_mode = Some(match request_mode {
                    Some(mode) => match mode {
                        PrintMode::All | PrintMode::Headers => PrintMode::All,
                        PrintMode::Body => PrintMode::Body,
                    },
                    None => PrintMode::Body,
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

fn print_manual() -> &'static str {
    r##"
usage:
    rama http [METHOD] URL [REQUEST_ITEM ...]

Positional arguments:

  These arguments come after any flags and in the order they are listed here.
  Only URL is required.

  METHOD
      The HTTP method to be used for the request (GET, POST, PUT, DELETE, ...).

      This argument can be omitted in which case HTTPie will use POST if there
      is some data to be sent, otherwise GET:

          $ rama http example.org               # => GET
          $ rama http example.org hello=world   # => POST

  URL
      The request URL. Scheme defaults to 'http://' if the URL
      does not include one.

      You can also use a shorthand for localhost

          $ rama http :3000                    # => http://localhost:3000
          $ rama http :/foo                    # => http://localhost/foo

  REQUEST_ITEM
      Optional key-value pairs to be included in the request. The separator used
      determines the type:

      ':' HTTP headers:

          Referer:https://ramaproxy.org  Cookie:foo=bar  User-Agent:rama/0.2.0

      '==' URL parameters to be appended to the request URI:

          search==rama

      '=' Data fields to be serialized into a JSON object (with --json, -j)
          or form data (with --form, -f):

          name=rama  language=Rust  description='CLI HTTP client'

      ':=' Non-string JSON data fields (only with --json, -j):

          awesome:=true  amount:=42  colors:='["red", "green", "blue"]'

      '=@' A data field like '=', but takes a file path and embeds its content:

          essay=@Documents/essay.txt

      ':=@' A raw JSON field like ':=', but takes a file path and embeds its content:

          package:=@./package.json

      You can use a backslash to escape a colliding separator in the field name:

          field-name-with\:colon=value
"##
}
