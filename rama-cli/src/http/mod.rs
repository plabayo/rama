use argh::FromArgs;
use rama::{
    error::{BoxError, ErrorContext},
    http::{
        client::HttpClient,
        header::USER_AGENT,
        layer::{
            auth::AddAuthorizationLayer,
            decompression::DecompressionLayer,
            follow_redirect::{policy::Limited, FollowRedirectLayer},
            timeout::TimeoutLayer,
        },
        Body, BodyExtractExt, Method, Request, Response,
    },
    proxy::http::client::HttpProxyConnectorLayer,
    service::{Context, Service, ServiceBuilder},
    tcp::service::HttpConnector,
    tls::rustls::client::HttpsConnectorLayer,
};
use std::time::Duration;
use terminal_prompt::Terminal;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod tls;

#[derive(FromArgs, PartialEq, Debug)]
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
    /// the timeout in seconds for each connection (0 = no timeout)
    timeout: u64,

    #[argh(switch)]
    /// fail if status code is not 2xx (4 if 4xx and 5 if 5xx)
    check_status: bool,

    #[argh(switch)]
    /// print debug info
    debug: bool,

    #[argh(positional, greedy)]
    args: Vec<String>,
}

// TODO:
// - options:
//   - http sessions
//   - output: print (headers, meta, body, all (all requests/responses))
//   - -v/--verbose: shortcut for --all and --print (headers, meta, body)
//   - --offline: print request instead of executing it
//   - --manual: print manual

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

    let mut builder = Request::builder().uri(url);

    // todo: use winnom??!

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

    let request = builder
        .method(method.clone().unwrap_or(Method::GET))
        .body(Body::empty())
        .context("build http request")?;

    let client_builder = ServiceBuilder::new()
        .map_result(map_internal_client_error)
        .layer(DecompressionLayer::new())
        .layer(cfg.auth.as_deref().map(|auth| {
            let auth = auth.trim().trim_end_matches(':');
            match cfg.auth_type.trim().to_lowercase().as_str() {
                "basic" => match auth.split_once(':') {
                    Some((user, pass)) => AddAuthorizationLayer::basic(user, pass),
                    None => {
                        let mut terminal =
                            Terminal::open().expect("open terminal for password prompting");
                        let password = terminal
                            .prompt_sensitive("password: ")
                            .expect("prompt password");
                        AddAuthorizationLayer::basic(auth, password.as_str())
                    }
                },
                "bearer" => AddAuthorizationLayer::bearer(auth),
                unknown => panic!("unknown auth type: {}", unknown),
            }
        }))
        .layer(
            cfg.follow
                .then(|| FollowRedirectLayer::with_policy(Limited::new(cfg.max_redirects))),
        )
        .layer(TimeoutLayer::new(if cfg.timeout > 0 {
            Duration::from_secs(cfg.timeout)
        } else {
            Duration::from_secs(180)
        }));

    let tls_client_config =
        tls::create_tls_client_config(cfg.insecure, cfg.tls, cfg.cert, cfg.cert_key).await?;

    let client = client_builder.service(HttpClient::new(
        ServiceBuilder::new()
            .layer(HttpsConnectorLayer::auto().with_config(tls_client_config))
            .layer(HttpProxyConnectorLayer::proxy_from_context())
            .layer(HttpsConnectorLayer::tunnel())
            .service(HttpConnector::default()),
    ));

    let response = client.serve(Context::default(), request).await?;

    // if cfg.verbose {
    //     // TODO:
    //     // - print request
    //     // - print also for each redirect?

    //     // print headers
    //     for (name, value) in response.headers() {
    //         println!("{}: {}", name, value.to_str().unwrap());
    //     }
    //     println!();
    // }

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

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, rama::error::BoxError>
where
    E: Into<rama::error::BoxError>,
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

          Referer:https://httpie.io  Cookie:foo=bar  User-Agent:bacon/1.0

      '==' URL parameters to be appended to the request URI:

          search==httpie

      '=' Data fields to be serialized into a JSON object (with --json, -j)
          or form data (with --form, -f):

          name=HTTPie  language=Python  description='CLI HTTP client'

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
