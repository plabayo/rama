use std::time::Duration;

use argh::FromArgs;
use rama::{
    error::{BoxError, ErrorContext},
    http::{
        client::HttpClient,
        header::USER_AGENT,
        layer::{
            decompression::DecompressionLayer,
            follow_redirect::FollowRedirectLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
        },
        Body, BodyExtractExt, Method, Request, Response,
    },
    proxy::http::client::HttpProxyConnectorLayer,
    service::{
        util::{backoff::ExponentialBackoff, rng::HasherRng},
        Context, Service, ServiceBuilder,
    },
    tcp::service::HttpConnector,
    tls::rustls::client::HttpsConnectorLayer,
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(FromArgs, PartialEq, Debug)]
/// rama http client (run usage for more info)
#[argh(subcommand, name = "http")]
pub struct CliCommandHttp {
    #[argh(switch, short = 'v')]
    /// verbose output (e.g. show headers)
    verbose: bool,

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

    #[argh(positional, greedy)]
    args: Vec<String>,
}

// TODO:
// - options:
//   - http: redirect, max redirects, auth (basic/bearer), -a/A, --auth/--auth-type
//   - http sessions
//   - TLS: verify, versions, ciphers, server cert, client cert/key
//   - conn: timeout
//   - output: print (headers, meta, body, all (all requests/responses))
//   - -v/--verbose: shortcut for --all and --print (headers, meta, body)
//   - --offline: print request instead of executing it
//   - --check-status: fail if status code is not 2xx (4 if 4xx and 5 if 5xx
//   - --debug: print debug info (set default log level to debug)
//   - --manual: print manual
//   - --version: print version

pub async fn run(cfg: CliCommandHttp) -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::ERROR.into())
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

    let client = ServiceBuilder::new()
        .map_result(map_internal_client_error)
        .layer(TraceLayer::new_for_http())
        .layer(DecompressionLayer::new())
        // TODO: make optional??
        .layer(FollowRedirectLayer::default())
        .layer(RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(100),
                    Duration::from_secs(30),
                    0.01,
                    HasherRng::default,
                )
                .unwrap(),
            ),
        ))
        .service(HttpClient::new(
            ServiceBuilder::new()
                .layer(HttpsConnectorLayer::auto())
                .layer(HttpProxyConnectorLayer::proxy_from_context())
                .layer(HttpsConnectorLayer::tunnel())
                .service(HttpConnector::default()),
        ));

    let response = client.serve(Context::default(), request).await?;

    if cfg.verbose {
        // TODO:
        // - print request
        // - print also for each redirect?

        // print headers
        for (name, value) in response.headers() {
            println!("{}: {}", name, value.to_str().unwrap());
        }
        println!();
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
