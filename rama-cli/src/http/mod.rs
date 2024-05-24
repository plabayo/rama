use std::time::Duration;

use argh::FromArgs;
use rama::{
    error::{BoxError, ErrorContext},
    http::{
        client::HttpClient,
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
/// rama http client
///
///
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

    #[argh(positional, greedy)]
    args: Vec<String>,
}

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
        _ => None,
    };
    if method.is_some() {
        args = &args[1..];
        if args.is_empty() {
            return Err("no url provided".into());
        }
    }

    let url = &args[0];
    // args = &args[1..];

    let builder = Request::builder().uri(url);

    let request = builder.body(Body::empty()).context("build http request")?;

    let client = ServiceBuilder::new()
        .map_result(map_internal_client_error)
        .layer(TraceLayer::new_for_http())
        .layer(DecompressionLayer::new())
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

    let body = response
        .try_into_string()
        .await
        .context("read response body as utf-8 string")?;

    println!("{}", body);

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
