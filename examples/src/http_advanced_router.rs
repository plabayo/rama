//! This example demonstrates advanced `Router` composition with a custom
//! endpoint layer and a router-wide custom error type.
//!
//! The outer router serves mixed response styles:
//! - `GET /`: a plain HTML landing page
//! - `GET /api/v2/info`: signed JSON metadata
//! - `GET /api/v2/greet?name=<name>`: signed JSON greeting, or a structured error
//!
//! The main thing being showcased is the `/api/v2` sub-router:
//! - handlers return ordinary typed outputs such as [`ApiInfo`] and [`GreetResponse`]
//! - handlers raise ordinary typed errors such as [`ApplicationError`] and [`RateLimit`]
//! - [`ApiEndpointLayer`] generically turns any successful `Serialize` output into
//!   a signed JSON [`Response`]
//! - all endpoint errors converge into the router-wide [`CustomRouterError`], which
//!   is then handled statically by outer middleware and [`ErrorHandlerLayer`]
//!
//! In other words: custom output and custom error is supported
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_advanced_router --features http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62031`. You can use `curl` to inspect
//! the different success and error paths:
//!
//! ```sh
//! curl -v http://127.0.0.1:62031/
//! curl -v 'http://127.0.0.1:62031/api/v2/info'
//! curl -v 'http://127.0.0.1:62031/api/v2/greet?name=Jane'
//! curl -v 'http://127.0.0.1:62031/api/v2/greet?name=John'
//! curl -v 'http://127.0.0.1:62031/api/v2/greet?name=Mike'
//! curl -v 'http://127.0.0.1:62031/api/v2/greet?name=Mike'
//! ```
//!
//! The `Jane` request shows the generic signed-success path, `John` shows a
//! typed application error rendered as `403`, and the second `Mike` request
//! shows the typed rate-limit error rendered as `429`.

use std::{
    convert::Infallible,
    fmt::Debug,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::HashMap;
use parking_lot::Mutex;
use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    graceful,
    http::{
        Body, Request, Response, StatusCode,
        headers::{ContentType, HttpResponseBuilderExt},
        layer::{
            error_handling::ErrorHandlerLayer, into_response::IntoResponseLayer, trace::TraceLayer,
        },
        mime,
        server::HttpServer,
        service::web::{
            Router,
            extract::{Query, State, query::FailedToDeserializeQueryString},
            response::{ErrorResponse, Html, IntoResponse, Json},
            router::{DefaultEndpointLayer, RouterError},
        },
    },
    layer::{ArcLayer, IntoErrLayer, layer_fn},
    net::stream::SocketInfo,
    rt::Executor,
    telemetry::tracing::{
        self, error,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
        trace,
    },
};

use serde::{Deserialize, Serialize};

const ADDRESS: &str = "127.0.0.1:62031";

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::new(
            "http_advanced_router=trace,rama_http[request]=off",
        ))
        .init();

    let graceful = graceful::Shutdown::default();

    // Outer router: every endpoint produces (Response, CustomRouterError).
    let router = Router::new_with_state(Arc::new(AppState {
        signing_key: "secret key".into(),
        last_mike_request: Mutex::new(None),
    }))
    .with_endpoint_layer((
        // Turns whatever `Output` the endpoint emits into a `Response`.
        IntoResponseLayer::new(),
        // Turns whatever `Error` the endpoint emits into `CustomRouterError` using `Into::into``
        IntoErrLayer::<CustomRouterError>::new(),
    ))
    .with_get(
        "/",
        Html(
            r#"<h1>Advanced Router</h1>
                <p>Try
                    <code>/api/v2/info</code>,
                    <code>/api/v2/greet?name=Jane</code>,
                    and then call
                    <code>/api/v2/greet?name=Mike</code> twice quickly to trigger the typed rate limiter.
                </p>"#,
        ),
    )
    .with_sub_router_make_fn("/api/v2", api_v2);

    let svc = (
        ArcLayer::new(),
        TraceLayer::new_for_http(),
        // Converts `Err(CustomRouterError)` to a `Response` via `IntoResponse`.
        ErrorHandlerLayer::default(),
        // Observes `CustomRouterError::RateLimit` and short-circuits repeat offenders within the configured window
        layer_fn(RateLimitService::new),
    )
        .into_layer(router);

    tracing::info!("running server at: {ADDRESS}");
    HttpServer::auto(Executor::graceful(graceful.guard()))
        .listen(ADDRESS, svc)
        .await
        .context("http listen")?;

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .context("shutdown")?;

    Ok(())
}

/// Sub-router for the `/api/v2` prefix.
///
/// Endpoints registered here emit a `Serialize` output and a `CustomRouterError`
/// error. [`ApiEndpointLayer`] wraps each endpoint so successful outputs become
/// a signed JSON envelope and errors are converted into [`CustomRouterError`]. The
/// trailing `with_default_endpoint_layer()` resets the endpoint_layer, so these layers
/// are only applied to these endpoints
fn api_v2<L>(
    router: Router<Arc<AppState>, L, Response, CustomRouterError>,
) -> Router<Arc<AppState>, DefaultEndpointLayer, Response, CustomRouterError> {
    let state = router.state().clone();

    router
        .with_endpoint_layer(ApiEndpointLayer::new(state))
        .with_get("/info", api_info)
        .with_get("/greet", greet_v2)
        .with_default_endpoint_layer()
}

async fn api_info() -> Result<ApiInfo, Infallible> {
    Ok(ApiInfo {
        api: "advanced-router",
        version: 2,
        notes: [
            "success responses are signed generically",
            "errors stay strongly typed until the edge",
            "rate limiting reacts to a typed error variant",
        ],
    })
}

async fn greet_v2(
    State(state): State<Arc<AppState>>,
    Query(req): Query<GreetRequest>,
) -> Result<GreetResponse, CustomRouterError> {
    if req.name == "John" {
        return Err(ApplicationError::new("ban", "you are banned from this service").into());
    }

    if req.name == "Mike" {
        let mut last_request = state.last_mike_request.lock();
        if let Some(previous) = *last_request
            && previous.elapsed() < Duration::from_secs(2)
        {
            return Err(RateLimit::new(Duration::from_secs(10)).into());
        }
        *last_request = Some(Instant::now());
    }

    Ok(GreetResponse {
        text: format!("Hello {}!", req.name),
    })
}

#[derive(Debug, Deserialize)]
struct GreetRequest {
    name: String,
}

#[derive(Debug, Serialize)]
struct GreetResponse {
    text: String,
}

#[derive(Debug, Serialize)]
struct ApiInfo {
    api: &'static str,
    version: u8,
    notes: [&'static str; 3],
}

#[derive(Debug, Serialize)]
struct SignedResponse<T> {
    data: T,
    signature: String,
}

struct AppState {
    signing_key: String,
    last_mike_request: Mutex<Option<Instant>>,
}

/// Router-wide error enum. Every endpoint, after the endpoint-layer stack runs,
/// produces this as its `Error`.
#[derive(Debug)]
enum CustomRouterError {
    /// Domain-level error reported back to the client as a structured JSON value.
    Application(ApplicationError),
    /// Rate-limit signal observed by [`RateLimitService`] and rendered as 429.
    RateLimit(RateLimit),
    /// Pre-rendered response (e.g. extractor rejections that already know how
    /// to render themselves).
    Http(ErrorResponse),
    /// Path-level routing failure (not-found, method-not-allowed, ...).
    Router(RouterError),
    /// Catch-all for any other error type that crosses the boundary.
    Unexpected(BoxError),
}

impl std::fmt::Display for CustomRouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Application(application_error) => {
                write!(f, "application_error: {application_error:?}")
            }
            Self::RateLimit(rate_limit) => {
                write!(f, "rate_limit: {rate_limit:?}")
            }
            Self::Http(error_response) => {
                write!(f, "error_response: {error_response:?}")
            }
            Self::Router(router_error) => {
                write!(f, "router_error: {router_error:?}")
            }
            Self::Unexpected(error) => {
                write!(f, "unexpected_error: {error:?}")
            }
        }
    }
}

impl IntoResponse for CustomRouterError {
    fn into_response(self) -> Response {
        match self {
            Self::Application(err) => (StatusCode::FORBIDDEN, Json(err)).into_response(),
            Self::RateLimit(err) => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ApplicationError::new(
                    "rate_limit",
                    format!("please retry in {} seconds", err.duration.as_secs().max(1)),
                )),
            )
                .into_response(),
            Self::Http(err) => err.into_response(),
            Self::Router(err) => err.into_response(),
            Self::Unexpected(err) => {
                error!(error = %err, "unexpected error while handling request");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApplicationError::new(
                        "internal",
                        "an unexpected error happened",
                    )),
                )
                    .into_response()
            }
        }
    }
}

impl From<ApplicationError> for CustomRouterError {
    fn from(value: ApplicationError) -> Self {
        Self::Application(value)
    }
}

impl From<RateLimit> for CustomRouterError {
    fn from(value: RateLimit) -> Self {
        Self::RateLimit(value)
    }
}

impl From<RouterError> for CustomRouterError {
    fn from(value: RouterError) -> Self {
        Self::Router(value)
    }
}

impl From<ErrorResponse> for CustomRouterError {
    fn from(value: ErrorResponse) -> Self {
        Self::Http(value)
    }
}

/// Extractor rejections are still regular typed errors. We convert them into the
/// router-wide error enum so the outer router can keep a single `Error` type.
/// This also makes it explicit to handle all possible Errors using a match.
impl From<FailedToDeserializeQueryString> for CustomRouterError {
    fn from(value: FailedToDeserializeQueryString) -> Self {
        Self::Http(value.into())
    }
}

impl From<BoxError> for CustomRouterError {
    fn from(value: BoxError) -> Self {
        Self::Unexpected(value)
    }
}

impl From<Infallible> for CustomRouterError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

/// Domain-level application error returned to the client as structured JSON.
#[derive(Debug, Serialize)]
struct ApplicationError {
    error: bool,
    key: String,
    message: String,
}

impl ApplicationError {
    fn new(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: true,
            key: key.into(),
            message: message.into(),
        }
    }
}

/// Signal raised by an endpoint to ask the outer [`RateLimitService`] to
/// remember the client and start refusing requests for `duration`.
#[derive(Debug)]
struct RateLimit {
    duration: Duration,
}

impl RateLimit {
    fn new(duration: Duration) -> Self {
        Self { duration }
    }
}

/// Endpoint-layer service for API routes:
/// - logs typed output and errors before any conversion
/// - signs every serializable success payload as a JSON envelope
/// - converts handler-specific errors into [`CustomRouterError`]
struct ApiEndpointService<S> {
    inner: S,
    state: Arc<AppState>,
}

#[derive(Clone)]
struct ApiEndpointLayer {
    state: Arc<AppState>,
}

impl ApiEndpointLayer {
    fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for ApiEndpointLayer {
    type Service = ApiEndpointService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ApiEndpointService {
            inner,
            state: self.state.clone(),
        }
    }
}

impl<S> Service<Request> for ApiEndpointService<S>
where
    S: Service<Request>,
    S::Output: Debug + Serialize,
    S::Error: Debug + Into<CustomRouterError>,
{
    type Output = Response;
    type Error = CustomRouterError;

    async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(input).await {
            Ok(output) => {
                trace!(?output, "api handler output");
                signed_json_response(&self.state.signing_key, output).map_err(Into::into)
            }
            Err(err) => {
                trace!(?err, "api handler error");
                Err(err.into())
            }
        }
    }
}

fn signed_json_response<T>(signing_key: &str, value: T) -> Result<Response, BoxError>
where
    T: Serialize,
{
    let body = serde_json::to_string(&SignedResponse {
        data: value,
        signature: format!("signed by {signing_key}"),
    })
    .context("serialize signed json response")?;

    Response::builder()
        .status(StatusCode::OK)
        .typed_header(ContentType::new(mime::APPLICATION_JSON))
        .body(Body::from(body))
        .context("build signed json response")
}

/// Service that turns the [`CustomRouterError::RateLimit`] variant into a
/// per-client cooldown.
struct RateLimitService<S> {
    inner: S,
    limits: Mutex<HashMap<IpAddr, Instant>>,
}

impl<S> RateLimitService<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            limits: Default::default(),
        }
    }
}

impl<S> Service<Request> for RateLimitService<S>
where
    S: Service<Request, Error = CustomRouterError>,
{
    type Output = S::Output;
    type Error = CustomRouterError;

    async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
        let socket = input
            .extensions()
            .get_ref::<SocketInfo>()
            .context("SocketInfo must be present")?;
        let client_ip = socket.peer_addr().ip_addr;

        {
            let mut limits = self.limits.lock();
            if let Some(until) = limits.get(&client_ip).copied() {
                let remaining = until.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    return Err(RateLimit::new(remaining).into());
                }
                limits.remove(&client_ip);
            }
        }

        let result = self.inner.serve(input).await;
        if let Err(CustomRouterError::RateLimit(err)) = &result {
            self.limits
                .lock()
                .insert(client_ip, Instant::now() + err.duration);
        }

        result
    }
}
