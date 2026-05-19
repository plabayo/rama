#![allow(clippy::unchecked_time_subtraction)]

use std::{
    error::Error,
    fmt::{Debug, Display, Formatter},
    iter::successors,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::HashMap;
use parking_lot::Mutex;
use rama::{
    error::{BoxError, ErrorContext},
    http::{
        Body, Request, Response, StatusCode,
        headers::{ContentType, HttpResponseBuilderExt},
        mime,
    },
    telemetry::{
        tracing,
        tracing::{error, trace},
    },
};
use rama_core::{
    Layer, Service,
    extensions::ExtensionsRef,
    graceful,
    layer::{ArcLayer, IntoErrLayer, layer_fn},
    rt::Executor,
};
use rama_http::{
    layer::{
        error_handling::DowncastErrorHandlerLayer, into_response::IntoResponseLayer,
        trace::TraceLayer,
    },
    service::web::{
        Router,
        error::DowncastResponseError,
        extract::{Query, State},
        response::{Html, IntoResponse},
    },
};
use rama_http_backend::server::HttpServer;
use rama_net::stream::SocketInfo;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

const ADDRESS: &str = "127.0.0.1:62018";

type Result<T, E = BoxError> = std::result::Result<T, E>;

pub fn recursive_downcast<'a, E: Error + Send + Sync + 'static>(
    err: &'a (dyn Error + 'static),
) -> Option<&'a E> {
    successors(Some(err), |p| (*p).source()).find_map(|e| e.downcast_ref::<E>())
}

struct AppState {
    signing_key: String,
    last_request: Mutex<Instant>,
}

/// Log output and error of endpoints before any conversions took place
struct LogHandlerOutput<S>(S);

impl<S> Service<Request> for LogHandlerOutput<S>
where
    S: Service<Request, Output: Debug, Error: Debug>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
        let res = self.0.serve(input).await;
        match &res {
            Ok(resp) => trace!(?resp),
            Err(err) => error!(?err, "error handling request"),
        }
        res
    }
}

/// Serialize and sign response data
struct SerializeResponse<S> {
    inner: S,
    state: Arc<AppState>,
}

impl<S> Service<Request> for SerializeResponse<S>
where
    S: Service<Request, Output: Serialize>,
    S::Error: From<BoxError>,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(input).await {
            Ok(value) => {
                #[derive(Serialize)]
                struct Signed<D> {
                    data: D,
                    signature: String,
                }

                let body = serde_json::to_string(&Signed {
                    data: value,
                    signature: format!("signed by {}", self.state.signing_key),
                })
                .context("serialize json")?;

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .typed_header(ContentType::new(mime::APPLICATION_JSON))
                    .body(Body::from(body))
                    .map_err(Into::into)?)
            }
            Err(err) => Err(err),
        }
    }
}

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

impl Display for ApplicationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ApplicationError: {}", self.message)
    }
}

impl Error for ApplicationError {}

#[derive(Serialize)]
#[serde(untagged)]
enum OutputOrError<O> {
    Output(O),
    Error(ApplicationError),
}

struct ApplicationErrorService<S>(S);

impl<S> Service<Request> for ApplicationErrorService<S>
where
    S: Service<Request, Error = BoxError>,
{
    type Output = OutputOrError<S::Output>;
    type Error = BoxError;

    async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
        match self.0.serve(input).await {
            Ok(val) => Ok(OutputOrError::Output(val)),
            Err(err) => match err.downcast::<ApplicationError>() {
                Ok(app_err) => Ok(OutputOrError::Error(*app_err)),
                Err(err) => Err(err),
            },
        }
    }
}

#[derive(Debug)]
struct RateLimit {
    duration: Duration,
}

impl Display for RateLimit {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("RateLimit")
    }
}

impl Error for RateLimit {}

/// Service that rate limits requests by IP address based on the [`RateLimit`] error produced from endpoints.
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
    S: Service<Request, Error = BoxError>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
        let socket = input
            .extensions()
            .get_ref::<SocketInfo>()
            .ok_or("SocketInfo must be present")?;
        let client_ip = socket.peer_addr().ip_addr;

        /// Gets converted to Response by [`DowncastErrorHandlerLayer`] later in the stack
        #[derive(Debug, Clone)]
        struct RateLimitResponse;

        impl IntoResponse for RateLimitResponse {
            fn into_response(self) -> Response {
                StatusCode::TOO_MANY_REQUESTS.into_response()
            }
        }

        impl Display for RateLimitResponse {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str("RateLimitResponse")
            }
        }
        impl Error for RateLimitResponse {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(DowncastResponseError::new(self))
            }
        }

        {
            let mut limits = self.limits.lock();
            if let Some(until) = limits.get(&client_ip) {
                if until > &Instant::now() {
                    return Err(RateLimitResponse.into());
                } else {
                    limits.remove(&client_ip);
                }
            }
        }

        match self.inner.serve(input).await {
            Ok(res) => Ok(res),
            Err(err) => Err(if let Some(err) = recursive_downcast::<RateLimit>(&*err) {
                self.limits
                    .lock()
                    .insert(client_ip, Instant::now() + err.duration);
                RateLimitResponse.into()
            } else {
                err
            }),
        }
    }
}

#[derive(Deserialize)]
struct GreetRequest {
    name: String,
}

#[derive(Debug, Serialize)]
struct GreetResponse {
    text: String,
}

async fn greet_v2(
    State(state): State<Arc<AppState>>,
    Query(req): Query<GreetRequest>,
) -> Result<GreetResponse> {
    if req.name == "John" {
        return Err(ApplicationError::new(
            "ban",
            "You are banned from this service",
        ))?;
    }

    if req.name == "Mike" {
        let mut last_request = state.last_request.lock();
        if *last_request > Instant::now() - Duration::from_secs(2) {
            return Err(RateLimit {
                duration: Duration::from_secs(10),
            })?;
        }
        *last_request = Instant::now();
    }

    Ok(GreetResponse {
        text: format!("Hello {}!", req.name),
    })
}

fn api_v2<L>(
    router: Router<Arc<AppState>, L, Response, BoxError>,
) -> Router<Arc<AppState>, (), Response, BoxError> {
    let state = router.state().clone();

    router
        .with_endpoint_layer((
            layer_fn(move |inner| SerializeResponse {
                inner,
                state: state.clone(),
            }),
            layer_fn(ApplicationErrorService),
            layer_fn(LogHandlerOutput),
        ))
        .with_get("/greet", greet_v2)
        .with_endpoint_layer(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::new(
            "http_advanced_router=trace,rama_http[request]=off",
        ))
        .init();

    let graceful = graceful::Shutdown::default();

    let router = Router::new_with_state(Arc::new(AppState {
        signing_key: "secret key".into(),
        last_request: Instant::now().into(),
    }))
    .with_endpoint_layer((IntoResponseLayer::new(), IntoErrLayer::into_box_error()))
    .with_get("/", Html(r#"<h1>Landing</h1>"#))
    .with_sub_router_make_fn("/api/v2", api_v2);

    let middlewares = (
        ArcLayer::new(),
        TraceLayer::new_for_http(), // creates a span for requests
        DowncastErrorHandlerLayer::auto(),
        layer_fn(RateLimitService::new),
    );

    tracing::info!("running server at: {ADDRESS}");
    HttpServer::auto(Executor::graceful(graceful.guard()))
        .listen(ADDRESS, middlewares.into_layer(router))
        .await
        .context("http listen")?;

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .context("shutdown")?;

    Ok(())
}
