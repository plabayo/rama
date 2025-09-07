//! This example demonstrates how to integrate tower into your rama HTTP stack
//!
//! ```sh
//! cargo run --example http_rama_tower --features=http-full,tower
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62020`. You can use your browser to interact with the service:
//!
//! ```sh
//! open http://127.0.0.1:62020
//! curl -v http://127.0.0.1:62020
//! ```
//!
//! You should see the homepage in your browser with the title "Rama + Tower".

/// rama provides everything out of the box to build a complete web service.
use rama::{
    Layer as _,
    error::{BoxError, OpaqueError},
    http::service::web::response::Html,
    http::{
        HeaderValue, Request, layer::trace::TraceLayer, server::HttpServer, service::web::Router,
    },
    layer::ConsumeErrLayer,
    net::address::SocketAddress,
    rt::Executor,
    telemetry::tracing::{self, level_filters::LevelFilter},
    utils::tower::{
        ServiceAdapter,
        core::{Layer, Service},
        layer::LayerAdapter,
    },
};

/// Everything else we need is provided by the standard library, community crates or tokio.
use pin_project_lite::pin_project;
use std::{
    convert::Infallible,
    future::{Ready, ready},
    pin::Pin,
    time::Duration,
};
use tokio::time::Sleep;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

const ADDRESS: SocketAddress = SocketAddress::local_ipv4(62020);

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    let router: Router = Router::new().get("/", ServiceAdapter::new(HelloSvc));
    let app = LayerAdapter::new((
        TimeoutLayer(Duration::from_secs(30)),
        AddHelloMarkerHeaderLayer,
    ))
    .into_layer(router);

    graceful.spawn_task_fn(async |guard| {
        tracing::info!("running service at: {ADDRESS}");
        let exec = Executor::graceful(guard);
        HttpServer::auto(exec)
            .listen(
                ADDRESS,
                (TraceLayer::new_for_http(), ConsumeErrLayer::default()).into_layer(app),
            )
            .await
            .unwrap();
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
struct AddHelloMarkerHeaderLayer;

#[derive(Debug, Clone, Default)]
struct AddHelloMarkerHeaderService<S>(S);

impl<S> Layer<S> for AddHelloMarkerHeaderLayer {
    type Service = AddHelloMarkerHeaderService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddHelloMarkerHeaderService(inner)
    }
}

impl<S> Service<Request> for AddHelloMarkerHeaderService<S>
where
    S: Service<Request>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        req.headers_mut()
            .insert("x-hello-marker", HeaderValue::from_static("1"));
        self.0.call(req)
    }
}

#[derive(Debug, Clone)]
struct TimeoutLayer(Duration);

#[derive(Debug, Clone, Default)]
struct TimeoutService<S> {
    inner: S,
    duration: Duration,
}

pin_project! {
    #[derive(Debug)]
    struct TimeoutResponseFuture<T> {
        #[pin]
        response: T,
        #[pin]
        sleep: Sleep,
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = TimeoutService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TimeoutService {
            inner,
            duration: self.0,
        }
    }
}

impl<S> Service<Request> for TimeoutService<S>
where
    S: Service<Request, Error: Into<BoxError>, Future: Send> + Clone + Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = TimeoutResponseFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(r) => std::task::Poll::Ready(r.map_err(Into::into)),
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let response = self.inner.call(req);
        let sleep = tokio::time::sleep(self.duration);
        TimeoutResponseFuture { response, sleep }
    }
}

impl<F, T, E> Future for TimeoutResponseFuture<F>
where
    F: Future<Output = Result<T, E>>,
    E: Into<BoxError>,
{
    type Output = Result<T, crate::BoxError>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();

        // First, try polling the future
        match this.response.poll(cx) {
            std::task::Poll::Ready(v) => return std::task::Poll::Ready(v.map_err(Into::into)),
            std::task::Poll::Pending => {}
        }

        // Now check the sleep
        match this.sleep.poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(_) => {
                std::task::Poll::Ready(Err(OpaqueError::from_display("Elapses").into_boxed()))
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
struct HelloSvc;

impl Service<Request> for HelloSvc {
    type Response = Html<&'static str>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        assert!(req.headers().contains_key("x-hello-marker"));
        ready(Ok(Html(
            r##"<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Rama + Tower</title>
    </head>
    <body>
        <p>
            <a href="https://ramaproxy.org">Rama</a>
            +
            <a href="https://github.com/tower-rs/tower">Tower</a>
        </p>
    </body>
</html>"##,
        )))
    }
}
