//! An example to showcase how one can build an unauthenticated http proxy server.
//!
//! This example also demonstrates how one can define their own username label parser,
//! next to the built-in username label parsers.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_connect_proxy --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62001`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62001 --proxy-user 'john:secret' http://www.example.com/
//! curl -v -x http://127.0.0.1:62001 --proxy-user 'john-red-blue:secret' http://www.example.com/
//! curl -v -x http://127.0.0.1:62001 --proxy-user 'john-priority-high-red-blue:secret' http://www.example.com/
//! curl -v -x http://127.0.0.1:62001 --proxy-user 'john:secret' https://www.example.com/
//! ```
//! The pseudo API can be used as follows:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62001 --proxy-user 'john:secret' http://echo.example.internal/foo/bar
//! curl -v -x http://127.0.0.1:62001 --proxy-user 'john-red-blue-priority-low:secret' http://echo.example.internal/foo/bar
//! curl -v -x http://127.0.0.1:62001 --proxy-user 'john:secret' -XPOST http://echo.example.internal/lucky/7
//! ```
//!
//! You should see in all the above examples the responses from the server.
//!
//! If you want to see the HTTP traffic in action you can of course also use telnet instead:
//!
//! ```sh
//! telnet 127.0.0.1 62001
//! ```
//!
//! and then type:
//!
//! ```
//! CONNECT example.com:80 HTTP/1.1
//! Host: example.com:80
//! Proxy-Authorization: basic am9objpzZWNyZXQ=
//!
//!
//! GET / HTTP/1.1
//! HOST: example.com:80
//! Connection: close
//!
//!
//! ```
//!
//! You should see the same response as when running:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62001 --proxy-user 'john:secret' http://www.example.com/
//! ```

use rama::{
    context::Extensions,
    http::{
        client::HttpClient,
        layer::{
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::{DomainMatcher, HttpMatcher, MethodMatcher},
        response::Json,
        server::HttpServer,
        service::web::{extract::Path, match_service},
        Body, IntoResponse, Request, Response, StatusCode,
    },
    layer::HijackLayer,
    net::http::RequestContext,
    net::stream::layer::http::BodyLimitLayer,
    net::{address::Domain, user::Basic},
    rt::Executor,
    service::service_fn,
    tcp::{server::TcpListener, utils::is_connection_error},
    username::{
        UsernameLabelParser, UsernameLabelState, UsernameLabels, UsernameOpaqueLabelParser,
    },
    Context, Layer, Service,
};
use serde::Deserialize;
use serde_json::json;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

    #[derive(Deserialize)]
    /// API parameters for the lucky number endpoint
    struct APILuckyParams {
        number: u32,
    }

    graceful.spawn_task_fn(|guard| async move {
        let tcp_service = TcpListener::build().bind("127.0.0.1:62001").await.expect("bind tcp proxy to 127.0.0.1:62001");

        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec)
            .service((
                    TraceLayer::new_for_http(),
                    // See [`ProxyAuthLayer::with_labels`] for more information,
                    // e.g. can also be used to extract upstream proxy filters
                    ProxyAuthLayer::new(Basic::new("john", "secret")).with_labels::<(PriorityUsernameLabelParser, UsernameOpaqueLabelParser)>(),
                    // example of how one might insert an API layer into their proxy
                    HijackLayer::new(
                        DomainMatcher::exact(Domain::from_static("echo.example.internal")),
                        Arc::new(match_service!{
                            HttpMatcher::post("/lucky/:number") => |path: Path<APILuckyParams>| async move {
                                Json(json!({
                                    "lucky_number": path.number,
                                }))
                            },
                            HttpMatcher::get("/*") => |ctx: Context<()>, req: Request| async move {
                                Json(json!({
                                    "method": req.method().as_str(),
                                    "path": req.uri().path(),
                                    "username_labels": ctx.get::<UsernameLabels>().map(|labels| &labels.0),
                                    "user_priority": ctx.get::<Priority>().map(|p| match p {
                                        Priority::High => "high",
                                        Priority::Medium => "medium",
                                        Priority::Low => "low",
                                    }),
                                }))
                            },
                            _ => StatusCode::NOT_FOUND,
                        })
                    ),
                    UpgradeLayer::new(
                        MethodMatcher::CONNECT,
                        service_fn(http_connect_accept),
                        service_fn(http_connect_proxy),
                    ),
                    RemoveResponseHeaderLayer::hop_by_hop(),
                    RemoveRequestHeaderLayer::hop_by_hop(),
                )
            .layer(service_fn(http_plain_proxy)));

            tcp_service.serve_graceful(guard, (
                // protect the http proxy from too large bodies, both from request and response end
                BodyLimitLayer::symmetric(2 * 1024 * 1024),
            ).layer(http_service)).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_connect_accept<S>(
    mut ctx: Context<S>,
    req: Request,
) -> Result<(Response, Context<S>, Request), Response>
where
    S: Clone + Send + Sync + 'static,
{
    match ctx.get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into()) {
        Ok(request_ctx) => tracing::info!("accept CONNECT to {}", request_ctx.authority),
        Err(err) => {
            tracing::error!(err = %err, "error extracting authority");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_connect_proxy<S>(ctx: Context<S>, mut upgraded: Upgraded) -> Result<(), Infallible>
where
    S: Clone + Send + Sync + 'static,
{
    let authority = ctx // assumption validated by `http_connect_accept`
        .get::<RequestContext>()
        .unwrap()
        .authority
        .to_string();
    tracing::info!("CONNECT to {}", authority);
    let mut stream = match tokio::net::TcpStream::connect(authority).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::error!(error = %err, "error connecting to host");
            return Ok(());
        }
    };
    if let Err(err) = tokio::io::copy_bidirectional(&mut upgraded, &mut stream).await {
        if !is_connection_error(&err) {
            tracing::error!(error = %err, "error copying data");
        }
    }
    Ok(())
}

async fn http_plain_proxy<S>(ctx: Context<S>, req: Request) -> Result<Response, Infallible>
where
    S: Clone + Send + Sync + 'static,
{
    let client = HttpClient::default();
    match client.serve(ctx, req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!(error = %err, "error in client request");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Default)]
pub struct PriorityUsernameLabelParser {
    key_seen: bool,
    priority: Option<Priority>,
}

impl UsernameLabelParser for PriorityUsernameLabelParser {
    type Error = Infallible;

    fn parse_label(&mut self, label: &str) -> UsernameLabelState {
        let label = label.trim().to_ascii_lowercase();

        if self.key_seen {
            self.key_seen = false;
            match label.as_str() {
                "high" => self.priority = Some(Priority::High),
                "medium" => self.priority = Some(Priority::Medium),
                "low" => self.priority = Some(Priority::Low),
                _ => {
                    tracing::trace!("invalid priority username label value: {label}");
                    return UsernameLabelState::Abort;
                }
            }
        } else if label == "priority" {
            self.key_seen = true;
        }

        UsernameLabelState::Used
    }

    fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
        ext.maybe_insert(self.priority);
        Ok(())
    }
}
