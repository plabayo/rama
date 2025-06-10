//! SSE Example, showcasing a very simple datastar example,
//! which is supported by rama both on the client as well as the server side.
//!
//! Datastar helps you build reactive web applications with the simplicity
//! of server-side rendering and the power of a full-stack SPA framework.
//!
//! It's the combination of a small js library which makes use of SSE among other utilities,
//! this module implements the event data types used from the server-side to send to the client,
//! which makes use of this JS library.
//!
//! This hello world example works with a global state, as such you should be able to open this
//! same page in multiple different user agents / browsers at once and see your interaction
//! and animation be in sync across all clients at all times. Try it. For most production applications however
//! you probably have scoped / specific states unique to the user (group) / target.
//!
//! Learn more at <https://ramaproxy.org/book/web_servers.html#datastar>.
//!
//! This example tried to apply the CQRS paradigm to the best of our knowledge, pull requests and feedback welcome as always.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_sse_datastar_hello --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62031`. You open the url in your browser to easily interact:
//!
//! ```sh
//! open http://127.0.0.1:62031
//! ```
//!
//! This will open a web page which will be a simple hello world data app.

use rama::{
    Context, Layer, Service,
    error::OpaqueError,
    graceful::ShutdownGuard,
    http::{
        Request, Response, StatusCode,
        layer::trace::TraceLayer,
        server::HttpServer,
        service::web::{
            Router,
            extract::datastar::ReadSignals,
            response::{Html, IntoResponse, Sse},
        },
        sse::{
            JsonEventData,
            datastar::{EventData, MergeFragments, MergeSignals},
            server::{KeepAlive, KeepAliveStream},
        },
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
};

use async_stream::stream;
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{broadcast, mpsc};
use tracing::{Instrument, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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

    let listener = TcpListener::bind(SocketAddress::default_ipv4(62031))
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(%bind_address, "http's tcp listener ready to serve");
    tracing::info!(
        "open http://{} in your browser to see the service in action",
        bind_address
    );

    let controller = Controller::new(graceful.guard());

    graceful.spawn_task_fn(async move |guard| {
        let exec = Executor::graceful(guard.clone());

        let router = Arc::new(
            Router::new()
                .get("/", handlers::index)
                .get("/start", handlers::start)
                .get("/hello-world", handlers::hello_world),
        );
        let graceful_router = GracefulRouter(router);

        let app = (TraceLayer::new_for_http()).into_layer(graceful_router);
        listener
            .with_state(controller)
            .serve_graceful(guard, HttpServer::auto(exec).service(app))
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Clone)]
struct GracefulRouter(Arc<Router<Controller>>);

impl Service<Controller, Request> for GracefulRouter {
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        ctx: Context<Controller>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        if ctx.state().is_closed() {
            tracing::debug!("router received request while shutting down: returning 401");
            return Ok(StatusCode::GONE.into_response());
        }
        self.0.serve(ctx, req).await
    }
}

pub mod handlers {
    use super::*;

    pub async fn index(ctx: Context<Controller>) -> Html<String> {
        let content = ctx.state().render_index();
        Html(content)
    }

    pub async fn start(
        ctx: Context<Controller>,
        ReadSignals(Signals { delay }): ReadSignals<Signals>,
    ) -> impl IntoResponse {
        ctx.state().reset(delay).await;
        StatusCode::OK
    }

    pub async fn hello_world(ctx: Context<Controller>) -> impl IntoResponse {
        let mut rx = ctx.state().subscribe();
        Sse::new(KeepAliveStream::new(
            KeepAlive::new(),
            stream! {
                while let Ok(msg) = rx.recv().await {
                    let data: EventData<_> = match msg {
                        Message::DataMergeFragment (data) => data.into(),
                        Message::DataMergeSignal(signals) => MergeSignals::new(JsonEventData(signals)).into(),
                        Message::Exit => {
                            tracing::debug!("exit message received, bye now!");
                            break;
                        }
                    };
                    tracing::trace!("send next event data");
                    yield Ok::<_, OpaqueError>(data.into_sse_event());
                }
                tracing::debug!("exit hello world stream loop, bye!");
            },
        ))
    }
}

pub mod controller {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize)]
    pub struct Signals {
        pub delay: u64,
    }

    #[derive(Debug, Clone, Default, Serialize)]
    pub struct UpdateSignals {
        pub delay: Option<u64>,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum Command {
        Reset(u64),
        Exit,
    }

    #[derive(Debug, Clone)]
    pub enum Message {
        Exit,
        DataMergeFragment(MergeFragments),
        DataMergeSignal(UpdateSignals),
    }

    #[derive(Debug, Clone)]
    pub struct Controller {
        is_closed: Arc<AtomicBool>,

        delay: Arc<AtomicU64>,
        anim_index: Arc<AtomicUsize>,

        cmd_tx: mpsc::Sender<Command>,
        msg_tx: broadcast::Sender<Message>,
    }

    impl Controller {
        const MESSAGE: &str = "Hello, datastar!";

        pub fn new(guard: ShutdownGuard) -> Self {
            let (cmd_tx, cmd_rx) = mpsc::channel(1024);
            let (msg_tx, msg_rx) = broadcast::channel(1024);

            let exit_cmd_tx = cmd_tx.clone();
            let weak_guard = guard.clone_weak();
            tokio::spawn(
                async move {
                    tracing::debug!("exit worker up and running awaiting cancellation");
                    weak_guard.into_cancelled().await;
                    tracing::trace!("shutdown initiated, send exit command to controller runtime");
                    if let Err(err) = exit_cmd_tx.send(Command::Exit).await {
                        tracing::error!(%err, "failed to send exit cmd")
                    }
                }
                .instrument(tracing::trace_span!("exit worker")),
            );

            let delay = Arc::new(AtomicU64::new(400));
            let anim_index = Arc::new(AtomicUsize::new(Self::MESSAGE.len()));

            let controller = Controller {
                is_closed: Arc::new(AtomicBool::new(false)),

                delay,
                anim_index,

                cmd_tx,

                msg_tx,
            };

            guard.into_spawn_task(
                controller
                    .clone()
                    .into_runtime(msg_rx, cmd_rx)
                    .instrument(tracing::trace_span!("runtime worker")),
            );

            controller
        }

        pub fn is_closed(&self) -> bool {
            self.is_closed.load(Ordering::Acquire)
        }

        pub async fn reset(&self, delay: u64) {
            if let Err(err) = self.cmd_tx.send(Command::Reset(delay)).await {
                tracing::warn!(%err, "failed to send reset command");
            }
        }

        pub fn subscribe(&self) -> broadcast::Receiver<Message> {
            self.msg_tx.subscribe()
        }

        pub fn render_index(&self) -> String {
            format!(
                r##"<!DOCTYPE html>
        <html lang="en">
        <head>
            <title>Datastar SDK Demo</title>
            <script src="https://unpkg.com/@tailwindcss/browser@4"></script>
            <script type="module" src="https://cdn.jsdelivr.net/gh/starfederation/datastar@v1.0.0-beta.11/bundles/datastar.js"></script>
        </head>
        <body class="bg-white dark:bg-gray-900 text-lg max-w-xl mx-auto my-16">
            <div data-signals-delay="{}"
                    class="bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400 rounded-lg px-6 py-8 ring shadow-xl ring-gray-900/5 space-y-2">
                <div class="flex justify-between items-center">
                    <h1 class="text-gray-900 dark:text-white text-3xl font-semibold">
                        Datastar SDK Demo
                    </h1>
                    <img src="https://data-star.dev/static/images/rocket.png" alt="Rocket" width="64" height="64"/>
                </div>

                <p class="mt-2">
                    SSE events will be streamed from the backend to the frontend.
                </p>
                <div class="space-x-2">
                    <label for="delay">
                        Delay in milliseconds
                    </label>
                    <input data-bind-delay id="delay" type="number" step="100" min="0" class="w-36 rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-sky-500 focus:outline focus:outline-sky-500 dark:disabled:border-gray-700 dark:disabled:bg-gray-800/20" />
                </div>
                <button data-on-click="@get(&#39;/start&#39;)" class="rounded-md bg-sky-500 px-5 py-2.5 leading-5 font-semibold text-white hover:bg-sky-700 hover:text-gray-100 cursor-pointer">
                Start
                </button>
            </div>
            <div class="my-16 text-8xl font-bold text-transparent" style="background: linear-gradient(to right in oklch, red, orange, yellow, green, blue, blue, violet); background-clip: text">
                <div
                    data-on-load="@get('/hello-world')"
                    id="message">
                    {}
                </div>
            </div>
            <div class="text-gray-900 dark:text-white">
                <pre data-text="ctx.signals.JSON()">Signals</pre>
            </div>
        </body>
        </html>"##,
                self.delay.load(Ordering::Acquire),
                &Self::MESSAGE[..self.anim_index.load(Ordering::Acquire)],
            )
        }

        async fn into_runtime(
            self,
            _msg_rx: broadcast::Receiver<Message>,
            mut cmd_rx: mpsc::Receiver<Command>,
        ) {
            #[derive(Debug, Clone, Copy)]
            enum State {
                Play,
                Stop,
            }
            let mut state = State::Stop;

            let mut recv_cmd = async || {
                // Assumption: channel can never close as `Controller` owns one sender
                let cmd = cmd_rx.recv().await.unwrap();
                match cmd {
                    Command::Reset(delay) => {
                        self.delay.store(delay, Ordering::Release);
                        if let Err(err) =
                            self.msg_tx.send(Message::DataMergeSignal(UpdateSignals {
                                delay: Some(delay),
                            }))
                        {
                            tracing::error!(%err, "failed to update delay signal via broadcast");
                        }
                    }
                    Command::Exit => {
                        self.is_closed.store(true, Ordering::Release);
                        tracing::debug!("exit command received: exit controller");
                        if let Err(err) = self.msg_tx.send(Message::Exit) {
                            tracing::error!(%err, "failed to send exit message to subscribers");
                        }
                    }
                }
                cmd
            };

            loop {
                match state {
                    State::Play => {
                        tokio::select! {
                            biased;

                            cmd = recv_cmd() => {
                                match cmd {
                                    Command::Reset(_) => {
                                        state = State::Play;
                                        self.anim_index.store(0, Ordering::Release);
                                    },
                                    Command::Exit => return,
                                }
                            }
                            _ = std::future::ready(()) => {}
                        }

                        let index = self.anim_index.fetch_add(1, Ordering::AcqRel) + 1;
                        let delay = Duration::from_millis(self.delay.load(Ordering::Acquire));
                        tracing::debug!(?delay, %index, "animation: play frame");
                        let msg = &Self::MESSAGE[..index];
                        let fragment =
                            MergeFragments::new(format!("<div id='message'>{}</div>", msg));
                        match self.msg_tx.send(Message::DataMergeFragment(fragment)) {
                            Err(err) => {
                                tracing::error!(%err, "failed to merge fragment via broadcast")
                            }
                            Ok(_) => tokio::time::sleep(delay).await,
                        }

                        if index >= Self::MESSAGE.len() {
                            tracing::debug!("stop animation: end reached: stop");
                            state = State::Stop;
                        }
                    }
                    State::Stop => match recv_cmd().await {
                        Command::Reset(_) => {
                            state = State::Play;
                            self.anim_index.store(0, Ordering::Release);
                        }
                        Command::Exit => return,
                    },
                }
            }
        }
    }
}
use controller::{Controller, Message, Signals};
