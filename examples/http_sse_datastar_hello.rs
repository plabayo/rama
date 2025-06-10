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
            response::{DatastarScript, Html, IntoResponse, Sse},
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
                .get("/hello-world", handlers::hello_world)
                .get("/assets/datastar.js", DatastarScript::default()),
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
                yield Ok(EventData::from(MergeFragments::new(r##"<div id="sse-status">🟢</div>"##)).into_sse_event());

                while let Ok(msg) = rx.recv().await {
                    let data: EventData<_> = match msg {
                        Message::DataMergeFragments (data) => data.into(),
                        Message::DataMergeSignals(signals) => MergeSignals::new(JsonEventData(signals)).into(),
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
        DataMergeFragments(MergeFragments),
        DataMergeSignals(UpdateSignals),
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
            let delay = self.delay.load(Ordering::Acquire);
            let anim_index = self.anim_index.load(Ordering::Acquire);

            let progress = (anim_index as f64) / (Self::MESSAGE.len() as f64) * 100f64;

            let text = &Self::MESSAGE[..anim_index];

            tracing::debug!(
                %delay,
                %anim_index,
                %progress,
                %text,
                "render index"
            );

            format!(
                r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>Datastar Rama Demo</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2210 0 100 100%22><text y=%22.90em%22 font-size=%2290%22>🦙</text></svg>">
    <script type="module" src="/assets/datastar.js"></script>
    <style>
        :root {{
            color-scheme: light dark;
            --bg-light: #ffffff;
            --bg-dark: #1f2937;
            --text-light: #6b7280;
            --text-dark: #9ca3af;
            --card-bg-light: #ffffff;
            --card-bg-dark: #374151;
            --text-heading-light: #111827;
            --text-heading-dark: #ffffff;
            --ring-color: rgba(17, 24, 39, 0.05);
            --input-border: #d1d5db;
            --input-placeholder: #9ca3af;
            --btn-bg: #0ea5e9;
            --btn-bg-hover: #0369a1;
        }}

        body {{
            margin: 0;
            padding: 0;
            font-size: 1.125rem;
            font-family: sans-serif;
            background-color: var(--bg-light);
            color: var(--text-light);
            max-width: 48rem;
            margin: 4rem auto;
        }}

        @media (prefers-color-scheme: dark) {{
            body {{
                background-color: var(--bg-dark);
                color: var(--text-dark);
            }}
        }}

        .card {{
            background-color: var(--card-bg-light);
            color: var(--text-light);
            border-radius: 0.5rem;
            padding: 2rem 1.5rem;
            box-shadow: 0 10px 15px -3px var(--ring-color),
                        0 4px 6px -4px var(--ring-color);
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}

        @media (prefers-color-scheme: dark) {{
            .card {{
                background-color: var(--card-bg-dark);
                color: var(--text-dark);
            }}
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .card-header h1 {{
            font-size: 1.875rem;
            font-weight: 600;
            color: var(--text-heading-light);
        }}

        @media (prefers-color-scheme: dark) {{
            .card-header h1 {{
                color: var(--text-heading-dark);
            }}
        }}

        .input-group {{
            margin-top: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        input[type="number"] {{
            width: 9rem;
            border-radius: 0.375rem;
            border: 1px solid var(--input-border);
            padding: 0.5rem 0.75rem;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
        }}

        input::placeholder {{
            color: var(--input-placeholder);
        }}

        input:focus {{
            border-color: var(--btn-bg);
            outline: 2px solid var(--btn-bg);
        }}

        button {{
            margin-top: 1rem;
            background-color: var(--btn-bg);
            color: white;
            font-weight: 600;
            padding: 0.625rem 1.25rem;
            border: none;
            border-radius: 0.375rem;
            cursor: pointer;
        }}

        button:hover {{
            background-color: var(--btn-bg-hover);
            color: #f3f4f6;
        }}

        .gradient-text {{
            margin-top: 4rem;
            font-size: 6rem;
            font-weight: bold;
            background: linear-gradient(to right in oklch, red, orange, yellow, green, blue, blue, violet);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        #progress-bar-container {{
          height: 8px;
          background-color: #e5e7eb; /* light gray */
          border-radius: 4px;
          overflow: hidden;
          margin-top: 1rem;
        }}

        #progress-bar {{
          height: 100%;
          width: 100%;
          background: linear-gradient(90deg, #3b82f6, #06b6d4); /* blue -> cyan */
        }}
    </style>
</head>
<body data-on-load="@get('/hello-world')">
    <div data-signals-delay="{delay}" class="card">
        <div class="card-header">
            <h1>🦙💬 "hello 🚀 data-*"</h1>
            <div id="sse-status">🔴</div>
        </div>

        <p>
            <a href="https://ramaproxy.org/book/sse.html">SSE events</a> will be streamed from the backend to the frontend.
        </p>
        <p>
            Learn more <a href="https://ramaproxy.org/book/web_servers.html#datastar">in the rama book</a>.
        </p>

        <div class="input-group">
            <label for="delay">Delay in milliseconds</label>
            <input data-bind-delay id="delay" type="number" step="100" min="0" />
        </div>

        <button data-on-click="@get('/start')">Start</button>
    </div>

    <div id="progress-bar-container">
      <div id="progress-bar" style="width: {progress}%"></div>
    </div>

    <div class="gradient-text">
        <div id="message">
            {text}
        </div>
    </div>
</body>
</html>
"##,
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
                            self.msg_tx.send(Message::DataMergeSignals(UpdateSignals {
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

                        let anim_index = self.anim_index.fetch_add(1, Ordering::AcqRel) + 1;
                        let delay = Duration::from_millis(self.delay.load(Ordering::Acquire));
                        let text = &Self::MESSAGE[..anim_index];
                        let progress = (anim_index as f64) / (Self::MESSAGE.len() as f64) * 100f64;
                        tracing::debug!(?delay, %anim_index, %progress, %text, "animation: play frame");

                        let fragment = MergeFragments::new(format!(
                            r##"
                                <div id='message'>{text}</div>
                                <div id="progress-bar" style="width: {progress}%"></div>
                            "##,
                        ));
                        match self.msg_tx.send(Message::DataMergeFragments(fragment)) {
                            Err(err) => {
                                tracing::error!(%err, "failed to merge fragment via broadcast")
                            }
                            Ok(_) => tokio::time::sleep(delay).await,
                        }

                        if anim_index >= Self::MESSAGE.len() {
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
