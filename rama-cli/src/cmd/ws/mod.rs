//! rama ws client

// e.g. can be used with <wss://echo.websocket.org>

use clap::Args;
use rama::{
    Context, Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    graceful::{self, Shutdown, ShutdownGuard},
    http::{
        Request, Response,
        client::{
            EasyHttpWebClient,
            proxy::layer::{HttpProxyAddressLayer, SetProxyAuthHttpHeaderLayer},
        },
        layer::{
            auth::AddAuthorizationLayer,
            decompression::DecompressionLayer,
            follow_redirect::{FollowRedirectLayer, policy::Limited},
            required_header::AddRequiredRequestHeadersLayer,
            timeout::TimeoutLayer,
        },
        ws::handshake::client::HttpClientWebSocketExt,
    },
    layer::MapResultLayer,
    net::{
        address::ProxyAddress,
        tls::{KeyLogIntent, client::ServerVerifyMode},
        user::{Basic, Bearer, ProxyCredential},
    },
    telemetry::tracing::level_filters::LevelFilter,
    tls::boring::client::{EmulateTlsProfileLayer, TlsConnectorDataBuilder},
    ua::{
        emulate::{
            UserAgentEmulateHttpConnectModifier, UserAgentEmulateHttpRequestModifier,
            UserAgentEmulateLayer, UserAgentSelectFallback,
        },
        profile::UserAgentDatabase,
    },
};
use std::{str::FromStr, sync::Arc, time::Duration};
use terminal_prompt::Terminal;
use tokio::{
    io::{self, AsyncBufReadExt, BufReader},
    sync::{mpsc, oneshot},
};

use crate::utils::http::HttpVersion;

#[derive(Args, Debug, Clone)]
/// rama ws client
pub struct CliCommandWs {
    #[arg(short = 'F', long)]
    /// follow Location redirects
    follow: bool,

    #[arg(short = 'v', long)]
    /// print verbose output, alias for --all --print hHbB
    verbose: bool,

    #[arg(long, default_value_t = 30)]
    /// the maximum number of redirects to follow
    max_redirects: usize,

    #[arg(long, short = 'P')]
    /// upstream proxy to use (can also be specified using PROXY env variable)
    proxy: Option<String>,

    #[arg(long, short = 'U')]
    /// upstream proxy user credentials to use (or overwrite)
    proxy_user: Option<String>,

    #[arg(long, short = 'a')]
    /// client authentication: `USER[:PASS]` | TOKEN,
    /// if basic and no password is given it will be promped
    auth: Option<String>,

    #[arg(long, short = 'A', default_value = "basic")]
    /// the type of authentication to use (basic, bearer)
    auth_type: String,

    #[arg(short = 'k', long)]
    /// skip Tls certificate verification
    insecure: bool,

    #[arg(long)]
    /// the desired tls version to use (automatically defined by default, choices are: 1.2, 1.3)
    tls: Option<String>,

    #[arg(long)]
    /// the client tls key file path to use
    cert_key: Option<String>,

    #[arg(long, short = 't', default_value = "0")]
    /// the timeout in seconds for each connection (0 = default timeout of 180s)
    timeout: u64,

    #[arg(long, short = 'E')]
    /// emulate user agent
    emulate: bool,

    #[arg(long, short = 'p', num_args = 1.., value_delimiter = ',')]
    /// WebSocket sub protocols to use
    protocols: Option<Vec<String>>,

    /// http version to use for the WebSocket handshake
    #[arg(long, default_value = "http/1.1")]
    http_version: HttpVersion,

    #[arg()]
    /// Uri to establish a WebSocket connection with
    uri: String,
}

/// Run the HTTP client command.
pub async fn run(cfg: CliCommandWs) -> Result<(), BoxError> {
    crate::trace::init_tracing(if cfg.verbose {
        LevelFilter::TRACE
    } else {
        LevelFilter::WARN
    });

    let (tx, rx) = oneshot::channel();
    let (tx_final, rx_final) = oneshot::channel();

    let shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = graceful::default_signal() => {
                let _ = tx_final.send(Ok(()));
            }
            result = rx => {
                match result {
                    Ok(result) => {
                        let _ = tx_final.send(result);
                    }
                    Err(_) => {
                        let _ = tx_final.send(Ok(()));
                    }
                }
            }
        }
    });

    shutdown.spawn_task_fn(async move |guard| {
        let result = run_inner(guard, cfg).await;
        let _ = tx.send(result);
    });

    let _ = shutdown.shutdown_with_limit(Duration::from_secs(1)).await;

    rx_final.await?
}

async fn run_inner(guard: ShutdownGuard, cfg: CliCommandWs) -> Result<(), BoxError> {
    let client = create_client(cfg.clone()).await?;

    let mut builder = match cfg.http_version {
        HttpVersion::Auto | HttpVersion::H1 => client.websocket(cfg.uri),
        HttpVersion::H2 => client.websocket_h2(cfg.uri),
    };

    if let Some(protocols) = cfg.protocols {
        builder.set_sub_protocols(protocols);
    }

    let mut socket = builder.handshake(Context::default()).await?;

    let (tx, mut rx) = mpsc::channel::<String>(32);

    #[allow(clippy::print_stdout)]
    // Spawn a task to manage all socket access
    let socket_task = guard.spawn_task(async move {
        loop {
            tokio::select! {
                Some(line) = rx.recv() => {
                    if let Err(err) = socket.send(line.into()).await {
                        return Err(err.context("send error"));
                    }
                }
                msg = socket.read() => {
                    match msg {
                        Ok(msg) => println!("<<< {msg}"),
                        Err(err) => {
                            if !err.is_connection_error() {
                                return Err(err.context("receive error"));
                            }
                            return Ok(());
                        }
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        let stdin = BufReader::new(io::stdin());
        let mut lines = stdin.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(line).await.is_err() {
                break;
            }
        }
    });

    socket_task.await?.map_err(|e| e.into_boxed())
}

async fn create_client<S>(
    cfg: CliCommandWs,
) -> Result<impl Service<S, Request, Response = Response, Error = BoxError>, BoxError>
where
    S: Clone + Send + Sync + 'static,
{
    let mut tls_config = if cfg.emulate {
        TlsConnectorDataBuilder::new()
    } else {
        match cfg.http_version {
            // NOTE: flow might be broken when in-mem upgrade http version between h1 and h2,
            // use at your own risk for now
            HttpVersion::Auto => TlsConnectorDataBuilder::new_http_auto(),
            HttpVersion::H1 => TlsConnectorDataBuilder::new_http_1(),
            HttpVersion::H2 => TlsConnectorDataBuilder::new_http_2(),
        }
    };
    tls_config.set_keylog_intent(KeyLogIntent::Environment);

    let mut proxy_tls_config = TlsConnectorDataBuilder::new();

    if cfg.insecure {
        tls_config.set_server_verify_mode(ServerVerifyMode::Disable);
        proxy_tls_config.set_server_verify_mode(ServerVerifyMode::Disable);
    }

    let inner_client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_boringssl_config(proxy_tls_config.into_shared_builder())
        .with_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config.into_shared_builder()))
        .with_jit_req_inspector(UserAgentEmulateHttpConnectModifier::default())
        .with_svc_req_inspector(UserAgentEmulateHttpRequestModifier::default())
        .build();

    // TODO: need to insert TLS separate from http:
    // - first tls is needed
    // - but http only is to be selected after handshake is done...

    let client_builder = (
        MapResultLayer::new(map_internal_client_error),
        cfg.emulate.then(|| {
            (
                UserAgentEmulateLayer::new(Arc::new(UserAgentDatabase::embedded()))
                    .try_auto_detect_user_agent(true)
                    .select_fallback(UserAgentSelectFallback::Random),
                EmulateTlsProfileLayer::new(),
            )
        }),
        (TimeoutLayer::new(if cfg.timeout > 0 {
            Duration::from_secs(cfg.timeout)
        } else {
            Duration::from_secs(180)
        })),
        FollowRedirectLayer::with_policy(Limited::new(if cfg.follow {
            cfg.max_redirects
        } else {
            0
        })),
        DecompressionLayer::new(),
        cfg.auth
            .as_deref()
            .map(|auth| match cfg.auth_type.trim().to_lowercase().as_str() {
                "basic" => {
                    let mut basic = Basic::from_str(auth).context("parse basic str")?;
                    if auth.ends_with(':') && basic.password().is_empty() {
                        let mut terminal =
                            Terminal::open().context("open terminal for password prompting")?;
                        let password = terminal
                            .prompt_sensitive("password: ")
                            .context("prompt password from terminal")?;
                        basic.set_password(password);
                    }
                    Ok::<_, OpaqueError>(AddAuthorizationLayer::new(basic).as_sensitive(true))
                }
                "bearer" => Ok(AddAuthorizationLayer::new(
                    Bearer::try_from(auth).context("parse bearer str")?,
                )),
                unknown => panic!("unknown auth type: {unknown} (known: basic, bearer)"),
            })
            .transpose()?
            .unwrap_or_else(AddAuthorizationLayer::none),
        AddRequiredRequestHeadersLayer::default(),
        match cfg.proxy {
            None => HttpProxyAddressLayer::try_from_env_default()?,
            Some(proxy) => {
                let mut proxy_address: ProxyAddress =
                    proxy.parse().context("parse proxy address")?;
                if let Some(proxy_user) = cfg.proxy_user {
                    let credential = ProxyCredential::Basic(
                        proxy_user
                            .parse()
                            .context("parse basic proxy credentials")?,
                    );
                    proxy_address.credential = Some(credential);
                }
                HttpProxyAddressLayer::maybe(Some(proxy_address))
            }
        },
        SetProxyAuthHttpHeaderLayer::default(),
    );

    Ok(client_builder.into_layer(inner_client))
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, BoxError>
where
    E: Into<BoxError>,
    Body: rama::http::dep::http_body::Body<Data = rama::bytes::Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
