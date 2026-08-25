//! Streaming ICAP echo service.

use std::{path::PathBuf, time::Duration};

use clap::Args;
use rama::{
    Layer as _,
    combinators::Either,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    graceful::ShutdownGuard,
    http::{Body, Request as HttpRequest, Response as HttpResponse, body::util::BodyExt as _},
    icap::{
        codec::{Header, ResponseLine},
        http::{DEFAULT_MAX_REPLAY_BYTES, IncomingRequest as HttpIncomingRequest},
        proto::{MethodKind, Preview, StatusCode, header},
        server::{IncomingRequest, OptionsResponse, OutgoingResponse, Server, ServerError},
    },
    layer::{
        ConsumeErrLayer, LimitLayer, MapErrLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, RatePolicy, UnlimitedPolicy},
    },
    net::{
        address::SocketAddress,
        stream::layer::{ThrottleLayer, ThrottleMode},
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{self, Instrument as _},
    tls::boring::server::TlsAcceptorLayer,
};

use crate::utils::{rate::opt_per_sec, tls::try_new_server_config_with_auth_files};

const SERVICE_TAG: &str = "\"rama-echo\"";

#[derive(Debug, Args)]
/// ICAP echo service for REQMOD and RESPMOD
pub struct CliCommandIcap {
    /// address to listen on
    #[arg(long, default_value_t = SocketAddress::local_ipv4(1344))]
    bind: SocketAddress,

    /// maximum concurrent connections (0 = no limit)
    #[arg(short = 'c', long, default_value_t = 0)]
    concurrent: usize,

    /// timeout in seconds for each connection (0 = no timeout)
    #[arg(short = 't', long, default_value_t = 300)]
    timeout: u64,

    /// rate limit new connections per second (0 = no limit)
    #[arg(long, default_value_t = 0)]
    rate: u64,

    /// throttle each connection in bytes per second, both directions
    /// (0 = no throttling)
    #[arg(long, default_value_t = 0)]
    throttle: u64,

    /// number of body bytes advertised for Preview
    #[arg(long, default_value_t = 1024)]
    preview: u64,

    /// OPTIONS response lifetime in seconds
    #[arg(long, default_value_t = 3600)]
    options_ttl: u64,

    /// maximum encapsulated body size retained for each echo
    #[arg(long, default_value_t = DEFAULT_MAX_REPLAY_BYTES)]
    body_limit: usize,

    /// enable TLS before ICAP protocol handling
    ///
    /// A self-signed certificate is generated unless `--cert` and `--key`,
    /// `RAMA_TLS_CRT` and `RAMA_TLS_KEY`, or a remote issuer are configured.
    #[arg(long)]
    secure: bool,

    /// PEM certificate chain; providing it also enables TLS
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,

    /// PEM private key; providing it also enables TLS
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
}

#[derive(Clone, Copy)]
struct EchoOptions {
    preview: Preview,
    options_ttl: u64,
    max_connections: Option<u64>,
    body_limit: usize,
}

/// Run the ICAP echo service.
pub async fn run(graceful: ShutdownGuard, cfg: CliCommandIcap) -> Result<(), BoxError> {
    let exec = Executor::graceful(graceful);
    let tls = (cfg.secure || cfg.cert.is_some())
        .then(|| {
            try_new_server_config_with_auth_files(
                cfg.cert.as_deref(),
                cfg.key.as_deref(),
                None,
                exec.clone(),
            )
        })
        .transpose()?;
    let options = EchoOptions {
        preview: Preview::new(cfg.preview),
        options_ttl: cfg.options_ttl,
        max_connections: (cfg.concurrent > 0)
            .then(|| u64::try_from(cfg.concurrent).unwrap_or(u64::MAX)),
        body_limit: cfg.body_limit,
    };
    let adaptation = service_fn(move |request| echo(request, options));
    let server = Server::new(adaptation, SERVICE_TAG)?;
    let server = MapErrLayer::new(|error: ServerError| BoxError::from(error)).into_layer(server);
    let service = (
        ConsumeErrLayer::trace_as(tracing::Level::DEBUG),
        opt_per_sec(Some(cfg.rate)).map(|rate| LimitLayer::new(RatePolicy::abort(rate))),
        LimitLayer::new(if cfg.concurrent > 0 {
            Either::A(ConcurrentPolicy::max(cfg.concurrent))
        } else {
            Either::B(UnlimitedPolicy::new())
        }),
        if cfg.timeout > 0 {
            TimeoutLayer::new(Duration::from_secs(cfg.timeout))
        } else {
            TimeoutLayer::never()
        },
        opt_per_sec(Some(cfg.throttle))
            .map(|rate| ThrottleLayer::symmetric(ThrottleMode::per_conn(rate))),
        tls.map(TlsAcceptorLayer::new),
    )
        .into_layer(server);

    let listener = TcpListener::build(exec.clone())
        .bind_address(cfg.bind)
        .await
        .context("bind ICAP echo service")?;
    let bind_address = listener
        .local_addr()
        .context("get ICAP echo service address")?;
    let secure = cfg.secure || cfg.cert.is_some();
    let span = tracing::trace_root_span!(
        "icap_echo",
        otel.kind = "server",
        network.protocol.name = "icap"
    );

    exec.spawn_task(async move {
        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            transport.secure = secure,
            "ICAP echo service ready: bind interface = {bind_address}"
        );
        listener.serve(service).instrument(span).await;
    });

    Ok(())
}

async fn echo(
    request: IncomingRequest,
    options: EchoOptions,
) -> Result<OutgoingResponse, BoxError> {
    let method = request.request().method();
    match method {
        MethodKind::Options => return options_response(options),
        MethodKind::Extension => {
            return Ok(
                HttpIncomingRequest::from_icap(request)?.respond_method_not_allowed(SERVICE_TAG)?
            );
        }
        MethodKind::Reqmod | MethodKind::Respmod => {}
    }

    let request = HttpIncomingRequest::from_icap(request)?;
    let line = ResponseLine::new(StatusCode::OK, b"OK")?;
    let fields = [Header::new(header::ISTAG, SERVICE_TAG.as_bytes())?];

    match method {
        MethodKind::Reqmod => {
            let (parts, body) = request.into_request()?.into_parts();
            let request =
                HttpRequest::from_parts(parts, buffer_echo_body(body, options.body_limit).await?);
            Ok(OutgoingResponse::from_http_request(line, &fields, request)?)
        }
        MethodKind::Respmod => {
            let (parts, body) = request.into_response()?.into_parts();
            let response =
                HttpResponse::from_parts(parts, buffer_echo_body(body, options.body_limit).await?);
            Ok(OutgoingResponse::from_http_response(
                MethodKind::Respmod,
                line,
                &fields,
                response,
            )?)
        }
        MethodKind::Options | MethodKind::Extension => Err(BoxError::from_static_str(
            "non-adaptation method reached ICAP echo response",
        )),
    }
}

async fn buffer_echo_body(body: Body, limit: usize) -> Result<Body, BoxError> {
    // ICAP permits a final response before the request body is complete. An
    // echo response depends on every input byte, so finish reading the bounded
    // request before sending the final response head.
    let body = body
        .limited(limit)
        .collect()
        .await
        .context("buffer ICAP echo body")?;
    Ok(Body::new(body))
}

fn options_response(options: EchoOptions) -> Result<OutgoingResponse, BoxError> {
    let mut response = OptionsResponse::new(SERVICE_TAG, "REQMOD, RESPMOD")
        .with_service("Rama ICAP echo service")
        .with_preview(options.preview)
        .with_transfer_preview_all(true)
        .with_options_ttl(options.options_ttl);
    if let Some(max_connections) = options.max_connections {
        response = response.with_max_connections(max_connections);
    }
    Ok(response.build()?)
}
