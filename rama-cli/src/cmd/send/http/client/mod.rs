use rama::{
    Layer, Service,
    error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt, extra::OpaqueError},
    extensions::Extension,
    http::{
        Body, Request, Response, StreamingBody,
        client::{
            EasyHttpWebClient, ProxyConnectorLayer,
            proxy::layer::{
                HttpProxyAddressLayer, HttpProxyConnectorLayer, SetProxyAuthHttpHeaderLayer,
            },
        },
        layer::{
            auth::AddAuthorizationLayer,
            follow_redirect::{
                FollowRedirectLayer,
                policy::{FilterCredentials, Limited, PolicyExt},
            },
            required_header::AddRequiredRequestHeadersLayer,
        },
    },
    json::path::JsonPath,
    layer::{HijackLayer, MapErrLayer, MapResultLayer, TimeoutLayer, layer_fn},
    net::user::{Basic, ProxyCredential},
    proxy::socks5::Socks5ProxyConnectorLayer,
    rt::Executor,
    tls::boring::client::{BoringClientConfigExt, EmulateTlsProfileLayer},
    tls::{
        ProtocolVersion,
        client::{ServerVerifyMode, TlsClientConfig},
    },
    ua::{
        layer::emulate::{
            UserAgentEmulateHttpConnectModifierLayer, UserAgentEmulateHttpRequestModifierLayer,
            UserAgentEmulateLayer, UserAgentSelectFallback,
        },
        profile::UserAgentDatabase,
    },
};

use std::{str::FromStr as _, sync::Arc, time::Duration};
use terminal_prompt::Terminal;

use crate::cmd::send::layer::resolve::OptDnsOverwriteLayer;

use super::{SendCommand, arg::HttpHeader};

mod logger_body_res;
mod logger_headers_req;
mod logger_headers_res;
mod logger_l4;
mod logger_tls;

mod curl_writer;
mod writer;

pub(super) async fn new(
    cfg: &SendCommand,
    feed_tui: bool,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError>, BoxError> {
    let writer = writer::try_new(cfg).await?;
    let json_selectors: Arc<[JsonPath]> = cfg.select_json.clone().into();

    let inner_client = new_inner_client(cfg)?;

    let show_headers = cfg.show_headers;
    let client_builder = (
        MapResultLayer::new(map_internal_client_error),
        layer_fn({
            let writer = writer.clone();
            move |inner| logger_body_res::ResponseBodyLogger {
                inner,
                writer: writer.clone(),
                feed_tui: feed_tui && json_selectors.is_empty(),
                json_selectors: json_selectors.clone(),
            }
        }),
        cfg.emulate
            .then(|| {
                Ok::<_, BoxError>((
                    UserAgentEmulateLayer::new(Arc::new(UserAgentDatabase::try_embedded()?))
                        .with_try_auto_detect_user_agent(true)
                        .with_select_fallback(UserAgentSelectFallback::Random),
                    EmulateTlsProfileLayer::new(),
                ))
            })
            .transpose()?,
        // Outer to FollowRedirect: `--user` credentials authenticate to the original origin, so
        // FilterCredentials must be able to strip them on a cross-origin hop.
        cfg.user
            .as_deref()
            .map(|auth| {
                let mut basic = Basic::from_str(auth).context("parse basic str")?;
                if auth.ends_with(':') && basic.password().is_none() {
                    let mut terminal =
                        Terminal::open().context("open terminal for password prompting")?;
                    let password = terminal
                        .prompt_sensitive("password: ")
                        .context("prompt password from terminal")?
                        .parse()
                        .context("parse password as non-empty-str")?;
                    basic.set_password(password);
                }
                Ok::<_, BoxError>(AddAuthorizationLayer::new(basic).with_sensitive(true))
            })
            .transpose()?
            .unwrap_or_else(AddAuthorizationLayer::none),
        // Kept unconditional even at a limit of 0: making it an `Option` adds a type level that
        // tips this stack over rustc's query depth limit, and one skipped fork per process is
        // nothing to a one-shot CLI request.
        FollowRedirectLayer::with_policy(
            Limited::new(redirect_limit(cfg)).and::<_, Body, OpaqueError>(
                FilterCredentials::new()
                    .with_block_cross_origin(!cfg.location_trusted)
                    .with_remove_blocklisted(!cfg.location_trusted),
            ),
        ),
        // Inner to FollowRedirect: `--resolve` matches on host:port, so it has to be evaluated
        // against each hop's real target instead of the original one.
        OptDnsOverwriteLayer::new(cfg.resolve.clone()),
        // Moved along with it: `--proxy` stamps one static route, so being consulted per hop is
        // behaviour-neutral today, and stays right if it ever becomes target-aware.
        match cfg.proxy.clone() {
            None => HttpProxyAddressLayer::try_from_env_default()?,
            Some(mut proxy_address) => {
                if let Some(credentials) = cfg.proxy_user.clone() {
                    proxy_address.credential = Some(ProxyCredential::Basic(credentials));
                }
                HttpProxyAddressLayer::maybe(Some(proxy_address))
            }
        },
        // Inner to FollowRedirect: proxy credentials are per-hop and authenticate
        // to the (same) proxy, so they must be re-applied on every redirect rather
        // than stripped by FilterCredentials' cross-origin rule like origin creds.
        SetProxyAuthHttpHeaderLayer::default(),
        AddRequiredRequestHeadersLayer::default(),
        HijackLayer::new(cfg.curl, curl_writer::CurlWriter { writer }),
        MapErrLayer::into_box_error(),
        layer_fn(move |svc| logger_headers_res::ResponseHeaderLogger {
            inner: svc,
            show_headers,
        }),
    );

    Ok(client_builder.into_layer(inner_client))
}

fn redirect_limit(cfg: &SendCommand) -> usize {
    compute_redirect_limit(cfg.location, cfg.location_trusted, cfg.max_redirs)
}

fn compute_redirect_limit(location: bool, location_trusted: bool, max_redirs: isize) -> usize {
    // Redirects only follow when --location or --location-trusted is set.
    if !(location || location_trusted) {
        return 0;
    }

    // curl semantics: --max-redirs -1 means unlimited.
    if max_redirs < 0 {
        usize::MAX
    } else {
        max_redirs as usize
    }
}

fn new_inner_client(
    cfg: &SendCommand,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, BoxError> {
    let mut tls_config = if cfg.emulate {
        TlsClientConfig::new()
    } else {
        TlsClientConfig::new().with_alpn_http_auto()
    };

    if cfg.verbose {
        tls_config.set_store_server_cert_chain(true);
    }

    if let Some(min_ssl_version) = match (cfg.tls_v10, cfg.tls_v11, cfg.tls_v12, cfg.tls_v13) {
        (true, false, false, false) => Some(ProtocolVersion::TLSv1_0),
        (false, true, false, false) => Some(ProtocolVersion::TLSv1_1),
        (false, false, true, false) => Some(ProtocolVersion::TLSv1_2),
        (false, false, false, true) => Some(ProtocolVersion::TLSv1_3),
        (false, false, false, false) => None,
        _ => Err(BoxError::from_static_str(
            "--tlsv1.0, --tlsv1.1, --tlsv1.2, --tlsv1.3 are mutually exclusive",
        ))?,
    } {
        tls_config.set_min_version(min_ssl_version);
    }

    if let Some(max_ssl_version) = cfg.tls_max.as_ref() {
        let max_ssl_version = match max_ssl_version {
            crate::cmd::send::arg::TlsVersion::V10 => ProtocolVersion::TLSv1_0,
            crate::cmd::send::arg::TlsVersion::V11 => ProtocolVersion::TLSv1_1,
            crate::cmd::send::arg::TlsVersion::V12 => ProtocolVersion::TLSv1_2,
            crate::cmd::send::arg::TlsVersion::V13 => ProtocolVersion::TLSv1_3,
        };
        tls_config.set_max_version(max_ssl_version);
    }

    let mut proxy_tls_config = TlsClientConfig::new();

    if cfg.insecure {
        tls_config.set_server_verify(ServerVerifyMode::Disable);
    }
    if cfg.proxy_insecure {
        proxy_tls_config.set_server_verify(ServerVerifyMode::Disable);
    }

    let mut http_proxy_connector = HttpProxyConnectorLayer::required();
    for HttpHeader { name, value } in &cfg.proxy_header {
        http_proxy_connector.set_custom_header(name.clone(), value.clone());
    }

    let proxy_connector =
        ProxyConnectorLayer::optional(Socks5ProxyConnectorLayer::required(), http_proxy_connector);

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_custom_connector(layer_fn(logger_l4::TransportConnInfoLogger))
        .with_tls_proxy_support_using_boringssl_config(proxy_tls_config)
        .with_custom_proxy_connector(proxy_connector)
        .with_tls_support_using_boringssl(tls_config)
        .with_custom_connector(layer_fn(logger_tls::TlsInfoLogger))
        .with_custom_connector(UserAgentEmulateHttpConnectModifierLayer::default())
        .with_default_http_connector(Executor::default())
        .with_custom_connector(
            if let Some(timeout) = cfg.connect_timeout
                && timeout > 0.
            {
                TimeoutLayer::new(Duration::from_secs_f64(timeout))
            } else {
                TimeoutLayer::never()
            },
        )
        .without_connection_pool()
        .build_client()
        .with_jit_layer((
            UserAgentEmulateHttpRequestModifierLayer::default(),
            logger_headers_req::RequestHeaderLoggerLayer::default(),
        ));

    Ok(client)
}

#[derive(Debug, Clone, Copy, Extension)]
pub(super) struct VerboseLogs;

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, OpaqueError>
where
    E: Into<BoxError>,
    Body: StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into_opaque_error()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use clap::Parser as _;
    use rama::{
        http::{StatusCode, header::LOCATION, server::HttpServer},
        net::address::SocketAddress,
        service::service_fn,
        tcp::server::TcpListener,
    };

    use super::*;

    /// Lets clap build a real [`SendCommand`], so the layer stack under test is the one `rama send`
    /// actually runs.
    #[derive(clap::Parser)]
    struct TestCli {
        #[command(flatten)]
        send: SendCommand,
    }

    fn send_cfg(args: &[&str]) -> SendCommand {
        TestCli::parse_from(std::iter::once("rama-send-test").chain(args.iter().copied())).send
    }

    /// Serve `handler` on an ephemeral loopback port and return its address.
    async fn spawn_origin<S>(handler: S) -> SocketAddress
    where
        S: Service<Request, Output = Response, Error = Infallible> + Clone,
    {
        let exec = Executor::default();
        let listener = TcpListener::build(exec.clone())
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = HttpServer::auto(exec.clone()).service(handler);
        exec.into_spawn_task(async move { listener.serve(Arc::new(server)).await });
        addr.into()
    }

    /// Drives the real `rama send` client stack through a cross-origin redirect and checks both
    /// halves of the ordering it depends on: `--user` is dropped on the cross-origin hop (its layer
    /// sits outside `FollowRedirect`, so `FilterCredentials` can strip the header), while `--resolve`
    /// is re-evaluated for the redirect target (its layer sits inside, so the second hop resolves at
    /// all). Getting either side of `FollowRedirectLayer` wrong fails this test.
    #[tokio::test]
    async fn send_client_stack_orders_layers_around_follow_redirect() {
        assert!(
            std::env::var_os("HTTP_PROXY").is_none(),
            "this test drives the real client stack, which honors HTTP_PROXY; unset it to run",
        );

        let saw_authorization = Arc::new(AtomicBool::new(false));
        let target_hits = Arc::new(AtomicUsize::new(0));
        let target = spawn_origin(service_fn({
            let saw_authorization = saw_authorization.clone();
            let target_hits = target_hits.clone();
            move |req: Request| {
                target_hits.fetch_add(1, Ordering::AcqRel);
                saw_authorization.store(
                    req.headers()
                        .contains_key(rama::http::header::AUTHORIZATION),
                    Ordering::Release,
                );
                async { Ok::<_, Infallible>(Response::new(Body::from("done"))) }
            }
        }))
        .await;

        // Only the redirect target's port is overwritten, so hop 2 resolves `redirect.example` only
        // when `--resolve` is consulted with that hop's own target.
        let start = spawn_origin(service_fn(move |_req: Request| async move {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(
                        LOCATION,
                        format!("http://redirect.example:{}/final", target.port),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
        }))
        .await;

        let uri = format!("http://{start}/start");
        let out_path = std::env::temp_dir().join("rama-send-redirect-order.out");
        let cfg = send_cfg(&[
            "--location",
            "--user",
            "someone:secret",
            "--resolve",
            &format!("*:{}:127.0.0.1", target.port),
            "--max-time",
            "10",
            "--output",
            &out_path.display().to_string(),
            &uri,
        ]);

        let svc = new(&cfg, false).await.unwrap();
        let res = svc
            .serve(
                Request::builder()
                    .uri(uri.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        // Guards against a false pass: the final hop has to have landed on *our* redirect target,
        // not on whatever a DNS resolver might hand back for `redirect.example`.
        assert_eq!(target_hits.load(Ordering::Acquire), 1);
        assert!(
            !saw_authorization.load(Ordering::Acquire),
            "`--user` credentials reached a cross-origin redirect target",
        );

        std::fs::remove_file(&out_path).expect("clean up the response output file");
    }

    #[test]
    fn redirect_limit_disabled_without_location() {
        // No redirects unless --location or --location-trusted is set.
        assert_eq!(compute_redirect_limit(false, false, 50), 0);
        assert_eq!(compute_redirect_limit(false, false, -1), 0);
    }

    #[test]
    fn redirect_limit_location_trusted_alone_enables_redirects() {
        assert_eq!(compute_redirect_limit(false, true, 50), 50);
    }

    #[test]
    fn redirect_limit_respects_max_redirs() {
        assert_eq!(compute_redirect_limit(true, false, 0), 0);
        assert_eq!(compute_redirect_limit(true, false, 7), 7);
    }

    #[test]
    fn redirect_limit_negative_is_unlimited() {
        assert_eq!(compute_redirect_limit(true, false, -1), usize::MAX);
        assert_eq!(compute_redirect_limit(false, true, -1), usize::MAX);
    }
}
