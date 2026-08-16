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
            uri::{DataUriLayer, FileUriLayer},
        },
    },
    js::pac::{FetchPacScript, SystemPacProxy},
    json::path::JsonPath,
    layer::{HijackLayer, MapErrLayer, MapResultLayer, TimeoutLayer, layer_fn},
    net::{
        client::{SystemProxyConfig, SystemProxyLayer},
        user::{Basic, ProxyCredential},
    },
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
    let proxy_layer = match cfg.proxy.clone() {
        None => HttpProxyAddressLayer::try_from_env_default()?,
        Some(mut proxy_address) => {
            if let Some(credentials) = cfg.proxy_user.clone() {
                proxy_address.credential = Some(ProxyCredential::Basic(credentials));
            }
            HttpProxyAddressLayer::maybe(Some(proxy_address))
        }
    };
    let mut system_proxy_layer =
        resolve_system_proxy_layer(&proxy_layer, SystemProxyLayer::try_from_system)?;
    if system_proxy_layer.config().pac_uri().is_some() {
        crate::cmd::pac::warm_up_javascript_engine()?;
        let pac_fetch_client = (
            FileUriLayer::new(),
            DataUriLayer::new(),
            FollowRedirectLayer::with_policy(Limited::new(10)),
        )
            .into_layer(EasyHttpWebClient::default());
        system_proxy_layer = system_proxy_layer
            .with_pac_service(SystemPacProxy::new(FetchPacScript::new(pac_fetch_client)));
    }
    new_with_proxy_layers(cfg, feed_tui, proxy_layer, system_proxy_layer).await
}

fn resolve_system_proxy_layer(
    higher_priority: &HttpProxyAddressLayer,
    read_system: impl FnOnce() -> Result<SystemProxyLayer, BoxError>,
) -> Result<SystemProxyLayer, BoxError> {
    if higher_priority.proxy_address().is_some() {
        Ok(SystemProxyLayer::new(SystemProxyConfig::default()))
    } else {
        read_system()
    }
}

/// Same as [`new`], with proxy layers handed in so tests do not inspect the
/// process environment or host operating-system settings.
async fn new_with_proxy_layers(
    cfg: &SendCommand,
    feed_tui: bool,
    proxy_layer: HttpProxyAddressLayer,
    system_proxy_layer: SystemProxyLayer,
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
        // outside FollowRedirect: a remote redirect can never reach
        // the local filesystem
        FileUriLayer::new(),
        DataUriLayer::new(),
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
        // Explicit `--proxy`, or `HTTP_PROXY` when the flag is absent, wins first.
        proxy_layer,
        // The system layer is inner and preserves an existing route, giving the
        // client the priority: CLI argument, environment, operating system.
        // It remains per-hop so PAC can evaluate every redirect target.
        system_proxy_layer,
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
        http::{
            StatusCode,
            header::{AUTHORIZATION, LOCATION, PROXY_AUTHORIZATION},
            server::HttpServer,
        },
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

    /// Keeps the response writer off the process stdout: `tokio::io::stdout()` writes straight to
    /// the descriptor, which libtest's `print!`-level capture does not intercept. The directory is
    /// returned so it outlives the request and cleans itself up (best effort, so a still-open handle
    /// on Windows cannot fail the test).
    fn output_dir() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("create temp dir for response output");
        let path = dir.path().join("response.out").display().to_string();
        (dir, path)
    }

    /// Drives the real `rama send` client stack through a cross-origin redirect and checks both
    /// halves of the ordering it depends on: `--user` is dropped on the cross-origin hop (its layer
    /// sits outside `FollowRedirect`, so `FilterCredentials` can strip the header), while `--resolve`
    /// is re-evaluated for the redirect target (its layer sits inside, so the second hop resolves at
    /// all). Getting either side of `FollowRedirectLayer` wrong fails this test.
    #[tokio::test]
    async fn send_client_stack_orders_layers_around_follow_redirect() {
        let saw_authorization = Arc::new(AtomicBool::new(false));
        let target_hits = Arc::new(AtomicUsize::new(0));
        let target = spawn_origin(service_fn({
            let saw_authorization = saw_authorization.clone();
            let target_hits = target_hits.clone();
            move |req: Request| {
                target_hits.fetch_add(1, Ordering::AcqRel);
                saw_authorization
                    .store(req.headers().contains_key(AUTHORIZATION), Ordering::Release);
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
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&[
            "--location",
            "--user",
            "someone:secret",
            "--resolve",
            &format!("*:{}:127.0.0.1", target.port),
            "--max-time",
            "10",
            "--output",
            &out_path,
            &uri,
        ]);

        // The proxy layer is handed in rather than read from `HTTP_PROXY`, so an ambient proxy in the
        // environment cannot decide the outcome of this test.
        let svc = new_with_proxy_layers(
            &cfg,
            false,
            HttpProxyAddressLayer::maybe(None),
            SystemProxyLayer::new(SystemProxyConfig::default()),
        )
        .await
        .unwrap();
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
    }

    /// The counterpart to the check above: proxy credentials are per-hop and authenticate to the
    /// (same) proxy, so `SetProxyAuthHttpHeaderLayer` sits _inside_ `FollowRedirect` and re-applies
    /// them on every hop — where origin credentials must not survive. Moving that layer outside
    /// leaves `Proxy-Authorization` to `FilterCredentials`' blocklist, which strips it cross-origin.
    #[tokio::test]
    async fn send_client_stack_reapplies_proxy_credentials_on_every_hop() {
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let proxy = spawn_origin(service_fn({
            let seen = seen.clone();
            move |req: Request| {
                let uri = req.uri().to_string();
                seen.lock().push((
                    uri.clone(),
                    req.headers().contains_key(PROXY_AUTHORIZATION),
                    req.headers().contains_key(AUTHORIZATION),
                ));
                async move {
                    let mut res = Response::builder();
                    // Plain-HTTP proxying, so both hops arrive here in absolute form.
                    res = if uri == "http://origin.example/start" {
                        res.status(StatusCode::FOUND)
                            .header(LOCATION, "http://other.example/final")
                    } else {
                        res.status(StatusCode::OK)
                    };
                    Ok::<_, Infallible>(res.body(Body::from("done")).unwrap())
                }
            }
        }))
        .await;

        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&[
            "--location",
            "--proxy",
            &format!("http://{proxy}"),
            "--proxy-user",
            "pu:pp",
            "--user",
            "someone:secret",
            "--max-time",
            "10",
            "--output",
            &out_path,
            "http://origin.example/start",
        ]);

        // `--proxy` is set, so this stack never consults `HTTP_PROXY`.
        let svc = new(&cfg, false).await.unwrap();
        let res = svc
            .serve(
                Request::builder()
                    .uri("http://origin.example/start")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            seen.lock().as_slice(),
            [
                ("http://origin.example/start".to_owned(), true, true),
                ("http://other.example/final".to_owned(), true, false),
            ],
            "expected proxy credentials on both hops and origin credentials on the first only",
        );
    }

    #[tokio::test]
    async fn send_client_uses_fixed_system_proxy() {
        let hits = Arc::new(AtomicUsize::new(0));
        let proxy = spawn_origin(service_fn({
            let hits = hits.clone();
            move |req: Request| {
                hits.fetch_add(1, Ordering::AcqRel);
                assert_eq!(req.uri().to_string(), "http://origin.example/system");
                async { Ok::<_, Infallible>(Response::new(Body::from("system"))) }
            }
        }))
        .await;
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&["--output", &out_path, "http://origin.example/system"]);
        let system = SystemProxyConfig::default()
            .with_http_proxy(format!("http://{proxy}").parse().unwrap());

        let svc = new_with_proxy_layers(
            &cfg,
            false,
            HttpProxyAddressLayer::maybe(None),
            SystemProxyLayer::new(system),
        )
        .await
        .unwrap();
        let res = svc
            .serve(
                Request::builder()
                    .uri("http://origin.example/system")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::Acquire), 1);
    }

    #[test]
    fn higher_priority_proxy_skips_system_discovery() {
        let calls = AtomicUsize::new(0);
        let higher_priority =
            HttpProxyAddressLayer::new("http://explicit.proxy:8080".parse().unwrap());

        let system = resolve_system_proxy_layer(&higher_priority, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(BoxError::from_static_str(
                "system discovery must be skipped",
            ))
        })
        .unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(system.config().is_empty());

        let no_higher_priority = HttpProxyAddressLayer::maybe(None);
        let system = resolve_system_proxy_layer(&no_higher_priority, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(SystemProxyLayer::new(
                SystemProxyConfig::default()
                    .with_http_proxy("http://system.proxy:8080".parse().unwrap()),
            ))
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(!system.config().is_empty());
    }

    #[tokio::test]
    async fn higher_priority_proxy_skips_system_pac() {
        let primary_hits = Arc::new(AtomicUsize::new(0));
        let primary = spawn_origin(service_fn({
            let primary_hits = primary_hits.clone();
            move |_req: Request| {
                primary_hits.fetch_add(1, Ordering::AcqRel);
                async { Ok::<_, Infallible>(Response::new(Body::from("primary"))) }
            }
        }))
        .await;
        let pac_calls = Arc::new(AtomicUsize::new(0));
        let pac_factory = service_fn({
            let pac_calls = pac_calls.clone();
            move |_uri: rama::net::uri::Uri| {
                pac_calls.fetch_add(1, Ordering::AcqRel);
                async move {
                    Ok::<_, OpaqueError>(rama::net::client::box_system_proxy_pac_resolver(
                        service_fn(|_request| async move {
                            Ok::<_, Infallible>(Some(rama::net::client::ProxyRoutes::from(
                                rama::net::client::ProxyRoute::Direct,
                            )))
                        }),
                    ))
                }
            }
        });
        let system = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&["--output", &out_path, "http://origin.example/priority"]);

        let svc = new_with_proxy_layers(
            &cfg,
            false,
            HttpProxyAddressLayer::new(format!("http://{primary}").parse().unwrap()),
            SystemProxyLayer::new(system).with_pac_service(pac_factory),
        )
        .await
        .unwrap();
        let res = svc
            .serve(
                Request::builder()
                    .uri("http://origin.example/priority")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(primary_hits.load(Ordering::Acquire), 1);
        assert_eq!(pac_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn send_client_routes_with_system_pac() {
        let hits = Arc::new(AtomicUsize::new(0));
        let proxy = spawn_origin(service_fn({
            let hits = hits.clone();
            move |req: Request| {
                hits.fetch_add(1, Ordering::AcqRel);
                assert_eq!(req.uri().to_string(), "http://origin.example/from-pac");
                async { Ok::<_, Infallible>(Response::new(Body::from("pac"))) }
            }
        }))
        .await;
        let script = format!("function FindProxyForURL(url, host) {{ return 'PROXY {proxy}'; }}");
        let pac = SystemPacProxy::new(rama::js::pac::StaticPacScript::new(script));
        let system = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&["--output", &out_path, "http://origin.example/from-pac"]);

        let svc = new_with_proxy_layers(
            &cfg,
            false,
            HttpProxyAddressLayer::maybe(None),
            SystemProxyLayer::new(system).with_pac_service(pac),
        )
        .await
        .unwrap();
        let res = svc
            .serve(
                Request::builder()
                    .uri("http://origin.example/from-pac")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::Acquire), 1);
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
