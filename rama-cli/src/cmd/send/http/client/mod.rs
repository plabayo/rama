use rama::{
    Layer, Service,
    error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt, extra::OpaqueError},
    error_sink::TracingErrorSink,
    extensions::Extension,
    http::{
        Body, Request, Response, StreamingBody,
        client::{EasyHttpWebClient, ProxyConnectorLayer, proxy::layer::HttpProxyConnectorLayer},
        layer::{
            auth::AddAuthorizationLayer,
            follow_redirect::{
                FollowRedirectLayer,
                policy::{FilterCredentials, Limited, PolicyExt},
            },
            har::{layer::HARExportLayer, recorder::FileRecorder},
            required_header::AddRequiredRequestHeadersLayer,
            uri::{DataUriLayer, FileUriLayer},
        },
    },
    json::path::JsonPath,
    layer::{HijackLayer, MapErrLayer, MapResultLayer, TimeoutLayer, layer_fn},
    net::{
        client::{
            NoProxyEnvLayer, ProxyAddressLayer, ProxyEnvLayer, ProxyRoutesLayer, SystemProxyLayer,
            SystemProxyPacService,
        },
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

#[cfg(test)]
use rama::js::pac::SystemPacProxy;

use crate::cmd::send::layer::resolve::OptDnsOverwriteLayer;

use super::{SendCommand, arg::HttpHeader};
use crate::cmd::send::EmulationProfiles;

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
    har_recorder: Option<FileRecorder>,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError>, BoxError> {
    let explicit_proxy = cfg.proxy.clone().map(|mut proxy_address| {
        if let Some(credentials) = cfg.proxy_user.clone() {
            proxy_address.credential = Some(ProxyCredential::Basic(credentials));
        }
        proxy_address
    });
    let explicit_proxy_layer = ProxyAddressLayer::maybe(explicit_proxy);
    // Shell-provided no-proxy lists are commonly shared across tools. Preserve
    // usable entries and make unsupported ones observable without making an
    // otherwise valid `rama send` invocation fail during route selection.
    let no_proxy_environment_layer =
        NoProxyEnvLayer::new().with_load_error_sink(TracingErrorSink::debug());
    let proxy_environment_layer = ProxyEnvLayer::new();

    let system_proxy_layer = crate::cmd::pac::system_proxy_layer();

    new_with_proxy_layers(
        cfg,
        feed_tui,
        no_proxy_environment_layer,
        explicit_proxy_layer,
        proxy_environment_layer,
        system_proxy_layer,
        har_recorder,
    )
    .await
}

/// Same as [`new`], with initial proxy layers handed in so construction does
/// not inspect the process environment or host operating-system settings.
async fn new_with_proxy_layers<P>(
    cfg: &SendCommand,
    feed_tui: bool,
    no_proxy_environment_layer: NoProxyEnvLayer,
    explicit_proxy_layer: ProxyAddressLayer,
    proxy_environment_layer: ProxyEnvLayer,
    system_proxy_layer: SystemProxyLayer<P>,
    har_recorder: Option<FileRecorder>,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError>, BoxError>
where
    P: SystemProxyPacService + Clone,
{
    let writer = writer::try_new(cfg).await?;
    let json_selectors: Arc<[JsonPath]> = cfg.select_json.clone().into();

    let inner_client = new_inner_client(cfg)?;
    let emulation_layer = if let Some(profiles) = &cfg.emulate {
        let database = load_emulation_database(profiles).await?;
        Some((
            UserAgentEmulateLayer::new(Arc::new(database))
                .with_try_auto_detect_user_agent(true)
                .with_select_fallback(UserAgentSelectFallback::Random),
            EmulateTlsProfileLayer::new(),
        ))
    } else {
        None
    };
    let har_layer = har_recorder.clone().map(|recorder| {
        let layer = HARExportLayer::new(recorder, true);
        if cfg.har_preserve_sensitive {
            layer.with_preserve_sensitive()
        } else {
            layer
        }
    });

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
        emulation_layer,
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
        // Inner to FollowRedirect: each actual network hop gets its own HAR entry.
        har_layer,
        // Inner to FollowRedirect: `--resolve` matches on host:port, so it has to be evaluated
        // against each hop's real target instead of the original one.
        OptDnsOverwriteLayer::new(cfg.resolve.clone()),
        // Every lower-priority proxy layer preserves an existing route, so
        // tuple order defines the priority: NO_PROXY, CLI argument,
        // environment, operating system.
        no_proxy_environment_layer,
        explicit_proxy_layer,
        proxy_environment_layer,
        // The system layer remains per-hop so PAC can evaluate every redirect target.
        system_proxy_layer,
        // Normalize the selected route only after every route source has run.
        ProxyRoutesLayer::new(),
        AddRequiredRequestHeadersLayer::default(),
        HijackLayer::new(
            cfg.curl,
            curl_writer::CurlWriter {
                writer,
                proxy_tunnel: cfg.proxy_tunnel,
                forward_proxy_auth: !cfg.no_proxy_forward_auth,
            },
        ),
        MapErrLayer::into_box_error(),
        layer_fn(move |svc| logger_headers_res::ResponseHeaderLogger {
            inner: svc,
            show_headers,
        }),
    );

    Ok(client_builder.into_layer(inner_client).boxed())
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
    let mut tls_config = if cfg.emulate.is_some() {
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
        .with_forward_proxy_auth(!cfg.no_proxy_forward_auth)
        .with_tunnel_plaintext_http(cfg.proxy_tunnel)
        .with_jit_layer((
            UserAgentEmulateHttpRequestModifierLayer::default(),
            logger_headers_req::RequestHeaderLoggerLayer::default(),
        ));

    Ok(client)
}

async fn load_emulation_database(
    profiles: &EmulationProfiles,
) -> Result<UserAgentDatabase, BoxError> {
    let database = match profiles {
        EmulationProfiles::Embedded => UserAgentDatabase::try_embedded()?,
        EmulationProfiles::File(path) => {
            let data = tokio::fs::read(path)
                .await
                .context("read custom user-agent profile database")?;
            UserAgentDatabase::try_from_json_slice(&data)?
        }
    };
    if database.is_empty() {
        return Err(BoxError::from_static_str(
            "user-agent profile database is empty",
        ));
    }
    Ok(database.with_disable_unknown_user_agent_data(true))
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
            header::{AUTHORIZATION, COOKIE, LOCATION, PROXY_AUTHORIZATION, SET_COOKIE},
            layer::har::spec::LogFile,
            server::HttpServer,
        },
        net::{
            address::{ProxyAddress, SocketAddress},
            client::{ProxyRoute, SystemProxyConfig, SystemProxyPacDisabledResolver},
        },
        service::service_fn,
        tcp::server::TcpListener,
        ua::profile::UserAgentProfileInput,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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

    async fn read_http_head(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "HTTP request ended before its headers");
            request.extend_from_slice(&buffer[..read]);
        }
        String::from_utf8(request).unwrap()
    }

    const CUSTOM_PROFILE_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/987.0.0.0 Safari/537.36";
    const CUSTOM_PROFILE_FIRST: &str = "rama-file-profile-first-6f87c9e2";
    const CUSTOM_PROFILE_LAST: &str = "rama-file-profile-last-b31d04aa";

    fn minimal_custom_emulation_profile_json() -> Vec<u8> {
        let mut profiles: Vec<UserAgentProfileInput> = serde_json::from_slice(include_bytes!(
            "../../../../../../rama-ua/src/profile/embed_profiles.json"
        ))
        .unwrap();
        let mut profile = profiles.remove(0);
        profile.uastr = CUSTOM_PROFILE_USER_AGENT.to_owned();
        let headers: rama::http::HeaderMap = serde_json::from_value(serde_json::json!([
            ["x-rama-profile-first", CUSTOM_PROFILE_FIRST],
            ["user-agent", CUSTOM_PROFILE_USER_AGENT],
            ["x-rama-profile-last", CUSTOM_PROFILE_LAST]
        ]))
        .unwrap();
        profile.h1_headers_navigate = Some(headers.clone());
        profile.h1_headers_fetch = None;
        profile.h1_headers_xhr = None;
        profile.h1_headers_form = None;
        profile.h1_headers_ws = None;
        profile.h2_headers_navigate = Some(headers);
        profile.h2_headers_fetch = None;
        profile.h2_headers_xhr = None;
        profile.h2_headers_form = None;
        profile.h2_headers_ws = None;
        profile.tls_ws_client_config_overwrites = None;
        profile.js_web_apis = None;
        profile.source_info = None;
        assert!(profile.h1_settings.is_some());
        assert!(profile.h2_settings.is_some());
        assert!(profile.tls_client_hello.is_some());
        serde_json::to_vec(&[profile]).unwrap()
    }

    #[test]
    fn emulate_accepts_a_bare_flag_or_an_equals_separated_json_path() {
        let embedded = send_cfg(&["--emulate", "http://example.test"]);
        assert!(matches!(
            embedded.emulate,
            Some(EmulationProfiles::Embedded)
        ));

        let custom = send_cfg(&[
            "--emulate=/tmp/captured-profiles.json",
            "http://example.test",
        ]);
        assert!(matches!(
            custom.emulate,
            Some(EmulationProfiles::File(path))
                if path == std::path::Path::new("/tmp/captured-profiles.json")
        ));
    }

    #[test]
    fn forward_proxy_options_are_opt_in() {
        let defaults = send_cfg(&["http://example.test"]);
        assert!(!defaults.no_proxy_forward_auth);
        assert!(!defaults.proxy_tunnel);

        let configured = send_cfg(&[
            "--no-proxy-forward-auth",
            "--proxytunnel",
            "http://example.test",
        ]);
        assert!(configured.no_proxy_forward_auth);
        assert!(configured.proxy_tunnel);
    }

    #[tokio::test]
    async fn custom_emulation_database_loads_from_a_temporary_json_file() {
        let directory = rama::utils::fs::tempdir().unwrap();
        let path = directory.path().join("profiles.json");
        tokio::fs::write(&path, minimal_custom_emulation_profile_json())
            .await
            .unwrap();

        let database = load_emulation_database(&EmulationProfiles::File(path))
            .await
            .unwrap();
        assert_eq!(database.len(), 1);
        assert!(
            database
                .get_exact_header_str(CUSTOM_PROFILE_USER_AGENT)
                .is_some()
        );

        let observed_custom_profile = Arc::new(AtomicBool::new(false));
        let inner = UserAgentEmulateHttpRequestModifierLayer::default().into_layer(
            rama::service::service_fn({
                let observed_custom_profile = observed_custom_profile.clone();
                move |request: Request| {
                    let observed_custom_profile = observed_custom_profile.clone();
                    async move {
                        let headers = request
                            .headers()
                            .clone()
                            .into_ordered_iter()
                            .map(|(name, value)| {
                                (
                                    name.to_string(),
                                    value
                                        .to_str()
                                        .expect("test profile header value")
                                        .to_owned(),
                                )
                            })
                            .collect::<Vec<_>>();
                        let position = |value: &str| {
                            headers
                                .iter()
                                .position(|(_, candidate)| candidate == value)
                                .expect("custom profile header")
                        };
                        let first = position(CUSTOM_PROFILE_FIRST);
                        let user_agent = position(CUSTOM_PROFILE_USER_AGENT);
                        let last = position(CUSTOM_PROFILE_LAST);
                        assert!(first < user_agent && user_agent < last, "{headers:?}");
                        observed_custom_profile.store(true, Ordering::Relaxed);
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    }
                }
            }),
        );
        let service = UserAgentEmulateLayer::new(Arc::new(database))
            .with_try_auto_detect_user_agent(true)
            .with_select_fallback(UserAgentSelectFallback::Random)
            .into_layer(inner);
        assert!(
            service
                .serve(
                    Request::builder()
                        .uri("http://example.test")
                        .header("user-agent", "not-a-real-emulatable-agent")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .is_err(),
            "an explicit unknown User-Agent must not fall back to an unrelated profile"
        );
        assert!(
            service
                .serve(
                    Request::builder()
                        .uri("http://example.test")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .is_ok(),
            "a request without User-Agent should select a random custom profile"
        );
        assert!(observed_custom_profile.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn custom_emulation_database_rejects_missing_invalid_empty_and_incomplete_files() {
        let directory = rama::utils::fs::tempdir().unwrap();

        let missing = directory.path().join("missing.json");
        let error = load_emulation_database(&EmulationProfiles::File(missing))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("read custom user-agent profile database"),
            "{error}"
        );

        let invalid = directory.path().join("invalid.json");
        tokio::fs::write(&invalid, b"not json").await.unwrap();
        let error = load_emulation_database(&EmulationProfiles::File(invalid))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("deserialize user-agent profiles"),
            "{error}"
        );

        let empty = directory.path().join("empty.json");
        tokio::fs::write(&empty, b"[]").await.unwrap();
        let error = load_emulation_database(&EmulationProfiles::File(empty))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("database is empty"), "{error}");

        let incomplete = directory.path().join("incomplete.json");
        let mut profile: serde_json::Value =
            serde_json::from_slice(&minimal_custom_emulation_profile_json()).unwrap();
        profile[0]["h2_settings"] = serde_json::Value::Null;
        tokio::fs::write(&incomplete, serde_json::to_vec(&profile).unwrap())
            .await
            .unwrap();
        let error = load_emulation_database(&EmulationProfiles::File(incomplete))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("h2_settings"), "{error}");
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
    fn output_dir() -> (rama::utils::fs::TempDir, String) {
        let dir = rama::utils::fs::tempdir().expect("create temp dir for response output");
        let path = dir.path().join("response.out").display().to_string();
        (dir, path)
    }

    fn no_proxy_none() -> NoProxyEnvLayer {
        NoProxyEnvLayer::new_with_reader(|_| Ok(None))
    }

    fn lazy_proxy(address: Option<ProxyAddress>) -> ProxyEnvLayer {
        let address = address.map(|address| address.to_string());
        ProxyEnvLayer::new_with_reader(move |name| {
            Ok((name == "http_proxy").then(|| address.clone()).flatten())
        })
    }

    async fn new_hermetic(
        cfg: &SendCommand,
    ) -> Result<impl Service<Request, Output = Response, Error = OpaqueError>, BoxError> {
        let explicit_proxy = cfg.proxy.clone().map(|mut proxy| {
            if let Some(credentials) = cfg.proxy_user.clone() {
                proxy.credential = Some(ProxyCredential::Basic(credentials));
            }
            proxy
        });
        new_with_proxy_layers(
            cfg,
            false,
            no_proxy_none(),
            ProxyAddressLayer::maybe(explicit_proxy),
            lazy_proxy(None),
            SystemProxyLayer::from_cached(SystemProxyConfig::default()),
            None,
        )
        .await
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
            no_proxy_none(),
            ProxyAddressLayer::maybe(None),
            lazy_proxy(None),
            SystemProxyLayer::from_cached(SystemProxyConfig::default()),
            None,
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

    /// The counterpart to the check above: proxy credentials are per-hop and
    /// authenticate to the selected proxy, so Easy-client JIT middleware
    /// reapplies them after each redirect establishes or reuses a connection.
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
        let svc = new_hermetic(&cfg).await.unwrap();
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
    async fn send_client_can_disable_automatic_forward_proxy_auth() {
        let proxy = spawn_origin(service_fn(|req: Request| async move {
            assert_eq!(req.uri().to_string(), "http://origin.example/no-auth");
            assert!(!req.headers().contains_key(PROXY_AUTHORIZATION));
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        }))
        .await;
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&[
            "--proxy",
            &format!("http://{proxy}"),
            "--proxy-user",
            "pu:pp",
            "--no-proxy-forward-auth",
            "--output",
            &out_path,
            "http://origin.example/no-auth",
        ]);

        let response = new_hermetic(&cfg)
            .await
            .unwrap()
            .serve(
                Request::builder()
                    .uri("http://origin.example/no-auth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn send_client_exposes_forward_proxy_407() {
        let proxy = spawn_origin(service_fn(|_: Request| async move {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header("proxy-authenticate", "Basic realm=upstream-only")
                    .header("proxy-authentication-info", "nextnonce=upstream-secret")
                    .body(Body::from("upstream-only-body"))
                    .unwrap(),
            )
        }))
        .await;
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&[
            "--proxy",
            &format!("http://{proxy}"),
            "--output",
            &out_path,
            "http://origin.example/challenge",
        ]);

        let response = new_hermetic(&cfg)
            .await
            .unwrap()
            .serve(
                Request::builder()
                    .uri("http://origin.example/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(
            response.headers()["proxy-authenticate"],
            "Basic realm=upstream-only"
        );
        assert_eq!(
            tokio::fs::read_to_string(&out_path).await.unwrap(),
            "upstream-only-body"
        );
    }

    #[tokio::test]
    async fn send_client_proxytunnel_authenticates_connect_without_leaking_to_origin() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let connect = read_http_head(&mut stream).await;
            assert!(
                connect.starts_with("CONNECT origin.example:80 HTTP/1.1\r\n"),
                "unexpected CONNECT request: {connect:?}"
            );
            assert!(
                connect
                    .to_ascii_lowercase()
                    .contains("proxy-authorization: basic chu6cha="),
                "CONNECT did not contain configured proxy credentials: {connect:?}"
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();

            let origin = read_http_head(&mut stream).await;
            assert!(
                origin.starts_with("GET /inside HTTP/1.1\r\n"),
                "tunneled request was not origin-form: {origin:?}"
            );
            assert!(
                !origin.to_ascii_lowercase().contains("proxy-authorization:"),
                "proxy credential crossed into the tunnel: {origin:?}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&[
            "--proxy",
            &format!("http://{proxy}"),
            "--proxy-user",
            "pu:pp",
            "--proxytunnel",
            "--output",
            &out_path,
            "http://origin.example/inside",
        ]);

        let response = new_hermetic(&cfg)
            .await
            .unwrap()
            .serve(
                Request::builder()
                    .uri("http://origin.example/inside")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        tokio::time::timeout(Duration::from_secs(5), proxy_task)
            .await
            .expect("proxy task timed out")
            .expect("proxy task failed");
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
            no_proxy_none(),
            ProxyAddressLayer::maybe(None),
            lazy_proxy(None),
            SystemProxyLayer::from_cached(system),
            None,
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

    #[tokio::test]
    async fn curl_export_includes_a_single_system_proxy_route() {
        let (output, output_path) = output_dir();
        let cfg = send_cfg(&[
            "--curl",
            "--output",
            &output_path,
            "http://origin.example/export",
        ]);
        let system = SystemProxyConfig::default()
            .with_http_proxy("http://system.proxy:8080".parse().unwrap());
        let service = new_with_proxy_layers(
            &cfg,
            false,
            no_proxy_none(),
            ProxyAddressLayer::maybe(None),
            lazy_proxy(None),
            SystemProxyLayer::from_cached(system),
            None,
        )
        .await
        .unwrap();

        service
            .serve(
                Request::builder()
                    .uri("http://origin.example/export")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let command = tokio::fs::read_to_string(output.path().join("response.out"))
            .await
            .unwrap();
        assert!(
            command.contains("-x 'http://system.proxy:8080'"),
            "{command}"
        );
    }

    #[tokio::test]
    async fn curl_export_matches_forward_auth_and_tunnel_options() {
        async fn export(args: &[&str]) -> String {
            let (output, output_path) = output_dir();
            let mut complete_args = vec!["--curl", "--output", output_path.as_str()];
            complete_args.extend_from_slice(args);
            let cfg = send_cfg(&complete_args);
            let uri = args.last().expect("target URI");
            let mut request = Request::builder().uri(*uri).body(Body::empty()).unwrap();
            for header in &cfg.header {
                request
                    .headers_mut()
                    .insert(header.name.clone(), header.value.clone());
            }
            new_hermetic(&cfg)
                .await
                .unwrap()
                .serve(request)
                .await
                .unwrap();
            tokio::fs::read_to_string(output.path().join("response.out"))
                .await
                .unwrap()
        }

        let command = export(&[
            "--proxy",
            "http://proxy.example:8080",
            "--proxy-user",
            "pu:pp",
            "--no-proxy-forward-auth",
            "http://origin.example/export",
        ])
        .await;
        assert!(command.contains("http://proxy.example:8080"), "{command}");
        assert!(!command.contains("pu:pp"), "{command}");
        assert!(!command.contains("--proxytunnel"), "{command}");

        let command = export(&[
            "--proxy",
            "http://proxy.example:8080",
            "--proxy-user",
            "pu:pp",
            "--no-proxy-forward-auth",
            "--proxytunnel",
            "http://origin.example/export",
        ])
        .await;
        assert!(command.contains("--proxytunnel"), "{command}");
        assert!(command.contains("pu:pp"), "{command}");

        let command = export(&[
            "--proxy",
            "http://proxy.example:8080",
            "--proxy-user",
            "pu:pp",
            "--no-proxy-forward-auth",
            "https://origin.example/export",
        ])
        .await;
        assert!(command.contains("pu:pp"), "{command}");

        let command = export(&[
            "--proxy",
            "socks5://proxy.example:1080",
            "--proxy-user",
            "pu:pp",
            "--no-proxy-forward-auth",
            "http://origin.example/export",
        ])
        .await;
        assert!(command.contains("pu:pp"), "{command}");

        let command = export(&[
            "-H",
            "Proxy-Authorization: Basic origin-secret",
            "http://origin.example/export",
        ])
        .await;
        assert!(!command.contains("origin-secret"), "{command}");

        let command = export(&[
            "--proxy",
            "http://proxy.example:8080",
            "--proxytunnel",
            "-H",
            "Proxy-Authorization: Basic origin-secret",
            "http://origin.example/export",
        ])
        .await;
        assert!(command.contains("--proxytunnel"), "{command}");
        assert!(!command.contains("origin-secret"), "{command}");

        let command = export(&[
            "--proxy",
            "http://proxy.example:8080",
            "--proxy-user",
            "pu:pp",
            "-H",
            "Proxy-Authorization: Basic stale-secret",
            "http://origin.example/export",
        ])
        .await;
        assert!(command.contains("pu:pp"), "{command}");
        assert!(!command.contains("stale-secret"), "{command}");

        let command = export(&[
            "--proxy",
            "http://proxy.example:8080",
            "-H",
            "Proxy-Authorization: Basic manual-secret",
            "http://origin.example/export",
        ])
        .await;
        assert!(command.contains("manual-secret"), "{command}");
    }

    #[tokio::test]
    async fn curl_export_uses_the_first_ordered_pac_route() {
        let (output, output_path) = output_dir();
        let cfg = send_cfg(&[
            "--curl",
            "--output",
            &output_path,
            "http://origin.example/export",
        ]);
        let factory = service_fn(|_uri: rama::net::uri::Uri| async {
            Ok::<_, Infallible>(service_fn(
                |_request: rama::net::client::SystemProxyPacRequest| async {
                    Ok::<_, Infallible>(Some(rama::net::client::ProxyRoutes::new([
                        ProxyRoute::Proxy("http://primary.proxy:8080".parse().unwrap()),
                        ProxyRoute::Direct,
                    ])))
                },
            ))
        });
        let system = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let service = new_with_proxy_layers(
            &cfg,
            false,
            no_proxy_none(),
            ProxyAddressLayer::maybe(None),
            lazy_proxy(None),
            SystemProxyLayer::from_cached(system).with_pac_service(factory),
            None,
        )
        .await
        .unwrap();

        service
            .serve(
                Request::builder()
                    .uri("http://origin.example/export")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let command = tokio::fs::read_to_string(output.path().join("response.out"))
            .await
            .unwrap();
        assert!(
            command.contains("-x 'http://primary.proxy:8080'"),
            "{command}"
        );
    }

    #[tokio::test]
    async fn send_client_uses_connect_for_an_https_system_proxy_route() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "CONNECT request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("CONNECT origin.example:443 HTTP/1.1\r\n"),
                "unexpected proxy request: {request:?}",
            );
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&[
            "--max-time",
            "5",
            "--output",
            &out_path,
            "https://origin.example/system",
        ]);
        let system = SystemProxyConfig::default()
            .with_https_proxy(format!("http://{proxy}").parse().unwrap());

        let svc = new_with_proxy_layers(
            &cfg,
            false,
            no_proxy_none(),
            ProxyAddressLayer::maybe(None),
            lazy_proxy(None),
            SystemProxyLayer::from_cached(system),
            None,
        )
        .await
        .unwrap();
        svc.serve(
            Request::builder()
                .uri("https://origin.example/system")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap_err();

        tokio::time::timeout(Duration::from_secs(5), proxy_task)
            .await
            .expect("system proxy should receive CONNECT")
            .expect("proxy task should finish");
    }

    #[tokio::test]
    async fn no_proxy_direct_route_is_preserved_by_every_proxy_layer() {
        let origin_hits = Arc::new(AtomicUsize::new(0));
        let origin = spawn_origin(service_fn({
            let origin_hits = origin_hits.clone();
            move |req: Request| {
                origin_hits.fetch_add(1, Ordering::AcqRel);
                async move {
                    let response = if req.uri().path().is_some_and(|path| path == "/direct") {
                        Response::builder()
                            .status(StatusCode::FOUND)
                            .header(LOCATION, "/final")
                            .body(Body::empty())
                            .unwrap()
                    } else {
                        Response::new(Body::from("direct"))
                    };
                    Ok::<_, Infallible>(response)
                }
            }
        }))
        .await;
        let proxy_hits = Arc::new(AtomicUsize::new(0));
        let proxy = spawn_origin(service_fn({
            let proxy_hits = proxy_hits.clone();
            move |_req: Request| {
                proxy_hits.fetch_add(1, Ordering::AcqRel);
                async { Ok::<_, Infallible>(Response::new(Body::from("proxied"))) }
            }
        }))
        .await;
        let pac_calls = Arc::new(AtomicUsize::new(0));
        let pac_factory = service_fn({
            let pac_calls = pac_calls.clone();
            move |_uri: rama::net::uri::Uri| {
                pac_calls.fetch_add(1, Ordering::AcqRel);
                async move {
                    Ok::<_, Infallible>(service_fn(move |_request| async move {
                        Ok::<_, Infallible>(Some(rama::net::client::ProxyRoutes::from(
                            ProxyRoute::Proxy(format!("http://{proxy}").parse().unwrap()),
                        )))
                    }))
                }
            }
        });
        let system = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let uri = format!("http://origin.example:{}/direct", origin.port);
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&[
            "--location",
            "--resolve",
            &format!("origin.example:{}:127.0.0.1", origin.port),
            "--output",
            &out_path,
            &uri,
        ]);
        let no_proxy_environment_layer = NoProxyEnvLayer::new_with_reader(|name| {
            Ok((name == "no_proxy").then(|| "origin.example".to_owned()))
        });
        let environment_calls = Arc::new(AtomicUsize::new(0));
        let environment_proxy_layer = ProxyEnvLayer::new_with_reader({
            let environment_calls = environment_calls.clone();
            move |_| {
                environment_calls.fetch_add(1, Ordering::AcqRel);
                Err(std::io::Error::other("invalid HTTP_PROXY").into())
            }
        });

        let svc = new_with_proxy_layers(
            &cfg,
            false,
            no_proxy_environment_layer,
            ProxyAddressLayer::new(format!("http://{proxy}").parse().unwrap()),
            environment_proxy_layer,
            SystemProxyLayer::from_cached(system).with_pac_service(pac_factory),
            None,
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
        assert_eq!(origin_hits.load(Ordering::Acquire), 2);
        assert_eq!(proxy_hits.load(Ordering::Acquire), 0);
        assert_eq!(pac_calls.load(Ordering::Acquire), 0);
        assert_eq!(environment_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn explicit_then_environment_proxies_win_over_system_pac() {
        let primary_hits = Arc::new(AtomicUsize::new(0));
        let primary = spawn_origin(service_fn({
            let primary_hits = primary_hits.clone();
            move |_req: Request| {
                primary_hits.fetch_add(1, Ordering::AcqRel);
                async { Ok::<_, Infallible>(Response::new(Body::from("primary"))) }
            }
        }))
        .await;
        let environment_hits = Arc::new(AtomicUsize::new(0));
        let environment = spawn_origin(service_fn({
            let environment_hits = environment_hits.clone();
            move |_req: Request| {
                environment_hits.fetch_add(1, Ordering::AcqRel);
                async { Ok::<_, Infallible>(Response::new(Body::from("environment"))) }
            }
        }))
        .await;
        let pac_calls = Arc::new(AtomicUsize::new(0));
        let pac_factory = service_fn({
            let pac_calls = pac_calls.clone();
            move |_uri: rama::net::uri::Uri| {
                pac_calls.fetch_add(1, Ordering::AcqRel);
                async move {
                    Ok::<_, Infallible>(service_fn(|_request| async move {
                        Ok::<_, Infallible>(Some(rama::net::client::ProxyRoutes::from(
                            rama::net::client::ProxyRoute::Direct,
                        )))
                    }))
                }
            }
        });
        let system = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&["--output", &out_path, "http://origin.example/priority"]);
        let environment_calls = Arc::new(AtomicUsize::new(0));
        let environment_proxy_layer = ProxyEnvLayer::new_with_reader({
            let environment_calls = environment_calls.clone();
            move |_| {
                environment_calls.fetch_add(1, Ordering::AcqRel);
                Err(std::io::Error::other("invalid HTTP_PROXY").into())
            }
        });

        let svc = new_with_proxy_layers(
            &cfg,
            false,
            no_proxy_none(),
            ProxyAddressLayer::new(format!("http://{primary}").parse().unwrap()),
            environment_proxy_layer,
            SystemProxyLayer::from_cached(system).with_pac_service(pac_factory),
            None,
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
        assert_eq!(environment_hits.load(Ordering::Acquire), 0);
        assert_eq!(pac_calls.load(Ordering::Acquire), 0);
        assert_eq!(environment_calls.load(Ordering::Acquire), 0);

        let pac_factory = service_fn({
            let pac_calls = pac_calls.clone();
            move |_uri: rama::net::uri::Uri| {
                pac_calls.fetch_add(1, Ordering::AcqRel);
                async move {
                    Ok::<_, Infallible>(service_fn(|_request| async move {
                        Ok::<_, Infallible>(Some(rama::net::client::ProxyRoutes::from(
                            rama::net::client::ProxyRoute::Direct,
                        )))
                    }))
                }
            }
        });
        let system = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let svc = new_with_proxy_layers(
            &cfg,
            false,
            no_proxy_none(),
            ProxyAddressLayer::maybe(None),
            lazy_proxy(Some(format!("http://{environment}").parse().unwrap())),
            SystemProxyLayer::from_cached(system).with_pac_service(pac_factory),
            None,
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
        assert_eq!(environment_hits.load(Ordering::Acquire), 1);
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
            no_proxy_none(),
            ProxyAddressLayer::maybe(None),
            lazy_proxy(None),
            SystemProxyLayer::from_cached(system).with_pac_service(pac),
            None,
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

    #[tokio::test]
    async fn system_pac_factory_failure_is_fail_closed_in_send_stack() {
        let factory = service_fn(|_uri: rama::net::uri::Uri| async {
            Err::<SystemProxyPacDisabledResolver, _>(std::io::Error::other("PAC unavailable"))
        });
        let system = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&["--output", &out_path, "http://origin.example/fail-closed"]);
        let svc = new_with_proxy_layers(
            &cfg,
            false,
            no_proxy_none(),
            ProxyAddressLayer::maybe(None),
            lazy_proxy(None),
            SystemProxyLayer::from_cached(system).with_pac_service(factory),
            None,
        )
        .await
        .unwrap();

        let error = svc
            .serve(
                Request::builder()
                    .uri("http://origin.example/fail-closed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("create system PAC resolver"));
    }

    #[tokio::test]
    async fn system_pac_is_re_evaluated_for_every_redirect_hop() {
        let proxy_hits = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let proxy = spawn_origin(service_fn({
            let proxy_hits = proxy_hits.clone();
            move |req: Request| {
                let uri = req.uri().to_string();
                proxy_hits.lock().push(uri.clone());
                async move {
                    let response = if uri == "http://origin.example/start" {
                        Response::builder()
                            .status(StatusCode::FOUND)
                            .header(LOCATION, "http://other.example/final")
                            .body(Body::empty())
                            .unwrap()
                    } else {
                        Response::new(Body::from("done"))
                    };
                    Ok::<_, Infallible>(response)
                }
            }
        }))
        .await;

        let pac_uris = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let proxy_address: rama::net::address::ProxyAddress =
            format!("http://{proxy}").parse().unwrap();
        let pac_factory = service_fn({
            let pac_uris = pac_uris.clone();
            move |_pac_uri: rama::net::uri::Uri| {
                let pac_uris = pac_uris.clone();
                let proxy_address = proxy_address.clone();
                async move {
                    Ok::<_, Infallible>(service_fn(
                        move |request: rama::net::client::SystemProxyPacRequest| {
                            pac_uris.lock().push(request.uri.to_string());
                            let routes =
                                rama::net::client::ProxyRoutes::from(proxy_address.clone());
                            async move { Ok::<_, Infallible>(Some(routes)) }
                        },
                    ))
                }
            }
        });
        let system = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let (_out_dir, out_path) = output_dir();
        let cfg = send_cfg(&[
            "--location",
            "--output",
            &out_path,
            "http://origin.example/start",
        ]);

        let svc = new_with_proxy_layers(
            &cfg,
            false,
            no_proxy_none(),
            ProxyAddressLayer::maybe(None),
            lazy_proxy(None),
            SystemProxyLayer::from_cached(system).with_pac_service(pac_factory),
            None,
        )
        .await
        .unwrap();
        let response = svc
            .serve(
                Request::builder()
                    .uri("http://origin.example/start")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            pac_uris.lock().as_slice(),
            ["http://origin.example/start", "http://other.example/final"]
        );
        assert_eq!(
            proxy_hits.lock().as_slice(),
            ["http://origin.example/start", "http://other.example/final"]
        );
    }

    #[tokio::test]
    async fn send_har_records_redirects_and_controls_sensitive_headers() {
        for preserve_sensitive in [false, true] {
            let proxy = spawn_origin(service_fn(|req: Request| async move {
                let mut response = if req.uri().path().is_some_and(|path| path == "/start") {
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header(LOCATION, "http://redirect.example/final")
                } else {
                    Response::builder().status(StatusCode::OK)
                };
                response = response.header(SET_COOKIE, "server-session=secret");
                Ok::<_, Infallible>(response.body(Body::from("done")).unwrap())
            }))
            .await;
            let dir = rama::utils::fs::tempdir().unwrap();
            let har_path = dir.path().join(if preserve_sensitive {
                "preserved.har"
            } else {
                "sanitized.har"
            });
            let output_path = dir.path().join("response.out");
            let mut args = vec![
                "--location".to_owned(),
                "--proxy".to_owned(),
                format!("http://{proxy}"),
                "--user".to_owned(),
                "alice:secret".to_owned(),
                "--header".to_owned(),
                "Cookie: client-session=secret".to_owned(),
                "--har".to_owned(),
                har_path.display().to_string(),
                "--output".to_owned(),
                output_path.display().to_string(),
            ];
            if preserve_sensitive {
                args.push("--har-preserve-sensitive".to_owned());
            }
            args.push("http://origin.example/start".to_owned());
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();
            let cfg = send_cfg(&args);

            crate::cmd::send::http::run_inner(&cfg, false)
                .await
                .unwrap();

            let bytes = tokio::fs::read(&har_path).await.unwrap();
            let log: LogFile = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(log.log.entries.len(), 2);
            let first = log
                .log
                .entries
                .iter()
                .find(|entry| entry.request.url.ends_with("/start"))
                .unwrap();
            let second = log
                .log
                .entries
                .iter()
                .find(|entry| entry.request.url.ends_with("/final"))
                .unwrap();
            let request_has = |entry: &rama::http::layer::har::spec::Entry, name| {
                entry
                    .request
                    .headers
                    .iter()
                    .any(|header| header.name.eq_ignore_ascii_case(name))
            };
            let response_has = |entry: &rama::http::layer::har::spec::Entry, name| {
                entry
                    .response
                    .headers
                    .iter()
                    .any(|header| header.name.eq_ignore_ascii_case(name))
            };

            assert_eq!(
                request_has(first, AUTHORIZATION.as_str()),
                preserve_sensitive
            );
            assert_eq!(request_has(first, COOKIE.as_str()), preserve_sensitive);
            assert!(!request_has(second, AUTHORIZATION.as_str()));
            assert!(!request_has(second, COOKIE.as_str()));
            assert_eq!(response_has(first, SET_COOKIE.as_str()), preserve_sensitive);
            assert_eq!(
                response_has(second, SET_COOKIE.as_str()),
                preserve_sensitive
            );
            assert_eq!(
                std::fs::read_dir(dir.path())
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "har"))
                    .count(),
                1,
                "the exact output path must not create generated HAR files",
            );
        }
    }

    #[tokio::test]
    async fn send_timeout_still_finalizes_the_har_file() {
        let proxy = spawn_origin(service_fn(|_req: Request| async move {
            std::future::pending::<Result<Response, Infallible>>().await
        }))
        .await;
        let dir = rama::utils::fs::tempdir().unwrap();
        let har_path = dir.path().join("timed-out.har");
        let output_path = dir.path().join("response.out");
        let cfg = send_cfg(&[
            "--proxy",
            &format!("http://{proxy}"),
            "--max-time",
            // The command-wide timeout includes client-stack startup. Leave
            // enough headroom for slower CI runners so the request reaches
            // the HAR layer before the permanently pending origin times out.
            "5",
            "--har",
            &har_path.display().to_string(),
            "--output",
            &output_path.display().to_string(),
            "http://origin.example/slow",
        ]);

        crate::cmd::send::http::run_inner(&cfg, false)
            .await
            .expect_err("request must time out");

        let bytes = tokio::fs::read(&har_path).await.unwrap();
        let log: LogFile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(log.log.entries.len(), 1);
        assert_eq!(log.log.entries[0].response.status, 0);
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
