//! The CONNECT-UDP acceptance matrix: every case is one value per dimension, run by one
//! harness on loopback with Rama on every side. Curated rows run in PR CI, each as its own
//! test; the full cross product runs nightly.

use super::*;

/// Who speaks HTTP/3 to the origin, and how the tunnel is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Perspective {
    /// A Rama HTTP/3 client tunnels through the proxy itself.
    Direct,
    /// A Rama QUIC/H3 MITM terminates the client and egresses through the proxy.
    MitmEgress,
    /// A Rama QUIC relay forwards the client untouched through the proxy.
    RelayEgress,
}

/// How the client names the proxy, and the template the proxy serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyConfig {
    MasqueDefault,
    MasquePath,
    MasqueQuery,
    HttpsWellKnown,
    HttpsQueryExpansion,
}

impl ProxyConfig {
    /// Scheme and the client template after the authority.
    fn client(self) -> (&'static str, &'static str) {
        match self {
            Self::MasqueDefault => ("masque", ""),
            Self::MasquePath => ("masque", "/proxy/{target_host}/{target_port}/"),
            Self::MasqueQuery => ("masque", "/masque?h={target_host}&p={target_port}"),
            Self::HttpsWellKnown => (
                "https",
                "/.well-known/masque/udp/{target_host}/{target_port}/",
            ),
            Self::HttpsQueryExpansion => ("https", "/masque{?target_host,target_port}"),
        }
    }

    fn server(self) -> Option<ProxyPathTemplate> {
        match self {
            Self::MasqueDefault | Self::HttpsWellKnown => None,
            Self::MasquePath | Self::MasqueQuery | Self::HttpsQueryExpansion => {
                Some(ProxyPathTemplate::try_new(self.client().1).unwrap())
            }
        }
    }
}

/// The credentials the client sends and the proxy expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Credentials {
    None,
    Basic,
    BasicWithLabels,
    WrongPassword,
}

impl Credentials {
    fn userinfo(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Basic => "john:secret@",
            Self::BasicWithLabels => "john-country-be:secret@",
            Self::WrongPassword => "john:wrong@",
        }
    }

    fn proxy(self) -> ProxyAuth {
        match self {
            Self::None => ProxyAuth::Anonymous,
            Self::Basic | Self::WrongPassword => ProxyAuth::Basic,
            Self::BasicWithLabels => ProxyAuth::BasicWithLabels,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Ipv4,
    Ipv6,
    /// `localhost`, resolved by the proxy.
    Name,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Workload {
    GetSmall,
    /// 2 MiB streamed to the origin and echoed back.
    PostLarge,
    /// Eight requests at once on one inner connection.
    Parallel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Once,
    /// Ten handshake → exchange → shutdown runs, every tunnel released in between.
    TenRuns,
}

#[derive(Debug, Clone, Copy)]
struct Case {
    perspective: Perspective,
    quic: QuicTls,
    config: ProxyConfig,
    credentials: Credentials,
    carrier: Carrier,
    target: Target,
    workload: Workload,
    lifecycle: Lifecycle,
}

const BASE: Case = Case {
    perspective: Perspective::Direct,
    quic: QuicTls::Boring,
    config: ProxyConfig::MasqueDefault,
    credentials: Credentials::None,
    carrier: Carrier::Http3Datagram,
    target: Target::Ipv4,
    workload: Workload::GetSmall,
    lifecycle: Lifecycle::Once,
};

async fn run(case: Case) {
    timeout(Duration::from_secs(120), run_case(case))
        .await
        .unwrap_or_else(|_elapsed| panic!("{case:?}: timed out"));
}

async fn run_case(case: Case) {
    let origin_address = match case.target {
        Target::Ipv6 => "[::1]:0".parse().unwrap(),
        Target::Ipv4 | Target::Name => SocketAddress::local_ipv4(0),
    };
    let Some((origin, origin_tasks)) = h3_origin_at(origin_address, case.quic).await else {
        eprintln!("{case:?}: skipped, no IPv6 loopback");
        return;
    };
    let template = case.config.server();
    let (proxy, proxy_tasks) = masque_proxy_with(
        template.as_ref(),
        DestinationScopePolicy::allow_private(),
        case.carrier != Carrier::Http3Capsule,
        case.credentials.proxy(),
        case.quic,
    )
    .await;
    let (scheme, client_template) = case.config.client();
    let proxy = ProxyAddress::try_from(
        format!(
            "{scheme}://{}{proxy}{client_template}",
            case.credentials.userinfo()
        )
        .as_str(),
    )
    .unwrap();
    let target = match case.target {
        Target::Ipv4 | Target::Ipv6 => HostWithPort::from(origin),
        Target::Name => {
            HostWithPort::try_from(format!("localhost:{}", origin.port).as_str()).unwrap()
        }
    };
    let stats = proxy_tasks.proxy.clone().unwrap();
    let version = case.carrier.version();

    // The egress fixtures stay up across runs; every run is a fresh client.
    let egress = match case.perspective {
        Perspective::Direct => None,
        Perspective::MitmEgress => Some(
            quic_mitm_with(
                proxy.clone(),
                target.clone(),
                version,
                http_client_on(Executor::new(), case.quic),
            )
            .await,
        ),
        Perspective::RelayEgress => {
            Some(quic_relay(proxy.clone(), target.clone(), version, case.quic).await)
        }
    };
    let runs = match case.lifecycle {
        Lifecycle::Once => 1,
        Lifecycle::TenRuns => 10,
    };
    for run in 0..runs {
        let label = format!("{case:?} run {run}");
        let exec = Executor::new();
        let (client, host, route) = match &egress {
            None => (
                tunneling_client_with(
                    exec.clone(),
                    version,
                    http_client_on(exec, case.quic),
                    case.quic,
                ),
                target.to_string(),
                Some(&proxy),
            ),
            Some((address, _tasks)) => {
                let host = match case.perspective {
                    // The MITM terminates the name it intercepts.
                    Perspective::MitmEgress => format!("localhost:{}", address.port),
                    _ => address.to_string(),
                };
                (http_client_on(exec, case.quic), host, None)
            }
        };
        let result = exercise(&client, &host, route, case.workload).await;
        if case.credentials == Credentials::WrongPassword {
            let error = result.expect_err(&label);
            if case.perspective == Perspective::Direct {
                assert!(
                    format!("{error:?}").contains("407"),
                    "{label}: expected 407, got {error:?}"
                );
            }
            // The 407 answers the egress; an inner QUIC client only sees its handshake fail.
            assert_eq!(
                proxy_tasks.requests.load(Ordering::SeqCst),
                0,
                "{label}: nothing passed the proxy's authentication"
            );
            assert_eq!(stats.opened(), 0, "{label}: no tunnel was opened");
            assert_eq!(
                origin_tasks.requests.load(Ordering::SeqCst),
                0,
                "{label}: nothing reached the origin"
            );
            return;
        }
        result.unwrap_or_else(|error| panic!("{label}: {error:?}"));
        if case.perspective == Perspective::Direct && case.workload == Workload::Parallel {
            assert_eq!(stats.opened(), run + 1, "{label}: one tunnel per client");
        }
        drop(client);
        if case.lifecycle == Lifecycle::TenRuns {
            released(&stats, &label).await;
        }
    }
    assert!(
        stats.opened() >= runs,
        "{case:?}: the proxy carried every run"
    );
}

/// Wait until every tunnel the proxy accepted is gone.
async fn released(stats: &EgressSockets, label: &str) {
    let released = timeout(Duration::from_secs(10), async {
        while stats.active() > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "{label}: {} tunnels still active",
        stats.active()
    );
}

/// The workload against `host` over HTTP/3, through `route` when the client tunnels itself.
async fn exercise(
    client: &Client,
    host: &str,
    route: Option<&ProxyAddress>,
    workload: Workload,
) -> Result<(), OpaqueError> {
    let request = |method: Method, body: Body| {
        let request = Request::builder()
            .method(method)
            .version(Version::HTTP_3)
            .uri(format!("https://{host}/"))
            .body(body)
            .unwrap();
        if let Some(proxy) = route {
            request
                .extensions()
                .insert(ProxyRoute::Proxy(proxy.clone()));
        }
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        // Loopback fixtures listen on IPv4 unless the origin itself is IPv6.
        request.extensions().insert(DnsResolveIpMode::SingleIpV4);
        request
    };
    match workload {
        Workload::GetSmall => {
            let body = collect(client.serve(request(Method::GET, Body::empty())).await?).await;
            assert_eq!(&body[..], b"HTTP/3.0 origin");
        }
        Workload::PostLarge => {
            let payload: Vec<u8> = (0..mib(2)).map(|i| (i % 251) as u8).collect();
            let body = collect(
                client
                    .serve(request(Method::POST, Body::from(payload.clone())))
                    .await?,
            )
            .await;
            assert!(body == payload, "echo of {} bytes differs", payload.len());
        }
        Workload::Parallel => {
            let responses =
                join_all((0..8).map(|_| client.serve(request(Method::GET, Body::empty())))).await;
            for response in responses {
                assert_eq!(&collect(response?).await[..], b"HTTP/3.0 origin");
            }
        }
    }
    Ok(())
}

async fn collect(response: Response) -> Vec<u8> {
    assert_eq!(response.status(), StatusCode::OK);
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// One named test per curated row, so a failure names its cell.
macro_rules! rows {
    ($($name:ident => $case:expr;)*) => {
        $(
            #[tokio::test]
            async fn $name() {
                run($case).await;
            }
        )*
    };
}

use Carrier::{Http1, Http2, Http3Capsule, Http3Datagram};
use Perspective::{Direct, MitmEgress, RelayEgress};

// Every carrier × perspective pair.
rows! {
    direct_h1 => Case { carrier: Http1, ..BASE };
    direct_h2 => Case { carrier: Http2, ..BASE };
    direct_h3_capsules => Case { carrier: Http3Capsule, ..BASE };
    direct_h3_datagrams => Case { carrier: Http3Datagram, ..BASE };
    mitm_h1 => Case { perspective: MitmEgress, carrier: Http1, ..BASE };
    mitm_h2 => Case { perspective: MitmEgress, carrier: Http2, ..BASE };
    mitm_h3_capsules => Case { perspective: MitmEgress, carrier: Http3Capsule, ..BASE };
    mitm_h3_datagrams => Case { perspective: MitmEgress, carrier: Http3Datagram, ..BASE };
    relay_h1 => Case { perspective: RelayEgress, carrier: Http1, ..BASE };
    relay_h2 => Case { perspective: RelayEgress, carrier: Http2, ..BASE };
    relay_h3_capsules => Case { perspective: RelayEgress, carrier: Http3Capsule, ..BASE };
    relay_h3_datagrams => Case { perspective: RelayEgress, carrier: Http3Datagram, ..BASE };
}

// Every proxy configuration.
rows! {
    config_masque_path => Case { config: ProxyConfig::MasquePath, ..BASE };
    config_masque_query => Case { config: ProxyConfig::MasqueQuery, carrier: Http2, ..BASE };
    config_https_well_known => Case { config: ProxyConfig::HttpsWellKnown, carrier: Http1, ..BASE };
    config_https_query_expansion => Case {
        config: ProxyConfig::HttpsQueryExpansion,
        perspective: MitmEgress,
        ..BASE
    };
}

// Every credential kind, and the wrong password refused.
rows! {
    credentials_basic_h2 => Case { credentials: Credentials::Basic, carrier: Http2, ..BASE };
    credentials_basic_mitm => Case {
        credentials: Credentials::Basic,
        perspective: MitmEgress,
        ..BASE
    };
    credentials_labels_h3 => Case { credentials: Credentials::BasicWithLabels, ..BASE };
    credentials_labels_relay_h1 => Case {
        credentials: Credentials::BasicWithLabels,
        perspective: RelayEgress,
        carrier: Http1,
        ..BASE
    };
    credentials_wrong_password_is_refused => Case {
        credentials: Credentials::WrongPassword,
        carrier: Http2,
        ..BASE
    };
    credentials_wrong_password_refuses_the_mitm_egress => Case {
        credentials: Credentials::WrongPassword,
        perspective: MitmEgress,
        ..BASE
    };
    credentials_wrong_password_refuses_the_relay_egress => Case {
        credentials: Credentials::WrongPassword,
        perspective: RelayEgress,
        carrier: Http1,
        ..BASE
    };
}

// Every target kind.
rows! {
    target_name_h1 => Case { target: Target::Name, carrier: Http1, ..BASE };
    target_name_mitm => Case { target: Target::Name, perspective: MitmEgress, ..BASE };
    target_name_relay_h2 => Case {
        target: Target::Name,
        perspective: RelayEgress,
        carrier: Http2,
        ..BASE
    };
    target_ipv6 => Case { target: Target::Ipv6, ..BASE };
    target_ipv6_capsules => Case { target: Target::Ipv6, carrier: Http3Capsule, ..BASE };
}

// Every workload.
rows! {
    workload_post_large_h3 => Case { workload: Workload::PostLarge, ..BASE };
    workload_post_large_h1 => Case { workload: Workload::PostLarge, carrier: Http1, ..BASE };
    workload_post_large_mitm => Case {
        workload: Workload::PostLarge,
        perspective: MitmEgress,
        ..BASE
    };
    workload_post_large_relay_capsules => Case {
        workload: Workload::PostLarge,
        perspective: RelayEgress,
        carrier: Http3Capsule,
        ..BASE
    };
    workload_parallel_h3 => Case { workload: Workload::Parallel, ..BASE };
    workload_parallel_mitm_h2 => Case {
        workload: Workload::Parallel,
        perspective: MitmEgress,
        carrier: Http2,
        ..BASE
    };
}

// Criterion (a): ten consecutive runs, every tunnel released, on both QUIC TLS backends.
rows! {
    ten_runs_direct => Case { lifecycle: Lifecycle::TenRuns, ..BASE };
    ten_runs_mitm => Case {
        lifecycle: Lifecycle::TenRuns,
        perspective: MitmEgress,
        ..BASE
    };
    ten_runs_direct_rustls => Case { lifecycle: Lifecycle::TenRuns, quic: QuicTls::Rustls, ..BASE };
    ten_runs_mitm_rustls => Case {
        lifecycle: Lifecycle::TenRuns,
        perspective: MitmEgress,
        quic: QuicTls::Rustls,
        ..BASE
    };
}

// Rustls on every carrier and perspective.
rows! {
    rustls_direct_h1 => Case { quic: QuicTls::Rustls, carrier: Http1, ..BASE };
    rustls_direct_h3_capsules => Case { quic: QuicTls::Rustls, carrier: Http3Capsule, ..BASE };
    rustls_relay_h2 => Case {
        quic: QuicTls::Rustls,
        perspective: RelayEgress,
        carrier: Http2,
        ..BASE
    };
    rustls_relay_h3_datagrams => Case { quic: QuicTls::Rustls, perspective: RelayEgress, ..BASE };
    rustls_mitm_h1 => Case { quic: QuicTls::Rustls, perspective: MitmEgress, carrier: Http1, ..BASE };
    rustls_workload_post_large => Case {
        quic: QuicTls::Rustls,
        workload: Workload::PostLarge,
        ..BASE
    };
}

/// Every combination of every dimension, one run each.
#[tokio::test]
#[ignore = "full MASQUE matrix, nightly"]
async fn full_cross_product() {
    for (perspective, quic) in
        [Direct, MitmEgress, RelayEgress]
            .into_iter()
            .flat_map(|perspective| {
                [
                    (perspective, QuicTls::Boring),
                    (perspective, QuicTls::Rustls),
                ]
            })
    {
        for config in [
            ProxyConfig::MasqueDefault,
            ProxyConfig::MasquePath,
            ProxyConfig::MasqueQuery,
            ProxyConfig::HttpsWellKnown,
            ProxyConfig::HttpsQueryExpansion,
        ] {
            for credentials in [
                Credentials::None,
                Credentials::Basic,
                Credentials::BasicWithLabels,
                Credentials::WrongPassword,
            ] {
                for carrier in Carrier::ALL {
                    for target in [Target::Ipv4, Target::Ipv6, Target::Name] {
                        for workload in
                            [Workload::GetSmall, Workload::PostLarge, Workload::Parallel]
                        {
                            run(Case {
                                perspective,
                                quic,
                                config,
                                credentials,
                                carrier,
                                target,
                                workload,
                                lifecycle: Lifecycle::Once,
                            })
                            .await;
                        }
                    }
                }
            }
        }
    }
}
