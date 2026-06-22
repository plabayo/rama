//! Self-contained harness for the MITM revocation gate: the boring
//! [`TlsMitmRelay`] in front of either a built-in upstream (local hermetic mode)
//! or a real host reached through an HTTP `CONNECT` tunnel. It runs the real
//! mirror → issue → staple/replace flow so external clients (`curl`,
//! `openssl s_client`, `cargo`) can validate the re-signed leaf.
//!
//! The whole proxy is assembled from rama building blocks — `UpgradeLayer`
//! (CONNECT), `IoToProxyBridgeIoLayer` (egress dial + bridge), the TLS
//! client-hello peek router, `TlsMitmRelay` as a layer, and `IoForwardService`
//! to bridge the terminated streams. The local upstream is a rama `HttpServer`
//! behind a `TlsAcceptorLayer`, and the revocation endpoints are a rama
//! `WebService`.
//!
//! `--upstream-revocation` (`ocsp` / `crl` / `none`) sets what the local upstream
//! cert advertises; `--leaf-revocation` (`staple` default, or `crl` / `ocsp` /
//! `both`) stands up a proxy-hosted revocation responder on loopback and stamps
//! the matching pointer onto the re-signed leaf.
//!
//! ```sh
//! cargo run --example mitm_ocsp_relay_gate --features=http-full,boring -- \
//!   --upstream-revocation crl --leaf-revocation crl --ca-out /tmp/ca.pem
//! ```
//!
//! Prints `READY proxy=<addr> ca=<path> [revoc=<addr>]` once the listeners are up,
//! then serves until killed.

#![expect(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "harness: panic-on-setup-error and the READY line on stdout are intended"
)]

use std::{convert::Infallible, fs, sync::Arc, time::Duration};

use base64::Engine as _;
use rama::{
    Layer,
    error::{BoxError, ErrorContext},
    http::{
        Body, Request, Response, StatusCode,
        header::CONTENT_TYPE,
        layer::{
            trace::TraceLayer,
            upgrade::{DefaultHttpProxyConnectReplyService, UpgradeLayer},
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::{
            WebService,
            extract::{Bytes, Path, State},
        },
    },
    layer::ConsumeErrLayer,
    net::{
        proxy::IoForwardService,
        tls::{
            DataEncoding,
            server::{
                PeekTlsClientHelloService, SelfSignedData, ServerAuth, ServerAuthData, ServerConfig,
            },
        },
    },
    rt::Executor,
    service::service_fn,
    tcp::{proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    tls::boring::{
        core::{
            asn1::Asn1Time,
            bn::{BigNum, MsbOption},
            hash::MessageDigest,
            pkey::{PKey, Private},
            rsa::Rsa,
            x509::{X509, X509Builder, X509NameBuilder, extension::SubjectAlternativeName},
        },
        proxy::{
            TlsMitmRelay,
            cert_issuer::InMemoryBoringMitmCertIssuer,
            revocation::{
                BoringMitmRevocation, CaId, MitmCa, ProxyHostedRevocation, RevocationArtifact,
                RevocationFetch, aia_ocsp_extension, crl_distribution_point_extension,
            },
        },
        server::utils::self_signed_server_auth_gen_ca,
        server::{TlsAcceptorData, TlsAcceptorLayer},
    },
};
use serde::Deserialize;

/// Hostname mirrored onto the leaf; clients connect with this SNI.
const SNI: &str = "upstream.example";

#[derive(Clone, Copy)]
enum Revocation {
    Ocsp,
    Crl,
    None,
}

impl Revocation {
    fn parse(s: &str) -> Result<Self, BoxError> {
        match s {
            "ocsp" => Ok(Self::Ocsp),
            "crl" => Ok(Self::Crl),
            "none" => Ok(Self::None),
            other => Err(format!("invalid --upstream-revocation: {other}").into()),
        }
    }
}

/// How the re-signed leaf advertises revocation to the client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LeafRevocation {
    /// OCSP staple only (the default; what the relay does out of the box).
    Staple,
    /// Stamp a CRL distribution point pointing at a proxy-hosted responder.
    Crl,
    /// Stamp an AIA OCSP responder pointing at a proxy-hosted responder.
    Ocsp,
    /// Stamp both a CRL distribution point and an AIA OCSP responder.
    Both,
}

impl LeafRevocation {
    fn parse(s: &str) -> Result<Self, BoxError> {
        match s {
            "staple" => Ok(Self::Staple),
            "crl" => Ok(Self::Crl),
            "ocsp" => Ok(Self::Ocsp),
            "both" => Ok(Self::Both),
            other => Err(format!("invalid --leaf-revocation: {other}").into()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut revocation = Revocation::Ocsp;
    let mut leaf_revocation = LeafRevocation::Staple;
    let mut ca_out = "/tmp/rama-mitm-ocsp-ca.pem".to_owned();
    let mut connect = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--upstream-revocation" => {
                revocation = Revocation::parse(&args.next().context("missing revocation value")?)?;
            }
            "--leaf-revocation" => {
                leaf_revocation =
                    LeafRevocation::parse(&args.next().context("missing leaf revocation value")?)?;
            }
            "--ca-out" => ca_out = args.next().context("missing --ca-out value")?,
            // CONNECT-proxy mode: MITM clients through to the real host they ask
            // for (e.g. crates.io) instead of the built-in local upstream.
            "--connect" => connect = true,
            other => return Err(format!("unknown arg: {other}").into()),
        }
    }

    let exec = Executor::default();

    // MITM relay with a fresh in-memory CA; export the CA cert for the client.
    let (ca_crt, ca_key) = self_signed_server_auth_gen_ca(&SelfSignedData {
        organisation_name: Some("Rama MITM OCSP Gate".to_owned()),
        ..Default::default()
    })
    .context("gen MITM CA")?;
    fs::write(&ca_out, ca_crt.to_pem().context("CA to PEM")?).context("write CA PEM")?;

    // Optionally stand up a proxy-hosted revocation responder, sharing the CA,
    // and stamp its pointers onto each re-signed leaf.
    let mut issuer = InMemoryBoringMitmCertIssuer::new(ca_crt.clone(), ca_key.clone());
    let mut revoc_addr = None;
    if leaf_revocation != LeafRevocation::Staple {
        let listener = TcpListener::bind_address("127.0.0.1:0", exec.clone())
            .await
            .context("bind revocation responder")?;
        let addr = listener.local_addr().context("revocation addr")?;
        revoc_addr = Some(addr);
        let ca = Arc::new(MitmCa::new(ca_crt.clone(), ca_key.clone()));
        let responder =
            ProxyHostedRevocation::new(ca, format!("http://{addr}"), Duration::from_hours(24 * 7));
        let responder = match leaf_revocation {
            LeafRevocation::Crl => responder.with_ocsp(false),
            LeafRevocation::Ocsp => responder.with_crl(false),
            LeafRevocation::Both | LeafRevocation::Staple => responder,
        };
        let responder = Arc::new(responder);
        let state = Arc::new(RevocationState {
            ca_id: responder.ca().id(),
            responder: responder.clone(),
        });
        let web = WebService::new_with_state(state)
            .with_get("/crl", revocation_crl)
            .with_post("/ocsp", revocation_ocsp_post)
            .with_get("/ocsp/{req}", revocation_ocsp_get);
        tokio::spawn(listener.serve(HttpServer::auto(exec.clone()).service(web)));
        issuer = issuer.with_revocation(responder);
    }
    let relay = TlsMitmRelay::new(issuer);

    let proxy = TcpListener::bind_address("127.0.0.1:0", exec.clone())
        .await
        .context("bind proxy")?;
    let proxy_addr = proxy.local_addr().context("proxy addr")?;

    if connect {
        // CONNECT-proxy mode: terminate the tunnel, dial the requested host, and
        // MITM it. `--upstream-revocation` is ignored (the real origin's cert is
        // mirrored). No local upstream.
        announce_ready(proxy_addr, &ca_out, revoc_addr)?;
        let mitm_svc = Arc::new(
            (
                ConsumeErrLayer::trace_as_debug(),
                IoToProxyBridgeIoLayer::extension_connector_target(exec.clone()),
            )
                .into_layer(mitm_app(relay, exec.clone())),
        );
        let http_service = HttpServer::auto(exec.clone()).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                UpgradeLayer::new(
                    exec.clone(),
                    MethodMatcher::CONNECT,
                    DefaultHttpProxyConnectReplyService::new(),
                    mitm_svc,
                ),
            )
                .into_layer(service_fn(reject_non_connect)),
        ));
        proxy.serve(http_service).await;
        return Ok(());
    }

    // Local hermetic mode: a built-in upstream (rama HTTPS server) advertising
    // `revocation`; the relay dials it for every client connection.
    let upstream = TcpListener::bind_address("127.0.0.1:0", exec.clone())
        .await
        .context("bind upstream")?;
    let up_addr = upstream.local_addr().context("upstream addr")?;
    let up_acceptor = upstream_acceptor_data(revocation)?;
    let up_service =
        TlsAcceptorLayer::new(up_acceptor).into_layer(HttpServer::auto(exec.clone()).service(
            service_fn(async |_: Request| Ok::<_, Infallible>(Response::new(Body::from("ok\n")))),
        ));
    tokio::spawn(upstream.serve(up_service));

    announce_ready(proxy_addr, &ca_out, revoc_addr)?;
    let local_svc = Arc::new(
        (
            ConsumeErrLayer::trace_as_debug(),
            IoToProxyBridgeIoLayer::new(exec.clone(), up_addr),
        )
            .into_layer(mitm_app(relay, exec.clone())),
    );
    proxy.serve(local_svc).await;
    Ok(())
}

/// The MITM core, shared by both modes: peek the client hello, run the relay
/// (mirror → issue → staple/replace), and bridge the terminated streams to the
/// already-dialed egress. Non-TLS input falls back to a plain byte forward.
fn mitm_app(
    relay: TlsMitmRelay<InMemoryBoringMitmCertIssuer>,
    exec: Executor,
) -> PeekTlsClientHelloService<
    rama::tls::boring::proxy::TlsMitmRelayService<InMemoryBoringMitmCertIssuer, IoForwardService>,
    IoForwardService,
> {
    let forward = IoForwardService::new(exec);
    PeekTlsClientHelloService::new(relay.into_layer(forward.clone())).with_fallback(forward)
}

async fn reject_non_connect(_req: Request) -> Result<Response, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(Body::empty())
        .expect("build 405 response"))
}

fn announce_ready(
    proxy_addr: std::net::SocketAddr,
    ca_out: &str,
    revoc_addr: Option<std::net::SocketAddr>,
) -> Result<(), BoxError> {
    use std::io::Write as _;
    match revoc_addr {
        Some(addr) => println!("READY proxy={proxy_addr} ca={ca_out} revoc={addr}"),
        None => println!("READY proxy={proxy_addr} ca={ca_out}"),
    }
    std::io::stdout().flush().context("flush stdout")?;
    Ok(())
}

/// Shared state for the proxy-hosted revocation responder.
struct RevocationState {
    ca_id: CaId,
    responder: Arc<ProxyHostedRevocation>,
}

#[derive(Deserialize)]
struct OcspGetParams {
    req: String,
}

/// `GET /crl` — the CA-signed CRL.
async fn revocation_crl(State(state): State<Arc<RevocationState>>) -> Response {
    artifact_response(state.responder.serve(RevocationFetch::Crl {
        ca_id: &state.ca_id,
    }))
}

/// `POST /ocsp` — the OCSP request DER is the body.
async fn revocation_ocsp_post(
    State(state): State<Arc<RevocationState>>,
    Bytes(body): Bytes,
) -> Response {
    artifact_response(state.responder.serve(RevocationFetch::Ocsp {
        ca_id: &state.ca_id,
        der_request: body.as_ref(),
    }))
}

/// `GET /ocsp/{req}` — the OCSP request DER is base64 in the path (RFC 6960
/// A.1.1); the router percent-decodes `req` for us.
async fn revocation_ocsp_get(
    State(state): State<Arc<RevocationState>>,
    Path(OcspGetParams { req }): Path<OcspGetParams>,
) -> Response {
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(req.as_bytes()) else {
        return empty_status(StatusCode::BAD_REQUEST);
    };
    artifact_response(state.responder.serve(RevocationFetch::Ocsp {
        ca_id: &state.ca_id,
        der_request: &der,
    }))
}

fn artifact_response(result: Result<RevocationArtifact, BoxError>) -> Response {
    match result {
        Ok(art) => Response::builder()
            .header(CONTENT_TYPE, art.content_type.as_str())
            .body(Body::from(art.body))
            .expect("build revocation response"),
        Err(err) => {
            eprintln!("revoc: {err}");
            empty_status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

fn empty_status(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("build empty response")
}

/// Build the local upstream's TLS acceptor data: a self-signed leaf advertising
/// `revocation`, served by the rama TLS acceptor so the relay mirrors it.
fn upstream_acceptor_data(revocation: Revocation) -> Result<TlsAcceptorData, BoxError> {
    let (key, cert) = upstream_identity(revocation)?;
    let config = ServerConfig::new(ServerAuth::Single(ServerAuthData {
        private_key: DataEncoding::Der(key.private_key_to_der().context("upstream key to DER")?),
        cert_chain: DataEncoding::Der(cert.to_der().context("upstream cert to DER")?),
        ocsp: None,
    }));
    TlsAcceptorData::try_from(config).context("upstream acceptor data")
}

/// Self-signed upstream identity (key + cert) with a SAN and the given
/// revocation advertisement (whose URLs the relay strips and replaces).
fn upstream_identity(revocation: Revocation) -> Result<(PKey<Private>, X509), BoxError> {
    let key = PKey::from_rsa(Rsa::generate(2048).context("rsa")?).context("pkey")?;
    let mut name = X509NameBuilder::new().context("name builder")?;
    name.append_entry_by_text("CN", SNI).context("cn")?;
    let name = name.build();

    let mut b = X509Builder::new().context("x509 builder")?;
    b.set_version(2).context("version")?;
    let serial = {
        let mut bn = BigNum::new().context("bn")?;
        bn.rand(159, MsbOption::MAYBE_ZERO, false).context("rand")?;
        bn.to_asn1_integer().context("serial")?
    };
    b.set_serial_number(&serial).context("serial")?;
    b.set_subject_name(&name).context("subject")?;
    b.set_issuer_name(&name).context("issuer")?;
    b.set_pubkey(&key).context("pubkey")?;
    b.set_not_before(Asn1Time::days_from_now(0).context("nb")?.as_ref())
        .context("set nb")?;
    b.set_not_after(Asn1Time::days_from_now(365).context("na")?.as_ref())
        .context("set na")?;

    let san = SubjectAlternativeName::new()
        .dns(SNI)
        .build(&b.x509v3_context(None, None))
        .context("san")?;
    b.append_extension(&san).context("append san")?;

    match revocation {
        Revocation::None => {}
        Revocation::Ocsp => {
            b.append_extension(aia_ocsp_extension("http://ocsp.test.example")?.as_ref())
                .context("append aia")?;
        }
        Revocation::Crl => {
            b.append_extension(
                crl_distribution_point_extension("http://crl.test.example/a.crl")?.as_ref(),
            )
            .context("append crldp")?;
        }
    }
    b.sign(&key, MessageDigest::sha256()).context("sign")?;
    Ok((key, b.build()))
}
