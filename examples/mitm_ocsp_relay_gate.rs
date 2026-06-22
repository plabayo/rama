//! Self-contained harness for the MITM OCSP-stapling gate: a local upstream
//! TLS+HTTP server plus the boring [`TlsMitmRelay`] proxy in front of it. It
//! runs the real mirror → issue → staple flow so an external client
//! (`curl --cert-status` / `openssl s_client -status`) can validate the stapled
//! response. Driven by `scripts/ocsp-relay-gate.sh`.
//!
//! The upstream cert advertises the revocation source picked by
//! `--upstream-revocation` (`ocsp`, `crl`, or `none`); the relay staples iff the
//! upstream advertised one, mirroring the origin's posture.
//!
//! `--leaf-revocation` (`staple` default, or `crl` / `ocsp` / `both`) additionally
//! stands up a proxy-hosted revocation responder on loopback and stamps a CRL
//! distribution point and/or AIA OCSP URL onto the re-signed leaf, so clients
//! that ignore staples (libcurl + schannel) can resolve revocation against us.
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
    clippy::let_underscore_must_use,
    reason = "harness: panic-on-setup-error, the READY line on stdout, and best-effort upstream I/O are intended"
)]

use std::{fs, sync::Arc, time::Duration};

use base64::Engine as _;
use rama::{
    ServiceInput,
    error::{BoxError, ErrorContext},
    http::{
        Body, Response, StatusCode,
        header::CONTENT_TYPE,
        server::HttpServer,
        service::web::{
            WebService,
            extract::{Bytes, Path, State},
        },
    },
    io::BridgeIo,
    net::{
        address::Domain,
        tls::{
            client::{ServerVerifyMode, TlsClientConfig},
            server::{SelfSignedData, peek_client_hello_from_input},
        },
    },
    rt::Executor,
    tcp::server::TcpListener as RamaTcpListener,
    tls::boring::{
        client::{BoringClientConfigExt, TlsConnectorData},
        core::{
            asn1::{Asn1Object, Asn1Time},
            bn::{BigNum, MsbOption},
            hash::MessageDigest,
            pkey::{PKey, Private},
            rsa::Rsa,
            ssl::{SslAcceptor, SslMethod},
            tokio::accept,
            x509::{
                X509, X509Builder, X509Extension, X509NameBuilder,
                extension::SubjectAlternativeName,
            },
        },
        proxy::{
            TlsMitmRelay,
            cert_issuer::InMemoryBoringMitmCertIssuer,
            revocation::{
                BoringMitmRevocation, CaId, MitmCa, ProxyHostedRevocation, RevocationArtifact,
                RevocationFetch,
            },
        },
        server::utils::self_signed_server_auth_gen_ca,
    },
};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};

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
        let listener = RamaTcpListener::bind_address("127.0.0.1:0", Executor::default())
            .await
            .context("bind revocation responder")?;
        let addr = listener.local_addr().context("revocation addr")?;
        revoc_addr = Some(addr);
        let ca = Arc::new(MitmCa::new(ca_crt.clone(), ca_key.clone()));
        let revocation =
            ProxyHostedRevocation::new(ca, format!("http://{addr}"), Duration::from_hours(24 * 7));
        let revocation = match leaf_revocation {
            LeafRevocation::Crl => revocation.with_ocsp(false),
            LeafRevocation::Ocsp => revocation.with_crl(false),
            LeafRevocation::Both | LeafRevocation::Staple => revocation,
        };
        let revocation = Arc::new(revocation);
        let state = Arc::new(RevocationState {
            ca_id: revocation.ca().id(),
            revocation: revocation.clone(),
        });
        let web = WebService::new_with_state(state)
            .with_get("/crl", revocation_crl)
            .with_post("/ocsp", revocation_ocsp_post)
            .with_get("/ocsp/{req}", revocation_ocsp_get);
        tokio::spawn(listener.serve(HttpServer::default().service(web)));
        issuer = issuer.with_revocation(revocation);
    }
    let relay = Arc::new(TlsMitmRelay::new(issuer));

    let proxy = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind proxy")?;
    let proxy_addr = proxy.local_addr().context("proxy addr")?;

    if connect {
        // CONNECT-proxy mode: MITM each client through to the real host it asks
        // for (e.g. crates.io), mirroring that origin's real cert. No local
        // upstream; `--upstream-revocation` is ignored.
        announce_ready(proxy_addr, &ca_out, revoc_addr)?;
        loop {
            let (client, _) = proxy.accept().await.context("accept client")?;
            let relay = relay.clone();
            tokio::spawn(async move {
                if let Err(err) = connect_one(&relay, client).await {
                    eprintln!("connect: {err}");
                }
            });
        }
    }

    // Local hermetic mode: a built-in upstream advertising `revocation`.
    let (up_key, up_crt) = upstream_identity(revocation);
    let mut up = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .context("build upstream acceptor")?;
    up.set_certificate(&up_crt).context("upstream cert")?;
    up.set_private_key(&up_key).context("upstream key")?;
    let up_acceptor = Arc::new(up.build());
    let up_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind upstream")?;
    let up_addr = up_listener.local_addr().context("upstream addr")?;
    tokio::spawn(serve_upstream(up_listener, up_acceptor));

    announce_ready(proxy_addr, &ca_out, revoc_addr)?;
    loop {
        let (client, _) = proxy.accept().await.context("accept client")?;
        let relay = relay.clone();
        tokio::spawn(async move {
            if let Err(err) = relay_one(&relay, client, up_addr).await {
                eprintln!("relay: {err}");
            }
        });
    }
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

/// CONNECT-proxy one client: read its `CONNECT host:port`, reply `200`, dial the
/// real host, peek the client's ClientHello to mirror its TLS version/SNI onto
/// the egress connector (which verifies the real cert via native roots), run the
/// relay handshake, then bridge plaintext both ways.
async fn connect_one(
    relay: &TlsMitmRelay<
        impl rama::tls::boring::proxy::cert_issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
    >,
    mut client: TcpStream,
) -> Result<(), BoxError> {
    let target = read_connect_target(&mut client).await?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("write CONNECT 200")?;
    let upstream = TcpStream::connect(&target)
        .await
        .with_context(|| format!("dial upstream {target}"))?;
    let host = target.rsplit_once(':').map_or(target.as_str(), |(h, _)| h);

    // Peek the client's ClientHello off the ingress side and mirror its TLS
    // capabilities onto the egress connector — the same thing the production
    // `TlsMitmRelayService` does. The relay pins the ingress acceptor to the
    // version it negotiated on egress; with a generic egress connector that
    // version can be newer (e.g. TLS 1.3 with crates.io) than the real client
    // offered — cargo's libcurl+schannel is TLS 1.2 only over a CONNECT tunnel
    // — and the pinned ingress would then reject it with UNSUPPORTED_PROTOCOL.
    // Mirroring caps egress to the client's own versions, keeping them aligned.
    let bridge = BridgeIo(ServiceInput::new(client), ServiceInput::new(upstream));
    let (bridge, client_hello) = peek_client_hello_from_input(bridge, None)
        .await
        .context("peek client hello")?;

    let mut config = match &client_hello {
        Some(hello) => TlsClientConfig::new_from_client_hello(hello),
        None => TlsClientConfig::new(),
    };
    if let Ok(domain) = Domain::try_from(host) {
        config.set_server_name(domain.into()); // SNI + verify hostname for egress
    }
    let egress = TlsConnectorData::try_from(&config).ok();

    let BridgeIo(mut ingress, mut egress_stream) = relay
        .handshake(bridge, egress)
        .await
        .map_err(BoxError::from)?;
    copy_bidirectional(&mut ingress, &mut egress_stream)
        .await
        .context("bridge")?;
    Ok(())
}

/// Read an HTTP `CONNECT host:port` request line (up to the blank line) and
/// return the `host:port` authority. Byte-at-a-time so we never over-read into
/// the client's following TLS bytes.
async fn read_connect_target(stream: &mut TcpStream) -> Result<String, BoxError> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).await.context("read CONNECT")? == 0 {
            return Err("eof before CONNECT terminator".into());
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err("CONNECT header too large".into());
        }
    }
    let first_line = buf.split(|&b| b == b'\r').next().unwrap_or_default();
    std::str::from_utf8(first_line)
        .context("CONNECT line utf8")?
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::to_owned)
        .ok_or_else(|| BoxError::from("malformed CONNECT request"))
}

/// MITM a single client connection: connect upstream, run the real relay
/// handshake (mirror → issue → staple), then bridge plaintext both ways.
async fn relay_one(
    relay: &TlsMitmRelay<
        impl rama::tls::boring::proxy::cert_issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
    >,
    client: TcpStream,
    up_addr: std::net::SocketAddr,
) -> Result<(), BoxError> {
    let upstream = TcpStream::connect(up_addr)
        .await
        .context("connect upstream")?;
    let egress = TlsConnectorData::try_from(
        &TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
    )
    .ok();
    let BridgeIo(mut ingress, mut egress_stream) = relay
        .handshake(
            BridgeIo(ServiceInput::new(client), ServiceInput::new(upstream)),
            egress,
        )
        .await
        .map_err(BoxError::from)?;
    copy_bidirectional(&mut ingress, &mut egress_stream)
        .await
        .context("bridge")?;
    Ok(())
}

/// Accept loop for the upstream: TLS handshake, then a fixed `200 OK`.
async fn serve_upstream(listener: TcpListener, acceptor: Arc<SslAcceptor>) {
    while let Ok((sock, _)) = listener.accept().await {
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = accept(&acceptor, sock).await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf).await;
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
                .await;
            let _ = tls.shutdown().await;
        });
    }
}

/// Shared state for the proxy-hosted revocation responder.
struct RevocationState {
    ca_id: CaId,
    revocation: Arc<ProxyHostedRevocation>,
}

#[derive(Deserialize)]
struct OcspGetParams {
    req: String,
}

/// `GET /crl` — the CA-signed CRL.
async fn revocation_crl(State(state): State<Arc<RevocationState>>) -> Response {
    artifact_response(state.revocation.serve(RevocationFetch::Crl {
        ca_id: &state.ca_id,
    }))
}

/// `POST /ocsp` — the OCSP request DER is the body.
async fn revocation_ocsp_post(
    State(state): State<Arc<RevocationState>>,
    Bytes(body): Bytes,
) -> Response {
    artifact_response(state.revocation.serve(RevocationFetch::Ocsp {
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
    artifact_response(state.revocation.serve(RevocationFetch::Ocsp {
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

/// Self-signed upstream identity (key + cert) with a SAN and the given
/// revocation advertisement.
fn upstream_identity(revocation: Revocation) -> (PKey<Private>, X509) {
    let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_text("CN", SNI).expect("cn");
    let name = name.build();

    let mut b = X509Builder::new().expect("x509 builder");
    b.set_version(2).expect("version");
    let serial = {
        let mut bn = BigNum::new().expect("bn");
        bn.rand(159, MsbOption::MAYBE_ZERO, false).expect("rand");
        bn.to_asn1_integer().expect("serial")
    };
    b.set_serial_number(&serial).expect("serial");
    b.set_subject_name(&name).expect("subject");
    b.set_issuer_name(&name).expect("issuer");
    b.set_pubkey(&key).expect("pubkey");
    b.set_not_before(&Asn1Time::days_from_now(0).expect("nb"))
        .expect("set nb");
    b.set_not_after(&Asn1Time::days_from_now(365).expect("na"))
        .expect("set na");

    // SAN so a strict client (curl) accepts the mirrored hostname.
    let san = SubjectAlternativeName::new()
        .dns(SNI)
        .build(&b.x509v3_context(None, None))
        .expect("san");
    b.append_extension(&san).expect("append san");

    match revocation {
        Revocation::None => {}
        Revocation::Ocsp => {
            let oid = Asn1Object::from_str("1.3.6.1.5.5.7.1.1").expect("aia oid");
            let ext = X509Extension::from_der_payload(
                oid.as_ref(),
                false,
                &aia_ocsp_payload(b"http://ocsp.test.example"),
            )
            .expect("aia ext");
            b.append_extension(&ext).expect("append aia");
        }
        Revocation::Crl => {
            let oid = Asn1Object::from_str("2.5.29.31").expect("crldp oid");
            let ext = X509Extension::from_der_payload(
                oid.as_ref(),
                false,
                &crldp_payload(b"http://crl.test.example/a.crl"),
            )
            .expect("crldp ext");
            b.append_extension(&ext).expect("append crldp");
        }
    }
    b.sign(&key, MessageDigest::sha256()).expect("sign");
    (key, b.build())
}

/// DER of `AuthorityInfoAccessSyntax` with one `id-ad-ocsp` AccessDescription.
fn aia_ocsp_payload(uri: &[u8]) -> Vec<u8> {
    let mut loc = vec![0x86, uri.len() as u8];
    loc.extend_from_slice(uri);
    let oid = [0x06u8, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    let mut ad = oid.to_vec();
    ad.extend_from_slice(&loc);
    let mut ad_seq = vec![0x30, ad.len() as u8];
    ad_seq.extend_from_slice(&ad);
    let mut aia = vec![0x30, ad_seq.len() as u8];
    aia.extend_from_slice(&ad_seq);
    aia
}

/// DER of `CRLDistributionPoints` with one fullName URI DistributionPoint.
fn crldp_payload(uri: &[u8]) -> Vec<u8> {
    let mut gn = vec![0x86, uri.len() as u8];
    gn.extend_from_slice(uri);
    let mut full = vec![0xA0, gn.len() as u8];
    full.extend_from_slice(&gn);
    let mut dpn = vec![0xA0, full.len() as u8];
    dpn.extend_from_slice(&full);
    let mut dp = vec![0x30, dpn.len() as u8];
    dp.extend_from_slice(&dpn);
    let mut crldp = vec![0x30, dp.len() as u8];
    crldp.extend_from_slice(&dp);
    crldp
}
