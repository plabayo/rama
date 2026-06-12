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
//! ```sh
//! cargo run --example mitm_ocsp_relay_gate --features=http-full,boring -- \
//!   --upstream-revocation ocsp --ca-out /tmp/ca.pem
//! ```
//!
//! Prints `READY proxy=<addr> ca=<path>` once both listeners are up, then serves
//! until killed.

#![expect(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    reason = "harness: panic-on-setup-error, the READY line on stdout, and best-effort upstream I/O are intended"
)]

use std::{fs, sync::Arc};

use rama::{
    ServiceInput,
    error::{BoxError, ErrorContext},
    io::BridgeIo,
    net::{
        address::Domain,
        tls::{client::ServerVerifyMode, server::SelfSignedData},
    },
    tls::boring::{
        client::TlsConnectorDataBuilder,
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
        proxy::TlsMitmRelay,
        server::utils::self_signed_server_auth_gen_ca,
    },
};
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

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut revocation = Revocation::Ocsp;
    let mut ca_out = "/tmp/rama-mitm-ocsp-ca.pem".to_owned();
    let mut connect = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--upstream-revocation" => {
                revocation = Revocation::parse(&args.next().context("missing revocation value")?)?;
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
    let relay = Arc::new(TlsMitmRelay::new_in_memory(ca_crt, ca_key));

    let proxy = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind proxy")?;
    let proxy_addr = proxy.local_addr().context("proxy addr")?;

    if connect {
        // CONNECT-proxy mode: MITM each client through to the real host it asks
        // for (e.g. crates.io), mirroring that origin's real cert. No local
        // upstream; `--upstream-revocation` is ignored.
        announce_ready(proxy_addr, &ca_out)?;
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

    announce_ready(proxy_addr, &ca_out)?;
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

fn announce_ready(proxy_addr: std::net::SocketAddr, ca_out: &str) -> Result<(), BoxError> {
    use std::io::Write as _;
    println!("READY proxy={proxy_addr} ca={ca_out}");
    std::io::stdout().flush().context("flush stdout")?;
    Ok(())
}

/// CONNECT-proxy one client: read its `CONNECT host:port`, reply `200`, dial the
/// real host, run the relay handshake (egress verifies the real cert via native
/// roots and sends SNI), then bridge plaintext both ways.
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
    let mut builder = TlsConnectorDataBuilder::new();
    if let Ok(domain) = Domain::try_from(host) {
        builder = builder.with_server_name(domain); // SNI for the egress handshake
    }
    let egress = builder.build().ok();
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
    let egress = TlsConnectorDataBuilder::new()
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .build()
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
