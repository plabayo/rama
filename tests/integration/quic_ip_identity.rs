//! QUIC clients on both TLS backends verify an IP-literal server identity
//! against the certificate's address name without sending SNI.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use rama::{
    extensions::ExtensionsRef as _,
    graceful::WeakScope,
    net::{
        address::{Domain, SocketAddress},
        tls::ApplicationProtocol,
    },
    quic::{
        ClientConfig, Endpoint, ServerConfig,
        proto::capture::CaptureLimits,
        tls::{BoringTlsProvider, QuicClientConfigProvider, RustlsTlsProvider, TlsOptions},
    },
    tls::{
        SecureTransport,
        client::{ClientHello, ClientHelloExtension, TlsClientConfig, TlsClientSni},
        server::{ServerAuthData, TlsServerConfig},
    },
};
use rama_crypto::{
    cert::{CertificateAuthorityData, CertificateIdentity, LeafCertRequest, SelfSignedCaConfig},
    pki_types::CertificateDer,
};
use rama_tls_rustls::dep::rustls::crypto::aws_lc_rs;
use tokio::time::timeout;

const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

fn providers() -> [(&'static str, Box<dyn QuicClientConfigProvider>); 2] {
    [
        ("boring", Box::new(BoringTlsProvider::new())),
        (
            "rustls",
            Box::new(RustlsTlsProvider::new(aws_lc_rs::default_provider().into())),
        ),
    ]
}

/// A leaf naming `identity` and the root that issued it.
fn issued(identity: CertificateIdentity) -> (ServerAuthData, CertificateDer<'static>) {
    let ca = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
    let auth = ServerAuthData::new_issued_by(
        &ca,
        LeafCertRequest {
            config: Default::default(),
            identities: vec![identity],
        },
    )
    .unwrap();
    (auth, ca.certificate_chain()[0].clone())
}

/// Serve one handshake on `ip` with `auth`, and connect to it with `provider`.
///
/// Returns whether the client handshake verified, and whether the server saw a
/// server name extension when it did.
async fn connect(
    provider: &dyn QuicClientConfigProvider,
    ip: IpAddr,
    auth: ServerAuthData,
    anchor: CertificateDer<'static>,
    sni: TlsClientSni,
) -> (bool, Option<ClientHello>) {
    let h3 = || [ApplicationProtocol::HTTP_3].into_iter().collect();
    let server_settings = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn(h3());
    // The server backend is the feature default; the client backend is under test.
    let mut server_config =
        ServerConfig::try_from_rama_tls(&server_settings, TlsOptions::default()).unwrap();
    server_config.set_capture(CaptureLimits::default());
    let server = Endpoint::bind_server(
        WeakScope::detached(),
        server_config,
        SocketAddress::new(ip, 0),
    )
    .await
    .unwrap();
    let address: SocketAddr = server.local_addr().unwrap();
    let accepting = server.clone();
    let observed = tokio::spawn(async move {
        let connection = accepting.accept().await?.accept().ok()?.await.ok()?;
        let hello = connection
            .extensions()
            .get_ref::<SecureTransport>()?
            .client_hello()?
            .clone();
        Some((hello, connection))
    });

    let client_settings = TlsClientConfig::new()
        .with_sni_policy(sni)
        .try_with_server_trust_anchors([anchor])
        .unwrap()
        .with_alpn(h3());
    let client_config = ClientConfig::try_from_rama_tls_with_provider(
        &client_settings,
        TlsOptions::default(),
        provider,
    )
    .unwrap();
    let client = Endpoint::bind_client(WeakScope::detached(), SocketAddress::new(ip, 0))
        .await
        .unwrap();
    let verified = match client.connect_with(client_config, address, &ip.to_string()) {
        Ok(connecting) => connecting.await.is_ok(),
        Err(_) => false,
    };
    let named = if verified {
        let (hello, connection) = observed.await.unwrap().expect("the server accepted");
        connection.close(0u32, b"done");
        Some(hello)
    } else {
        observed.abort();
        None
    };
    client.close(0u32, b"done");
    server.shutdown().await;
    (verified, named)
}

#[tokio::test]
async fn quic_clients_verify_ip_identities_without_sending_sni() {
    for (name, provider) in providers() {
        for ip in [V4, V6] {
            let (auth, anchor) = issued(CertificateIdentity::Ip(ip));
            let (verified, named) = timeout(
                Duration::from_secs(10),
                connect(provider.as_ref(), ip, auth, anchor, TlsClientSni::Auto),
            )
            .await
            .unwrap();
            assert!(verified, "{name} to {ip}");
            let hello = named.unwrap();
            assert!(
                !hello
                    .extensions()
                    .iter()
                    .any(|extension| matches!(extension, ClientHelloExtension::ServerName(_))),
                "{name} to {ip} sent a server name"
            );
        }
    }
}

#[tokio::test]
async fn quic_clients_refuse_certificates_without_the_address() {
    for (name, provider) in providers() {
        for (target, identity) in [
            (V4, CertificateIdentity::Ip(IpAddr::from([127, 0, 0, 2]))),
            (V6, CertificateIdentity::Ip(V4)),
            (V4, CertificateIdentity::Dns(Domain::tld_localhost())),
        ] {
            let (auth, anchor) = issued(identity);
            let (verified, _) = timeout(
                Duration::from_secs(10),
                connect(provider.as_ref(), target, auth, anchor, TlsClientSni::Auto),
            )
            .await
            .unwrap();
            assert!(!verified, "{name} to {target}");
        }
    }
}

#[tokio::test]
async fn quic_clients_opt_in_to_ip_literal_sni() {
    for ip in [V4, V6] {
        let (auth, anchor) = issued(CertificateIdentity::Ip(ip));
        let (verified, hello) = timeout(
            Duration::from_secs(10),
            connect(
                &BoringTlsProvider::new(),
                ip,
                auth,
                anchor,
                TlsClientSni::IncludeIp,
            ),
        )
        .await
        .unwrap();
        assert!(verified, "{ip}");
        assert_eq!(
            hello
                .unwrap()
                .ext_server_name()
                .and_then(|name| name.as_ip()),
            Some(ip)
        );
    }
}

#[test]
fn quic_rustls_rejects_the_ip_literal_sni_opt_in() {
    let config = TlsClientConfig::new()
        .with_sni_policy(TlsClientSni::IncludeIp)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let error = RustlsTlsProvider::new(aws_lc_rs::default_provider().into())
        .client_config(&config, TlsOptions::default())
        .expect_err("unsupported SNI policy must fail configuration");
    assert!(format!("{error:?}").contains("IP literal SNI requires the BoringSSL backend"));
}
