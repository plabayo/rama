use super::*;
use rama_tls::client::TlsClientConfig;
#[cfg(any(feature = "aws-lc", feature = "ring"))]
use {
    crate::client::RustlsTlsConnectorConfig, rama_core::error::BoxErrorExt as _,
    rama_net::tls::ApplicationProtocol,
};
#[cfg(all(unix, feature = "ring"))]
use {
    crate::{client::RustlsClientConfigExt as _, verify::NoServerCertVerifier},
    std::{
        fs,
        future::{Future as _, poll_fn},
        io::Write as _,
        pin::pin,
        process::Command,
        sync::mpsc,
        task::Poll,
        time::Duration,
    },
};

fn custom_root(index: usize) -> TlsClientConfig {
    TlsClientConfig::new()
        .try_with_server_trust_anchors([native_certs::bundled_root_certs()[index].clone()])
        .unwrap()
}

fn cached_roots(cache: &RustlsServerTrustCache, config: &TlsClientConfig) -> Arc<RootCertStore> {
    match cache
        .server_verification(config.as_extensions())
        .unwrap()
        .map(|verification| verification.verifier)
    {
        Some(Either::A(roots)) => roots,
        _ => panic!("expected a rustls root store"),
    }
}

#[test]
fn derived_cache_is_shared_by_clones_and_respects_capacity() {
    let cache = RustlsServerTrustCache::new(NonZeroUsize::new(1).unwrap());
    let clone = cache.clone();
    let independent = RustlsServerTrustCache::default();
    let first = custom_root(0);
    let second = custom_root(1);
    let first_store = cached_roots(&cache, &first);

    assert!(Arc::ptr_eq(&first_store, &cached_roots(&clone, &first)));
    assert!(!Arc::ptr_eq(
        &first_store,
        &cached_roots(&independent, &first)
    ));

    let second_store = cached_roots(&cache, &second);
    cache.cache().run_pending_tasks();
    assert_eq!(cache.cache().entry_count(), 1);
    assert_eq!(clone.cache().entry_count(), 1);

    assert_eq!(first_store.len(), 1);
    assert_eq!(second_store.len(), 1);
}

#[cfg(any(feature = "aws-lc", feature = "ring"))]
#[test]
fn native_config_cache_is_bounded_and_shared_by_clones() {
    crate::ensure_default_crypto_provider();
    let cache = RustlsServerTrustCache::new(NonZeroUsize::new(2).unwrap());
    let clone = cache.clone();
    let protocols = [
        ApplicationProtocol::HTTP_11,
        ApplicationProtocol::HTTP_2,
        ApplicationProtocol::HTTP_3,
        ApplicationProtocol::HTTP_10,
    ];
    for protocol in protocols {
        let config = TlsClientConfig::new().with_alpn([protocol].into_iter().collect());
        let key = RustlsTlsConnectorConfig::from_extensions(config.as_extensions())
            .native_config_key(None)
            .unwrap();
        let built = cache
            .client_config(key.clone(), || {
                Ok(ClientConfig::builder()
                    .with_root_certificates(RootCertStore::empty())
                    .with_no_client_auth())
            })
            .unwrap();
        let shared = clone
            .client_config(key, || {
                Err(BoxError::from_static_str("cached entry expected"))
            })
            .unwrap();
        assert!(Arc::ptr_eq(&built, &shared));
    }
    cache.configs().run_pending_tasks();
    assert!((1..=2).contains(&cache.configs().entry_count()));
}

#[cfg(all(unix, feature = "ring"))]
#[test]
fn cold_default_is_offloaded_and_custom_verification_skips_it() {
    const CHILD: &str = "RAMA_TEST_RUSTLS_COLD_TRUST";
    if let Some(path) = std::env::var_os(CHILD) {
        crate::ensure_default_crypto_provider();
        let config =
            TlsClientConfig::new().with_cert_verifier(Arc::new(NoServerCertVerifier::new()));
        let cache = RustlsServerTrustCache::default();
        std::assert_matches!(
            cache.server_verification(config.as_extensions()).unwrap(),
            None
        );
        RustlsTlsConnectorConfig::from_extensions(config.as_extensions())
            .try_into_client_config_with_provider(
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .unwrap();
        assert!(LazyLock::get(&NATIVE).is_none());

        assert!(
            Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let (release, wait) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            let yielded = wait.recv_timeout(Duration::from_secs(5)).unwrap_or(false);
            let mut out = fs::OpenOptions::new().write(true).open(path).unwrap();
            out.write_all(b"\n").unwrap();
            yielded
        });
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let config = TlsClientConfig::new();
                let mut acquire = pin!(cache.server_verification_async(config.as_extensions()));
                let mut release = Some(release);
                let verification = poll_fn(|cx| {
                    let progress = acquire.as_mut().poll(cx);
                    if let Some(release) = release.take() {
                        let _sent = release.send(matches!(progress, Poll::Pending));
                    }
                    progress
                })
                .await
                .unwrap();
                std::assert_matches!(
                    verification.map(|verification| verification.verifier),
                    Some(Either::A(_))
                );
            });
        assert!(writer.join().unwrap(), "cold default blocked the runtime");
        return;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rama-rustls-roots-{}-{now}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("roots.fifo");
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "client::verification::tests::cold_default_is_offloaded_and_custom_verification_skips_it",
        ])
        .env(CHILD, &path)
        .env("SSL_CERT_FILE", &path)
        .env_remove("SSL_CERT_DIR")
        .env_remove("SSL_CERT_EXTRA_FILE")
        .env_remove("SSL_CERT_EXTRA_DIR")
        .status();
    fs::remove_dir_all(dir).unwrap();
    assert!(status.unwrap().success());
}
