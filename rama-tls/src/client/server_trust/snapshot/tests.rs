use std::{env, process::Command, time::Duration};
#[cfg(target_vendor = "apple")]
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::PathBuf,
    thread,
    time::Instant,
};

use rama_crypto::pki_types::CertificateDer;
#[cfg(target_vendor = "apple")]
use rama_utils::fs::TempDir;

use super::{
    Arc, PlatformVerifier, ServerTrustKey, ServerTrustRoots, ServerTrustSnapshot,
    ServerTrustSource, SharedServerTrustRoots, TlsServerTrust, TlsServerTrustAnchors,
    shared_platform_verifier, shared_platform_verifier_async,
};
use crate::client::{ChannelReloadTrigger, NativeTrustPolicy, PlatformTrustPolicy};

fn anchors() -> TlsServerTrustAnchors {
    TlsServerTrustAnchors::try_new([CertificateDer::from(vec![1])]).unwrap()
}

#[test]
fn only_native_and_platform_policies_with_reload_settings_reload() {
    let (_sender, native_trigger) = ChannelReloadTrigger::new();
    let (_sender, platform_trigger) = ChannelReloadTrigger::new();
    let reloadable = [
        ServerTrustSource::Native(NativeTrustPolicy::new().with_reload_trigger(native_trigger)),
        ServerTrustSource::Native(NativeTrustPolicy::new().with_max_age(Duration::ZERO)),
        ServerTrustSource::Platform(
            PlatformTrustPolicy::new().with_reload_trigger(platform_trigger),
        ),
        ServerTrustSource::Platform(
            PlatformTrustPolicy::new().with_max_age(Duration::from_mins(1)),
        ),
    ];
    let fixed = [
        ServerTrustSource::native_roots(),
        ServerTrustSource::platform_verifier(),
        ServerTrustSource::Platform(
            PlatformTrustPolicy::new()
                .with_max_age(Duration::ZERO)
                .without_max_age(),
        ),
        ServerTrustSource::WebPki,
        ServerTrustSource::Custom(anchors()),
    ];
    assert!(reloadable.iter().all(ServerTrustSource::is_reloadable));
    assert!(!fixed.iter().any(ServerTrustSource::is_reloadable));
}

#[test]
fn static_sources_resolve_without_reading_trust() {
    let platform = if PlatformVerifier::IS_AVAILABLE {
        SharedServerTrustRoots::Platform
    } else {
        SharedServerTrustRoots::Native
    };
    for (trust, shared) in [
        (
            TlsServerTrust::native_roots(),
            SharedServerTrustRoots::Native,
        ),
        (
            TlsServerTrust::webpki_roots(),
            SharedServerTrustRoots::WebPki,
        ),
        (TlsServerTrust::platform_verifier(), platform),
    ] {
        let snapshot = ServerTrustSnapshot::read(&trust).unwrap();
        assert_eq!(snapshot.shared(), Some(shared));
        let extended = trust.try_with_additional_anchors([CertificateDer::from(vec![2])]);
        let extended = ServerTrustSnapshot::read(&extended.unwrap()).unwrap();
        assert_eq!(extended.shared(), None);
        assert_ne!(extended.key(), snapshot.key());
    }
    let custom = ServerTrustSnapshot::read(&TlsServerTrust::custom(anchors())).unwrap();
    assert!(matches!(custom.roots(), ServerTrustRoots::Custom(_)));
    assert_eq!(
        custom.key(),
        ServerTrustSnapshot::read(&TlsServerTrust::custom(anchors()))
            .unwrap()
            .key()
    );
}

async fn key(trust: &TlsServerTrust, read_async: bool) -> ServerTrustKey {
    let snapshot = if read_async {
        ServerTrustSnapshot::read_async(trust).await
    } else {
        ServerTrustSnapshot::read(trust)
    };
    snapshot.unwrap().key()
}

#[tokio::test]
async fn the_read_that_consumes_an_event_rotates_operating_system_verification() {
    for read_async in [false, true] {
        let (native_sender, native_trigger) = ChannelReloadTrigger::new();
        let (platform_sender, platform_trigger) = ChannelReloadTrigger::new();
        let native =
            TlsServerTrust::from(NativeTrustPolicy::new().with_reload_trigger(native_trigger));
        let platform =
            TlsServerTrust::from(PlatformTrustPolicy::new().with_reload_trigger(platform_trigger));

        for (trust, sender, rotates) in [
            (native, native_sender, false),
            (platform, platform_sender, PlatformVerifier::IS_AVAILABLE),
        ] {
            let first = key(&trust, read_async).await;
            assert_eq!(first, key(&trust, read_async).await);
            // No read has polled this event yet. The next one polls it while
            // pinning its anchors and must already key on the new generation.
            sender.request_reload().unwrap();
            let next = key(&trust, read_async).await;
            assert_eq!(first != next, rotates);
            assert_eq!(next, key(&trust, read_async).await);
        }
    }
}

#[cfg(target_vendor = "apple")]
#[test]
fn reads_during_an_event_refresh_key_on_the_new_generation() {
    const CHILD: &str = "RAMA_TEST_SNAPSHOT_FLIGHT_EXTRAS";
    let Some(extras) = env::var_os(CHILD) else {
        let dir = TempDir::new_sync().unwrap();
        let mut child = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "client::server_trust::snapshot::tests::reads_during_an_event_refresh_key_on_the_new_generation",
            ])
            .env(CHILD, dir.path().join("extras.pem"))
            .env("SSL_CERT_EXTRA_FILE", dir.path().join("extras.pem"))
            .env_remove("SSL_CERT_EXTRA_DIR")
            .spawn()
            .unwrap();
        // A regression can block on the FIFO; bound the child from outside.
        let deadline = Instant::now() + Duration::from_secs(20);
        let succeeded = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status.success();
            }
            if Instant::now() >= deadline {
                _ = child.kill();
                _ = child.wait().unwrap();
                break false;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(succeeded, "the overlapping reads failed or blocked");
        return;
    };
    let extras = PathBuf::from(extras);
    for max_age in [None, Some(Duration::ZERO)] {
        fs::write(&extras, b"").unwrap();
        let (sender, trigger) = ChannelReloadTrigger::new();
        let trust = TlsServerTrust::from(
            PlatformTrustPolicy::new()
                .with_reload_trigger(trigger)
                .maybe_with_max_age(max_age),
        );
        let first = ServerTrustSnapshot::read(&trust).unwrap().key();

        // The refresh blocks on the FIFO until this test opens and closes it.
        fs::remove_file(&extras).unwrap();
        assert!(
            Command::new("mkfifo")
                .arg(&extras)
                .status()
                .unwrap()
                .success()
        );
        sender.request_reload().unwrap();
        let refreshing = thread::spawn({
            let trust = trust.clone();
            move || ServerTrustSnapshot::read(&trust).unwrap().key()
        });
        let mut fifo = OpenOptions::new().write(true).open(&extras).unwrap();
        // Later refreshes read a regular file with the same, empty, contents.
        fs::remove_file(&extras).unwrap();
        fs::write(&extras, b"").unwrap();
        let overlapping = thread::spawn(move || ServerTrustSnapshot::read(&trust).unwrap().key());
        if max_age.is_none() {
            // A fresh snapshot is served without waiting for the refresh.
            let overlapping = overlapping.join().unwrap();
            assert_ne!(overlapping, first);
            fifo.write_all(b"").unwrap();
            drop(fifo);
            assert_eq!(refreshing.join().unwrap(), overlapping);
        } else {
            fifo.write_all(b"").unwrap();
            drop(fifo);
            let refreshed = refreshing.join().unwrap();
            assert_ne!(refreshed, first);
            assert_eq!(overlapping.join().unwrap(), refreshed);
        }
    }
}

#[test]
fn static_platform_snapshot_reuses_the_shared_verifier() {
    let platform = ServerTrustSnapshot::read(&TlsServerTrust::platform_verifier()).unwrap();
    if PlatformVerifier::IS_AVAILABLE {
        let verifier = platform.platform_verifier().unwrap();
        assert!(Arc::ptr_eq(&verifier, &shared_platform_verifier()));
    } else {
        // Without an operating system verifier, platform trust is the static native store.
        assert_eq!(platform.shared(), Some(SharedServerTrustRoots::Native));
    }
}

#[test]
fn async_platform_verifier_is_the_shared_one_when_called_first() {
    const CHILD: &str = "RAMA_TEST_ASYNC_PLATFORM_VERIFIER_FIRST";
    if env::var_os(CHILD).is_none() {
        // The process-wide verifier must be unbuilt, so run in a fresh process.
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "client::server_trust::snapshot::tests::async_platform_verifier_is_the_shared_one_when_called_first",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    assert!(super::PLATFORM.get().is_none());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let first = runtime.block_on(shared_platform_verifier_async()).unwrap();
    assert!(Arc::ptr_eq(&first, &shared_platform_verifier()));
    let again = runtime.block_on(shared_platform_verifier_async()).unwrap();
    assert!(Arc::ptr_eq(&first, &again));
}
