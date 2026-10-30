//! A principal keyer's error never reaches the logs: it may quote a credential from the request.
//! In a test binary of its own, as tracing's callsite interest is shared by a whole process.

use std::{num::NonZeroU16, sync::Arc};

use parking_lot::Mutex;
use rama_core::{Service as _, error::BoxError, rt::Executor, telemetry::tracing};
use rama_http::{Request, StatusCode, Version};
use rama_masque::connect_udp::{
    ConnectUdpLimits, ConnectUdpService, ConnectUdpTarget, connect_udp_request,
};
use rama_net::address::{Host, ProxyAddress};

/// Captures what a `fmt` subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_keyers_error_never_reaches_the_logs() {
    const CREDENTIAL: &str = "secret-api-key-0451";
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    // Process-wide, before any callsite registers: no other test runs in this binary.
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let limits = ConnectUdpLimits::new()
        .with_max_tunnels_per_principal(1)
        .with_keyer(|_: &Request| Err::<Option<u64>, BoxError>(CREDENTIAL.into()));
    let service = ConnectUdpService::try_new(Executor::default(), None)
        .unwrap()
        .with_limits(limits);
    let proxy = ProxyAddress::try_from("masque://proxy.example:443").unwrap();
    let target = ConnectUdpTarget::new(Host::LOCALHOST_IPV4, NonZeroU16::MIN);
    let request = connect_udp_request(&proxy, &target, Version::HTTP_2).unwrap();

    let response = service.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    for (name, value) in response.headers() {
        let value = String::from_utf8_lossy(value.as_bytes());
        assert!(!value.contains(CREDENTIAL), "{name}: {value}");
    }
    let logs = String::from_utf8_lossy(&captured.0.lock()).into_owned();
    assert!(
        logs.contains("connect-udp principal keyer failed"),
        "the failure was logged: {logs}"
    );
    assert!(!logs.contains(CREDENTIAL), "{logs}");
}
