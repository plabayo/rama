#![cfg(all(unix, feature = "native-certs"))]

use rama_core::futures::{FutureExt as _, StreamExt as _, stream};
use rama_tls::client::UnixSignalTrigger;
use std::{process::Command, time::Duration};
use tokio::signal::unix::SignalKind;

// Keep process-wide signal dispositions isolated from the library unit tests.
#[tokio::test]
async fn sighup_and_custom_unix_signal_request_reload() {
    let mut triggers = stream::select(
        UnixSignalTrigger::sighup().unwrap(),
        UnixSignalTrigger::new(SignalKind::user_defined1()).unwrap(),
    );
    for signal in ["HUP", "USR1"] {
        assert!(triggers.next().now_or_never().is_none());
        let sent = Command::new("kill")
            .args(["-s", signal, &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        let event = tokio::time::timeout(Duration::from_secs(5), triggers.next())
            .await
            .expect("registered signal should request a reload");
        assert_eq!(event, Some(()));
    }
    assert!(triggers.next().now_or_never().is_none());
}
