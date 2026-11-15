//! Opt-in ECH configuration shared by fp, echo and other TLS servers.

use rama::{
    error::{BoxError, ErrorContext as _},
    graceful::WeakScope,
    tls::{
        boring::server::{BoringServerConfigExt as _, EchServerKeys, ReloadableEchServerKeys},
        server::TlsServerConfig,
    },
    utils::octets::mib,
};
use std::{path::Path, sync::Arc};

fn load(path: &Path) -> Result<Arc<EchServerKeys>, BoxError> {
    let file = std::fs::File::open(path).context("open ECH key file")?;
    EchServerKeys::from_json_reader(file, mib(1))
}

pub(crate) fn configure_server_ech_from_env(
    config: &mut TlsServerConfig,
    scope: &WeakScope,
) -> Result<bool, BoxError> {
    let Some(path) = std::env::var_os("RAMA_TLS_ECH_KEYS_FILE") else {
        return Ok(false);
    };
    let path = std::path::PathBuf::from(path);
    let provider = ReloadableEchServerKeys::new(load(&path)?);
    config.set_ech_keys(provider.clone());
    #[cfg(unix)]
    {
        use rama::telemetry::tracing;

        let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .context("register ECH key reload signal")?;
        scope.try_hold()?.into_spawn_task(async move {
            while reload.recv().await.is_some() {
                let path = path.clone();
                let keys = tokio::task::spawn_blocking(move || load(&path))
                    .await
                    .context("load ECH server keys")
                    .and_then(|keys| keys);
                match keys.and_then(|keys| provider.replace(keys)) {
                    Ok(()) => tracing::info!("reloaded ECH server keys"),
                    Err(error) => {
                        tracing::error!(%error, "ECH reload failed; retaining previous keys")
                    }
                }
            }
        });
    }
    #[cfg(not(unix))]
    let _ = scope;
    Ok(true)
}
