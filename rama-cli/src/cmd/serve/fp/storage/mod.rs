use std::fmt;

use rama::{
    error::{BoxError, ErrorContext},
    extensions::Extensions,
    net::uri::Uri,
    rt::Executor,
    telemetry::tracing,
    ua::profile::model::{js::JsProfileWebApis, ua::UserAgentSourceInfo},
};

mod profile_source;
pub(crate) use profile_source::CountedProfileSource;

mod export;
pub(crate) use export::export_counted_profiles;

mod collector;
mod counted;
mod intent;
mod issuer;
mod legacy;
mod migrations;
mod startup;
mod worker;
use super::data::Http3Info;
pub(super) use intent::{CaptureLayer, is_protocol_probe};
use worker::CollectionQueue;
mod postgres;

#[derive(Clone)]
pub(super) struct Storage {
    queue: Option<CollectionQueue>,
}

impl fmt::Debug for Storage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Storage").finish_non_exhaustive()
    }
}

struct DebugPgUrl(Option<Uri>);

impl fmt::Debug for DebugPgUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(uri) => fmt::Debug::fmt(uri, f),
            None => f.write_str("<invalid uri>"),
        }
    }
}

fn debug_pg_url(pg_url: &str) -> DebugPgUrl {
    DebugPgUrl(Uri::parse(pg_url).ok())
}

impl Storage {
    #[cfg(test)]
    pub(super) fn unavailable() -> Self {
        Self { queue: None }
    }

    pub(super) async fn try_new(pg_url: String, exec: &Executor) -> Result<Self, BoxError> {
        let url = debug_pg_url(&pg_url);
        tracing::debug!(
            url.full = ?url,
            "create new PG storage",
        );
        let pool = postgres::try_new_pool(pg_url).await?;
        {
            let mut client = pool.get().await.context("get fp migration client")?;
            migrations::apply(&mut client).await?;
        }
        let queue = Some(startup::start(pool.clone(), exec).await?);
        Ok(Self { queue })
    }
}

impl Storage {
    pub(super) fn capture_layer(&self) -> Option<CaptureLayer> {
        self.queue.clone().map(CaptureLayer::new)
    }

    pub(super) fn submit(&self, ext: &Extensions, h3: Option<&Http3Info>) {
        if self.queue.is_some() {
            intent::submit(ext, h3);
        }
    }

    pub(super) fn capture_runtime(
        &self,
        ext: &Extensions,
        source: Option<&UserAgentSourceInfo>,
        web_apis: Option<&JsProfileWebApis>,
    ) {
        if self.queue.is_some() {
            intent::attach_runtime(ext, source, web_apis);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_pg_url_redacts_password() {
        let formatted = format!(
            "{:?}",
            debug_pg_url("postgres://alice:super-secret@example.com/rama")
        );

        assert!(
            !formatted.contains("super-secret"),
            "debug leaked database password: {formatted}"
        );
        assert!(
            formatted.contains("***"),
            "debug missing URI redaction marker: {formatted}"
        );
    }

    #[test]
    fn debug_pg_url_does_not_echo_invalid_input() {
        let formatted = format!(
            "{:?}",
            debug_pg_url("postgres://alice:super-secret@example.com/rama\r")
        );

        assert_eq!(formatted, "<invalid uri>");
    }
}
