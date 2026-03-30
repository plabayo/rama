use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    futures::{Stream, async_stream::stream_fn, stream},
    telemetry::tracing,
};
use rama_net::address::Domain;
use rama_utils::{
    macros::{error::static_str_error, generate_set_and_with},
    str::arcstr::ArcStr,
};

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Portable DNS resolver backed by [`tokio::net::lookup_host`].
///
/// This relies on the host resolver for address lookups and does not support TXT
/// record resolution.
pub struct TokioDnsResolver {
    timeout: Duration,
}

impl Default for TokioDnsResolver {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl TokioDnsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    generate_set_and_with! {
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }
}

impl DnsAddressResolver for TokioDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        lookup_host_stream(domain, self.timeout, |addr| match addr {
            SocketAddr::V4(addr) => Some(*addr.ip()),
            SocketAddr::V6(_) => None,
        })
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        lookup_host_stream(domain, self.timeout, |addr| match addr {
            SocketAddr::V4(_) => None,
            SocketAddr::V6(addr) => Some(*addr.ip()),
        })
    }
}

impl DnsTxtResolver for TokioDnsResolver {
    type Error = TokioDnsTxtUnsupportedError;

    fn lookup_txt(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Err(TokioDnsTxtUnsupportedError)))
    }
}

impl DnsResolver for TokioDnsResolver {}

fn lookup_host_stream<T, F>(
    domain: Domain,
    timeout: Duration,
    map_addr: F,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: Copy + Eq + std::hash::Hash + Send + 'static,
    F: Fn(SocketAddr) -> Option<T> + Send + Sync + 'static,
{
    stream_fn(async move |mut yielder| {
        tracing::debug!(?timeout, %domain, "dns::tokio: lookup_host");

        let lookup = match tokio::time::timeout(
            timeout,
            tokio::net::lookup_host((domain.as_str(), 0)),
        )
        .await
        {
            Ok(Ok(lookup)) => lookup,
            Ok(Err(err)) => {
                yielder
                    .yield_item(Err(TokioDnsResolverError::message(format!(
                        "tokio dns lookup_host failed: {err}"
                    ))
                    .into()))
                    .await;
                return;
            }
            Err(err) => {
                tracing::debug!("tokio::lookup_host: error = {err} (report as timeout)");
                yielder
                    .yield_item(Err(TokioDnsResolverError::timeout(timeout).into()))
                    .await;
                return;
            }
        };

        for addr in lookup {
            if let Some(value) = map_addr(addr) {
                yielder.yield_item(Ok(value)).await;
            }
        }
    })
}

#[derive(Debug)]
struct TokioDnsResolverError(ArcStr);

impl TokioDnsResolverError {
    fn message(message: impl Into<ArcStr>) -> Self {
        Self(message.into())
    }

    fn timeout(timeout: Duration) -> Self {
        Self::message(format!("tokio dns lookup timed out after {timeout:?}"))
    }
}

impl fmt::Display for TokioDnsResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TokioDnsResolverError {}

static_str_error! {
    #[doc = "Tokio DNS resolver does not support TXT lookups"]
    pub struct TokioDnsTxtUnsupportedError;
}
