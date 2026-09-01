use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
};

use crate::{
    address::{Domain, HostWithPort},
    transport::TransportProtocol,
};

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extensions,
    futures::{
        Stream, StreamExt as _,
        stream::{BoxStream, FuturesUnordered},
    },
};
use rama_macros::Extension;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Extension)]
#[extension(tags(net))]
/// Target [`HostWithPort`] which if found in extensions
/// is to be used by a connector such as a TCPConnector instead
/// of the requested address, unless a proxy is requested in
/// which case a proxy is to be used instead.
pub struct ConnectorTarget(pub HostWithPort);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(net))]
/// Transport protocol a connector must use for the selected route.
///
/// Routing middleware can use this alongside [`ConnectorTarget`] when the
/// physical route's transport differs from the requested destination.
pub struct ConnectorTransportProtocol(pub TransportProtocol);

/// A lazily-resolved source of connection target [`IpAddr`]esses.
///
/// This is the abstraction boundary between resolving a target and
/// connecting to it. An upstream connector (e.g. the `rama-dns` address
/// resolver) stamps a [`ConnectorTargetStream`] into the [`Extensions`], and a
/// transport connector consumes it: dialing (and optionally racing) the
/// yielded addresses. The transport stays resolver-agnostic: it only ever sees
/// a stream of [`IpAddr`]s, never a DNS resolver. It combines each address with
/// the current connector target's port immediately before dialing.
pub trait AddressCandidates: Send + Sync + 'static {
    /// Return the domain these candidates resolve.
    ///
    /// Transport connectors use this correlation to avoid consuming stale
    /// candidates after routing middleware selects a different domain.
    fn domain(&self) -> &Domain;

    /// Stream the candidate [`IpAddr`]esses, in the order they should be
    /// attempted. The given [`Extensions`] carry per-request resolve config.
    fn stream<'a>(&'a self, extensions: &'a Extensions) -> BoxStream<'a, Result<IpAddr, BoxError>>;
}

#[derive(Extension)]
#[extension(tags(net))]
/// [`Extensions`] carrier for an [`AddressCandidates`] source.
pub struct ConnectorTargetStream(pub Box<dyn AddressCandidates>);

impl ConnectorTargetStream {
    /// Wrap an [`AddressCandidates`] implementor.
    #[must_use]
    pub fn new(candidates: impl AddressCandidates) -> Self {
        Self(Box::new(candidates))
    }

    /// Return the domain these candidates resolve.
    #[must_use]
    pub fn domain(&self) -> &Domain {
        self.0.domain()
    }

    /// Stream the candidate addresses (see [`AddressCandidates::stream`]).
    pub fn stream<'a>(
        &'a self,
        extensions: &'a Extensions,
    ) -> BoxStream<'a, Result<IpAddr, BoxError>> {
        self.0.stream(extensions)
    }
}

impl core::fmt::Debug for ConnectorTargetStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnectorTargetStream")
            .field("domain", &self.domain())
            .finish_non_exhaustive()
    }
}

/// Race connection attempts over a stream of candidate [`SocketAddr`]esses.
///
/// Pulls candidates from `candidates` in order (e.g. happy-eyeballs order from a
/// [`ConnectorTargetStream`]), keeps up to `max_in_flight` dials racing
/// concurrently via `dial`, and returns the first successful connection together
/// with the address it connected to. If every candidate fails (to resolve or to
/// connect), the last error is returned.
pub async fn race_connect<S, C, F, Fut>(
    candidates: S,
    max_in_flight: usize,
    dial: F,
) -> Result<(SocketAddr, C), BoxError>
where
    S: Stream<Item = Result<SocketAddr, BoxError>>,
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: Future<Output = Result<C, BoxError>> + Send,
    C: Send,
{
    let max_in_flight = max_in_flight.max(1);

    let dial = &dial;
    let mut candidates = std::pin::pin!(candidates);
    let mut in_flight = FuturesUnordered::new();
    let mut candidates_done = false;
    let mut last_err: Option<BoxError> = None;

    enum Event<C> {
        Candidate(Option<Result<SocketAddr, BoxError>>),
        Dialed(Option<(SocketAddr, Result<C, BoxError>)>),
    }

    loop {
        if candidates_done && in_flight.is_empty() {
            break;
        }

        let event = if !candidates_done && in_flight.len() < max_in_flight {
            if in_flight.is_empty() {
                Event::Candidate(candidates.next().await)
            } else {
                tokio::select! {
                    candidate = candidates.next() => Event::Candidate(candidate),
                    dialed = in_flight.next() => Event::Dialed(dialed),
                }
            }
        } else {
            Event::Dialed(in_flight.next().await)
        };

        match event {
            Event::Candidate(Some(Ok(addr))) => {
                in_flight.push(async move { (addr, dial(addr).await) });
            }
            Event::Candidate(Some(Err(err))) => last_err = Some(err),
            Event::Candidate(None) => candidates_done = true,
            Event::Dialed(Some((addr, Ok(conn)))) => return Ok((addr, conn)),
            Event::Dialed(Some((_addr, Err(err)))) => last_err = Some(err),
            Event::Dialed(None) => {}
        }
    }

    Err(last_err
        .unwrap_or_else(|| BoxError::from_static_str("race_connect: no connection candidates")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use rama_core::futures::stream;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[tokio::test]
    async fn race_connect_returns_a_success_skipping_failures() {
        let candidates = stream::iter([addr(1), addr(2), addr(3)].map(Ok::<_, BoxError>));

        let (won, conn) = race_connect(candidates, 3, |a: SocketAddr| async move {
            if a.port() == 1 {
                Err(BoxError::from_static_str("refused"))
            } else {
                Ok::<_, BoxError>(a.port())
            }
        })
        .await
        .unwrap();
        assert_ne!(won.port(), 1);
        assert_eq!(conn, won.port());
    }

    #[tokio::test]
    async fn race_connect_all_failures_returns_last_error() {
        let candidates = stream::iter([addr(1), addr(2)].map(Ok::<_, BoxError>));
        let result = race_connect(candidates, 3, |_a| async move {
            Err::<u16, BoxError>(BoxError::from_static_str("always refused"))
        })
        .await;
        result.unwrap_err();
    }
}
