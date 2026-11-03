use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
};

use crate::{
    address::{Domain, HostWithPort},
    client::ConnectionError,
    transport::TransportProtocol,
};

use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorExt as _, ErrorList},
    extensions::Extensions,
    futures::{
        Stream, StreamExt as _,
        stream::{BoxStream, FuturesUnordered},
    },
    telemetry::tracing,
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
/// connect), every failure is returned in an [`ErrorList`], each dial failure
/// with its address as context. The last failure is the primary one, so the
/// error classifies as before: when that failure is classified (it carries a
/// [`ConnectionError`] or a timeout), the returned error is a [`ConnectionError`]
/// with that classification. A single unclassified failure is returned as itself.
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
    let mut failures = Failures::default();

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
                tracing::trace!(%addr, "race connect: dial candidate");
                in_flight.push(async move { (addr, dial(addr).await) });
            }
            Event::Candidate(Some(Err(err))) => {
                tracing::debug!(error = %err, "race connect: candidate failed");
                failures.push(None, err);
            }
            Event::Candidate(None) => {
                tracing::trace!(in_flight = in_flight.len(), "race connect: candidates done");
                candidates_done = true;
            }
            Event::Dialed(Some((addr, Ok(conn)))) => {
                tracing::trace!(%addr, "race connect: connected");
                return Ok((addr, conn));
            }
            Event::Dialed(Some((addr, Err(err)))) => {
                tracing::debug!(%addr, error = %err, "race connect: dial failed");
                failures.push(Some(addr), err);
            }
            Event::Dialed(None) => {}
        }
    }

    Err(failures.into_error())
}

/// Failures of a race, kept as they arrive and only wrapped once every
/// candidate failed, so a race that still succeeds pays for no more than storing them.
#[derive(Default)]
struct Failures {
    first: Option<(Option<SocketAddr>, BoxError)>,
    rest: Vec<(Option<SocketAddr>, BoxError)>,
}

impl Failures {
    fn push(&mut self, address: Option<SocketAddr>, error: BoxError) {
        if self.first.is_none() {
            self.first = Some((address, error));
        } else {
            self.rest.push((address, error));
        }
    }

    fn into_error(self) -> BoxError {
        let Self { first, rest } = self;
        let Some(first) = first else {
            return BoxError::from_static_str("race_connect: no connection candidates");
        };
        // Diagnostics deepen the chain: take the primary failure's classification
        // first, so a bounded walk finds what it found without them.
        let primary = rest.last().unwrap_or(&first);
        let classification = ConnectionError::classification_in_source_chain(primary.1.as_ref());
        let error = diagnostics(first, rest);
        match classification {
            Some(classification) => {
                Box::new(ConnectionError::with_classification(error, classification))
            }
            None => error,
        }
    }
}

fn with_address((address, error): (Option<SocketAddr>, BoxError)) -> BoxError {
    match address {
        Some(address) => error.context_field("address", address),
        None => error,
    }
}

/// Every failure, each dial failure with its address; the last one primary.
fn diagnostics(
    first: (Option<SocketAddr>, BoxError),
    rest: Vec<(Option<SocketAddr>, BoxError)>,
) -> BoxError {
    if rest.is_empty() {
        return with_address(first);
    }
    let mut errors = ErrorList::with_capacity(1 + rest.len());
    errors.push(with_address(first));
    let last = rest.len() - 1;
    for (idx, failure) in rest.into_iter().enumerate() {
        if idx == last {
            errors.push_primary(with_address(failure));
        } else {
            errors.push(with_address(failure));
        }
    }
    Box::new(errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ConnectionErrorKind;
    use std::time::Duration;

    use rama_core::{error::CauseExt as _, futures::stream};

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

    #[derive(Debug)]
    struct Refused(u16);

    impl core::fmt::Display for Refused {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "refused {}", self.0)
        }
    }

    impl core::error::Error for Refused {}

    #[tokio::test]
    async fn race_connect_all_failures_keeps_every_failure_last_primary() {
        let candidates = stream::iter(
            [
                Ok(addr(1)),
                Err(BoxError::from_static_str("resolve failed")),
                Ok(addr(2)),
            ]
            .into_iter(),
        );
        // One at a time, so the failure order is the candidate order.
        let error = race_connect(candidates, 1, |a: SocketAddr| async move {
            Err::<u16, BoxError>(Refused(a.port()).into())
        })
        .await
        .unwrap_err();

        let list = error.downcast_ref::<ErrorList>().expect("several failures");
        let failures: Vec<_> = list.iter().map(ToString::to_string).collect();
        assert_eq!(
            failures,
            [
                r#"refused 1 | address="127.0.0.1:1""#,
                "resolve failed",
                r#"refused 2 | address="127.0.0.1:2""#,
            ]
        );
        assert_eq!(
            error.root_cause().downcast_ref::<Refused>().map(|e| e.0),
            Some(2),
            "the last failure is primary"
        );
    }

    #[tokio::test]
    async fn race_connect_failures_classify_by_the_last_failure() {
        let candidates = stream::iter([addr(1), addr(2)].map(Ok::<_, BoxError>));
        let error = race_connect(candidates, 1, |a: SocketAddr| async move {
            let kind = if a.port() == 1 {
                ConnectionErrorKind::Authentication
            } else {
                ConnectionErrorKind::Timeout
            };
            Err::<u16, BoxError>(ConnectionError::transport(Refused(a.port()), kind).into())
        })
        .await
        .unwrap_err();
        assert!(error.has_cause::<ErrorList>());
        assert_eq!(
            ConnectionError::from(error).kind(),
            ConnectionErrorKind::Timeout,
            "the primary path is the last failure, as when only that one was returned"
        );
    }

    #[derive(Debug)]
    struct Layer(BoxError);

    impl core::fmt::Display for Layer {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("layer")
        }
    }

    impl core::error::Error for Layer {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    /// A timeout under `layers` wrappers: at 63 the walk's 64th error is the timeout.
    fn deep_timeout(port: u16, layers: usize) -> BoxError {
        let mut error: BoxError =
            ConnectionError::transport(Refused(port), ConnectionErrorKind::Timeout).into();
        for _ in 0..layers {
            error = Box::new(Layer(error));
        }
        error
    }

    #[tokio::test]
    async fn race_connect_classification_survives_diagnostics_at_the_walk_bound() {
        assert_eq!(
            ConnectionError::from(deep_timeout(1, 63)).kind(),
            ConnectionErrorKind::Timeout,
            "the bound this test sits on"
        );
        for count in [1, 2] {
            let candidates = stream::iter((1..=count).map(|port| Ok::<_, BoxError>(addr(port))));
            let error = race_connect(candidates, 1, |a: SocketAddr| async move {
                Err::<u16, BoxError>(deep_timeout(a.port(), 63))
            })
            .await
            .unwrap_err();
            assert_eq!(
                ConnectionError::from(error).kind(),
                ConnectionErrorKind::Timeout,
                "{count} failures"
            );
        }
    }

    #[tokio::test]
    async fn race_connect_timeout_classification_survives_diagnostics_at_the_walk_bound() {
        async fn deep_elapsed(layers: usize) -> BoxError {
            let elapsed = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
                .await
                .unwrap_err();
            let mut error: BoxError = elapsed.into();
            for _ in 0..layers {
                error = Box::new(Layer(error));
            }
            error
        }
        assert_eq!(
            ConnectionError::from(deep_elapsed(63).await).kind(),
            ConnectionErrorKind::Timeout
        );
        for count in [1, 2] {
            let candidates = stream::iter((1..=count).map(|port| Ok::<_, BoxError>(addr(port))));
            let error = race_connect(candidates, 1, |_a: SocketAddr| async move {
                Err::<u16, BoxError>(deep_elapsed(63).await)
            })
            .await
            .unwrap_err();
            assert_eq!(
                ConnectionError::from(error).kind(),
                ConnectionErrorKind::Timeout,
                "{count} failures"
            );
        }
    }

    #[tokio::test]
    async fn race_connect_single_failure_is_returned_as_itself() {
        let candidates = stream::iter([Ok::<_, BoxError>(addr(1))]);
        let error = race_connect(candidates, 3, |a: SocketAddr| async move {
            Err::<u16, BoxError>(Refused(a.port()).into())
        })
        .await
        .unwrap_err();
        assert!(!error.has_cause::<ErrorList>());
        assert!(error.has_cause::<Refused>());
    }

    #[tokio::test]
    async fn race_connect_without_candidates_says_so() {
        let error = race_connect(stream::empty(), 3, |_a: SocketAddr| async move {
            Ok::<u16, BoxError>(0)
        })
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "race_connect: no connection candidates");
    }
}
