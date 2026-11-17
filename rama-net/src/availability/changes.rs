use std::{future::Future, time::Duration};

use rama_core::error::{BoxError, BoxErrorExt as _};
use tokio::sync::{Semaphore, watch};

use super::{NetworkAvailability, NetworkState};

/// A bounded, coalescing source of trusted network observations.
///
/// Publish platform or routing-policy observations here, never unauthenticated packet
/// claims. Readers receive the latest [`NetworkState`], not a growing event queue.
/// Clones share the source.
#[derive(Debug, Clone)]
pub struct NetworkChanges(watch::Sender<NetworkState>);

impl Default for NetworkChanges {
    fn default() -> Self {
        Self(watch::channel(NetworkState::default()).0)
    }
}

impl NetworkChanges {
    /// Create a source in the [`NetworkAvailability::Unknown`] state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish an externally managed routing revision, ignoring identical observations.
    ///
    /// Use this or [`Self::advance`]; do not mix revision owners.
    pub fn update(&self, state: NetworkState) {
        self.0.send_if_modified(|current| {
            if *current == state {
                return false;
            }
            *current = state;
            true
        });
    }

    /// Publish `availability` under a new, locally managed revision.
    pub fn advance(&self, availability: NetworkAvailability) {
        self.0.send_modify(|state| {
            state.revision = state.revision.wrapping_add(1);
            state.availability = availability;
        });
    }

    /// The latest published observation.
    #[must_use]
    pub fn state(&self) -> NetworkState {
        *self.0.borrow()
    }

    /// Subscribe to observations published after this call.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<NetworkState> {
        self.0.subscribe()
    }
}

/// Prepare work in response to a network change within a bounded time.
///
/// The optional `gate` bounds concurrent preparations; waiting for it does not consume
/// `timeout`, and `prepare` is only called once admitted. The permit is held until `finish` has consumed the prepared value, so that
/// value is applied before another preparation starts. Dropping the future cancels both.
pub async fn prepare_network_change<F, T, E, R>(
    gate: Option<&Semaphore>,
    timeout: Duration,
    prepare: impl FnOnce() -> F,
    finish: impl FnOnce(T) -> Result<R, BoxError>,
) -> Result<R, BoxError>
where
    F: Future<Output = Result<T, E>>,
    E: Into<BoxError>,
{
    let _permit = match gate {
        Some(gate) => Some(gate.acquire().await.map_err(|_closed| {
            BoxError::from_static_str("network change preparation gate closed")
        })?),
        None => None,
    };
    let prepared = tokio::time::timeout(timeout, prepare())
        .await
        .map_err(|_elapsed| BoxError::from_static_str("network change preparation timed out"))?
        .map_err(Into::into)?;
    finish(prepared)
}
