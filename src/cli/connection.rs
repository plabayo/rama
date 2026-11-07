//! The scope every connection a CLI service serves runs in.

use crate::{graceful::WeakScope, layer::ScopeLayer};
use std::time::Duration;

/// How long a connection may still run once it drains, unless configured otherwise.
pub const DEFAULT_CONNECTION_GRACE: Duration = Duration::from_secs(5);

/// The share either way by which a connection's max age is spread.
const MAX_AGE_JITTER: f64 = 0.1;

/// Runs each served connection in a scope below `parent` that starts draining once it is
/// `max_age` old, give or take a tenth so connections opened together do not drain together,
/// and is aborted at most `grace` after it starts draining for any reason, sooner when
/// `parent` reaches its own hard phase first; zero `max_age` sets no age.
#[must_use]
pub fn connection_scope(parent: &WeakScope, max_age: Duration, grace: Duration) -> ScopeLayer {
    ScopeLayer::new()
        .with_parent(parent.clone())
        .maybe_with_max_age((!max_age.is_zero()).then_some(max_age))
        .with_max_age_jitter(MAX_AGE_JITTER)
        .with_grace(grace)
}
