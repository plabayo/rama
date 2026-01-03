use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use rama_core::{Service, error::OpaqueError, service::BoxService};

#[derive(Clone, Debug)]
/// Any layer can inject one or multiple [`HealthCheck`]s which can then be used by other layers
///
/// This is mostly useful for connectors/connections so they can be tested before actual usage.
/// The main use case for this is connection pooling, there we want to test if the connection
/// is actually still healthy before using or storing it.
pub struct HealthCheck(HealthCheckInner);

// TODO instead of hacky interior mutability we should reform extensions so we can just this enum
// without any atomics

#[derive(Clone, Debug)]
enum HealthCheckInner {
    IsHealty(Arc<AtomicBool>),
    IsBroken(Arc<AtomicBool>),
    Service(BoxService<IsHealthy, (), OpaqueError>),
}

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub enum HealthStatus {
    Unknown = 0,
    Broken = 1,
    Healthy = 2,
}

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct IsHealthy;

impl HealthCheck {
    /// Create a new [`HealthCheck`] using the provided service.
    pub fn new<S>(health_check_svc: S) -> Self
    where
        S: Service<IsHealthy, Output = (), Error = OpaqueError>,
    {
        Self(HealthCheckInner::Service(health_check_svc.boxed()))
    }

    /// Create a new [`HealthCheck`] that looks at the value of the provided Atomicbool
    /// to decide if the connection is healthy.
    pub fn new_atomic_is_healthy(is_healthy: Arc<AtomicBool>) -> Self {
        Self(HealthCheckInner::IsHealty(is_healthy))
    }

    /// Create a new [`HealthCheck`] that looks at the value of the provided Atomicbool
    /// to decide if the connection is broken.
    pub fn new_atomic_is_broken(is_broken: Arc<AtomicBool>) -> Self {
        Self(HealthCheckInner::IsBroken(is_broken))
    }

    /// Execute this [`HealthCheck`]
    pub async fn run_health_check(&self) -> Result<(), OpaqueError> {
        match &self.0 {
            HealthCheckInner::IsHealty(atomic_bool) => {
                if atomic_bool.load(Ordering::Relaxed) {
                    Ok(())
                } else {
                    Err(OpaqueError::from_display("marked as not healthy"))
                }
            }
            HealthCheckInner::IsBroken(atomic_bool) => {
                if atomic_bool.load(Ordering::Relaxed) {
                    Err(OpaqueError::from_display("marked as broken"))
                } else {
                    Ok(())
                }
            }
            HealthCheckInner::Service(svc) => svc.serve(IsHealthy).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use rama_core::{error::OpaqueError, service::service_fn};
    use tokio_test::{assert_err, assert_ok};

    #[tokio::test]
    async fn svc_health_check_should_work() {
        let check = HealthCheck::new(service_fn(async |_| Ok(())));
        assert_ok!(check.run_health_check().await);

        let check = HealthCheck::new(service_fn(async |_| {
            Err(OpaqueError::from_display("broken"))
        }));
        assert_err!(check.run_health_check().await);
    }

    #[tokio::test]
    async fn is_healthy_check_should_work() {
        let is_health = Arc::new(AtomicBool::new(true));

        let check = HealthCheck::new_atomic_is_healthy(is_health.clone());
        assert_ok!(check.run_health_check().await);

        is_health.store(false, Ordering::Release);
        assert_err!(check.run_health_check().await);
    }

    #[tokio::test]
    async fn is_broken_check_should_work() {
        let is_broken = Arc::new(AtomicBool::new(false));

        let check = HealthCheck::new_atomic_is_broken(is_broken.clone());
        assert_ok!(check.run_health_check().await);

        is_broken.store(true, Ordering::Release);
        assert_err!(check.run_health_check().await);
    }
}
