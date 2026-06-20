use rama_core::{Layer, Service, extensions::ExtensionsRef};

use super::ProxyTarget;
use crate::{Protocol, TransportAddressInputExt};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A [`Layer`] that injects a [`ProxyTarget`] into the input, resolved from the
/// input's routing authority (see [`AuthorityInputExt`](crate::AuthorityInputExt)).
pub struct ProxyTargetFromAuthorityLayer;

impl ProxyTargetFromAuthorityLayer {
    #[inline(always)]
    /// Create a new [`ProxyTargetFromAuthorityLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for ProxyTargetFromAuthorityLayer {
    type Service = ProxyTargetFromAuthority<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        ProxyTargetFromAuthority(inner)
    }
}

#[derive(Debug, Clone)]
/// A [`Service`] that injects a [`ProxyTarget`] into the input, resolved from the
/// input's routing authority (the authority's port, else the protocol default,
/// else the HTTP default port).
///
/// See [`ProxyTargetFromAuthorityLayer`] for more info.
pub struct ProxyTargetFromAuthority<S>(S);

impl<S, Input> Service<Input> for ProxyTargetFromAuthority<S>
where
    S: Service<Input>,
    Input: ExtensionsRef + TransportAddressInputExt + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(target) = input.host_with_port_or(Protocol::HTTP_DEFAULT_PORT) {
            input.extensions().insert(ProxyTarget(target));
        }

        self.0.serve(input).await
    }
}
