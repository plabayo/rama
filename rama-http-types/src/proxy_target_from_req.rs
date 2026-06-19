use rama_core::{Layer, Service, extensions::ExtensionsRef};

use rama_net::proxy::ProxyTarget;
use rama_net::{Protocol, TransportAddressInputExt};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A layer to inject ProxyTarget in an input,
/// based on an input from which a RequestContext can be derived.
///
/// Note that the concept of RequestContext is soon to be removed,
/// which also means this layer (service) will be moved and refactored,
/// and make use of the newer concept instead. More TBA soon.
pub struct ProxyTargetFromRequestContextLayer;

impl ProxyTargetFromRequestContextLayer {
    #[inline(always)]
    /// Create a new [`ProxyTargetFromRequestContextLayer`].
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for ProxyTargetFromRequestContextLayer {
    type Service = ProxyTargetFromRequestContext<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        ProxyTargetFromRequestContext(inner)
    }
}

#[derive(Debug, Clone)]
/// A layer to inject ProxyTarget in an input,
/// based on an input from which a RequestContext can be derived.
///
/// See [`ProxyTargetFromRequestContextLayer`] for more info.
pub struct ProxyTargetFromRequestContext<S>(S);

impl<S, Input> Service<Input> for ProxyTargetFromRequestContext<S>
where
    S: Service<Input>,
    Input: ExtensionsRef + TransportAddressInputExt + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let maybe_target = input.host_with_port_or(Protocol::HTTP_DEFAULT_PORT);

        if let Some(target) = maybe_target {
            input.extensions().insert(ProxyTarget(target));
        }

        self.0.serve(input).await
    }
}
