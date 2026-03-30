use std::fmt;

use rama_core::{Layer, Service, extensions::ExtensionsMut, telemetry::tracing};

use crate::{http::RequestContext, proxy::ProxyTarget};

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
    Input: ExtensionsMut + Send + 'static,
    RequestContext: for<'a> TryFrom<&'a Input, Error: fmt::Debug>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let maybe_target = match RequestContext::try_from(&input) {
            Ok(req_ctx) => Some(req_ctx.host_with_port()),
            Err(err) => {
                tracing::debug!("failed to create RequestContext from input: {err:?}");
                None
            }
        };

        if let Some(target) = maybe_target {
            input.extensions_mut().insert(ProxyTarget(target));
        }

        self.0.serve(input).await
    }
}
