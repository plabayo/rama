use super::DnsResolveModeService;
use crate::HeaderName;
use rama_core::Layer;

/// Layer which can extend `Dns` (see `rama_core`) overwrites with mappings.
///
/// See [the module level documentation](crate::layer::dns) for more information.
#[derive(Debug, Clone)]
pub struct DnsResolveModeLayer {
    header_name: HeaderName,
}

impl DnsResolveModeLayer {
    /// Creates a new [`DnsResolveModeLayer`].
    pub const fn new(name: HeaderName) -> Self {
        Self { header_name: name }
    }
}

impl<S> Layer<S> for DnsResolveModeLayer {
    type Service = DnsResolveModeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsResolveModeService::new(inner, self.header_name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Request, layer::dns::DnsResolveMode};
    use rama_core::{Context, Service, service::service_fn};
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_dns_resolve_mode_layer() {
        let svc = DnsResolveModeLayer::new(HeaderName::from_static("x-dns-resolve")).layer(
            service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                assert_eq!(
                    ctx.get::<DnsResolveMode>().unwrap(),
                    &DnsResolveMode::eager()
                );
                Ok::<_, Infallible>(())
            }),
        );

        let ctx = Context::default();
        let req = Request::builder()
            .header("x-dns-resolve", "eager")
            .uri("http://example.com")
            .body(())
            .unwrap();

        svc.serve(ctx, req).await.unwrap();
    }
}
