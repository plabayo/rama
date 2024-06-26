use super::DnsResolveModeService;
use crate::{http::HeaderName, service::Layer};

/// Layer which can extend [`Dns`] overwrites with mappings.
///
/// See [the module level documentation](crate::dns::layer) for more information.
///
/// [`Dns`]: crate::dns::Dns
#[derive(Debug, Clone)]
pub struct DnsResolveModeLayer {
    header_name: HeaderName,
}

impl DnsResolveModeLayer {
    /// Creates a new [`DnsResolveModeLayer`].
    pub fn new(name: HeaderName) -> Self {
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
    use crate::{
        dns::layer::DnsResolveMode,
        http::Request,
        service::{Context, Service, ServiceBuilder},
    };
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_dns_resolve_mode_layer() {
        let svc = ServiceBuilder::new()
            .layer(DnsResolveModeLayer::new(HeaderName::from_static(
                "x-dns-resolve",
            )))
            .service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                assert_eq!(
                    ctx.get::<DnsResolveMode>().unwrap(),
                    &DnsResolveMode::eager()
                );
                Ok::<_, Infallible>(())
            });

        let ctx = Context::default();
        let req = Request::builder()
            .header("x-dns-resolve", "eager")
            .uri("http://example.com")
            .body(())
            .unwrap();

        svc.serve(ctx, req).await.unwrap();
    }
}
