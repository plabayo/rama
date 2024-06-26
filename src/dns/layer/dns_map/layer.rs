use super::DnsMapService;
use crate::{http::HeaderName, service::Layer};

/// Layer which can extend [`Dns`] overwrites with mappings.
///
/// See [the module level documentation](crate::dns::layer) for more information.
///
/// [`Dns`]: crate::dns::Dns
#[derive(Debug, Clone)]
pub struct DnsMapLayer {
    header_name: HeaderName,
}

impl DnsMapLayer {
    /// Creates a new [`DnsMapLayer`].
    pub fn new(name: HeaderName) -> Self {
        Self { header_name: name }
    }
}

impl<S> Layer<S> for DnsMapLayer {
    type Service = DnsMapService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsMapService::new(inner, self.header_name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        http::{get_request_context, Request},
        net::address::Host,
        service::{Context, Service, ServiceBuilder},
    };
    use std::{
        convert::Infallible,
        net::{IpAddr, Ipv4Addr},
    };

    #[tokio::test]
    async fn test_dns_map_layer() {
        let svc = ServiceBuilder::new()
            .layer(DnsMapLayer::new(HeaderName::from_static("x-dns-map")))
            .service_fn(|mut ctx: Context<()>, req: Request<()>| async move {
                let req_ctx = get_request_context!(ctx, req);
                let domain = match req_ctx.authority.as_ref().unwrap().host() {
                    Host::Name(domain) => domain,
                    Host::Address(ip) => panic!("unexpected host: {ip}"),
                };

                let addresses: Vec<_> = ctx
                    .dns()
                    .ipv4_lookup(domain.clone())
                    .await
                    .unwrap()
                    .collect();
                assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);

                let addresses: Vec<_> = ctx
                    .dns()
                    .ipv6_lookup(domain.clone())
                    .await
                    .unwrap()
                    .collect();
                assert!(addresses.is_empty());

                Ok::<_, Infallible>(())
            });

        let ctx = Context::default();
        let req = Request::builder()
            .header("x-dns-map", "example.com=127.0.0.1")
            .uri("http://example.com")
            .body(())
            .unwrap();

        svc.serve(ctx, req).await.unwrap();
    }
}
