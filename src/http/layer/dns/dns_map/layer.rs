use super::DnsMapService;
use crate::{http::HeaderName, Layer};

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
    pub const fn new(name: HeaderName) -> Self {
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
        http::{Request, RequestContext},
        net::address::Host,
        service::service_fn,
        Context, Service,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_dns_map_layer() {
        let svc = DnsMapLayer::new(HeaderName::from_static("x-dns-map")).layer(service_fn(
            |mut ctx: Context<()>, req: Request<()>| async move {
                match ctx
                    .get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into())
                    .map(|req_ctx| req_ctx.authority.host().clone())
                {
                    Ok(host) => {
                        let domain = match host {
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

                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            },
        ));

        let ctx = Context::default();
        let req = Request::builder()
            .header("x-dns-map", "example.com=127.0.0.1")
            .uri("http://example.com")
            .body(())
            .unwrap();

        svc.serve(ctx, req).await.unwrap();
    }
}
