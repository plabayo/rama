use rama::{
    Layer, Service,
    dns::client::resolver::DnsAddresssResolverOverwrite,
    net::{ConnectorTargetInputExt, address::DomainTrie},
};

use crate::cmd::send::arg::ResolveArg;

#[derive(Debug, Clone)]
pub(in crate::cmd::send) struct OptDnsOverwriteLayer(Option<ResolveArg>);

impl OptDnsOverwriteLayer {
    pub(in crate::cmd::send) fn new(arg: Option<ResolveArg>) -> Self {
        Self(arg)
    }
}

impl<S> Layer<S> for OptDnsOverwriteLayer {
    type Service = OptDnsOverwriteService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OptDnsOverwriteService {
            inner,
            info: self.0.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        OptDnsOverwriteService {
            inner,
            info: self.0,
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::send) struct OptDnsOverwriteService<S> {
    inner: S,
    info: Option<ResolveArg>,
}

impl<Input, S> Service<Input> for OptDnsOverwriteService<S>
where
    Input: ConnectorTargetInputExt + Send + 'static,
    S: Service<Input>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let Some(ref info) = self.info else {
            return self.inner.serve(input).await;
        };

        if info.port.is_none()
            || input
                .connector_target()
                .map(|hwp| info.port == Some(hwp.port))
                .unwrap_or_default()
        {
            let addresses = info.addresses.clone();
            let overwrite = match info.host.clone() {
                Some(domain) => {
                    let mut trie = DomainTrie::new();
                    trie.insert_domain(domain, addresses);
                    DnsAddresssResolverOverwrite::new(trie)
                }
                None => DnsAddresssResolverOverwrite::new(addresses),
            };
            input.extensions().insert(overwrite);
        }

        self.inner.serve(input).await
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, str::FromStr as _, sync::Arc};

    use parking_lot::Mutex;

    use rama::{
        extensions::ExtensionsRef,
        http::{
            Body, Request, Response, StatusCode,
            header::LOCATION,
            layer::follow_redirect::{FollowRedirectLayer, policy::Action},
        },
        service::service_fn,
    };

    use super::*;

    /// Regression: `--resolve` is matched on host:port, so an overwrite for hop 1's target must not
    /// carry over to a hop that goes somewhere else. This pins the per-hop semantics; that the send
    /// client actually wires this layer inside `FollowRedirect` is covered by
    /// `send_client_stack_orders_layers_around_follow_redirect`.
    #[tokio::test]
    async fn resolve_overwrite_is_evaluated_per_redirect_hop() {
        let hops = Arc::new(Mutex::new(Vec::new()));
        let svc = (
            FollowRedirectLayer::with_policy(Action::Follow),
            OptDnsOverwriteLayer::new(Some(ResolveArg::from_str("*:8080:1.2.3.4").unwrap())),
        )
            .into_layer(service_fn({
                let hops = hops.clone();
                move |req: Request| {
                    hops.lock().push((
                        req.uri().to_string(),
                        req.extensions().contains::<DnsAddresssResolverOverwrite>(),
                    ));
                    let mut res = Response::builder();
                    if req.uri().port_u16() == Some(8080) {
                        res = res
                            .status(StatusCode::MOVED_PERMANENTLY)
                            .header(LOCATION, "http://b.example:9090/");
                    }
                    async move { Ok::<_, Infallible>(res.body(Body::empty()).unwrap()) }
                }
            }));

        let req = Request::builder()
            .uri("http://a.example:8080/")
            .body(Body::empty())
            .unwrap();
        svc.serve(req).await.unwrap();

        assert_eq!(
            hops.lock().as_slice(),
            [
                ("http://a.example:8080/".to_owned(), true),
                ("http://b.example:9090/".to_owned(), false),
            ],
        );
    }
}
