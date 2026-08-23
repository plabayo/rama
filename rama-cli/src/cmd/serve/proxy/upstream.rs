use rama::{
    Layer, Service,
    error::BoxError,
    http::Request,
    http::layer::{
        follow_redirect::{FollowRedirectLayer, policy::Limited},
        uri::{DataUriLayer, FileUriLayer},
    },
    js::pac::{FetchPacScript, PacResolver, PacScriptCacheLayer, SystemPacProxy},
    layer::{IntoErrLayer, TimeoutLayer},
    net::{
        address::ProxyAddress,
        client::{
            BypassRules, ConnectRequest, ProxyAddressLayer, ProxyBypassLayer, ProxyRoutesLayer,
            SystemProxyLayer, SystemProxyPacService,
        },
    },
};
use std::time::Duration;

const SYSTEM_PAC_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Upstream route configuration shared by HTTP and connector stacks.
#[derive(Debug, Clone)]
pub(super) struct UpstreamProxyConfig {
    explicit: Option<ProxyAddress>,
    system: bool,
    bypass: ProxyBypassLayer,
}

impl UpstreamProxyConfig {
    pub(super) fn new(
        explicit: Option<ProxyAddress>,
        system: bool,
        bypass: &[String],
    ) -> Result<Self, BoxError> {
        Ok(Self {
            explicit,
            system,
            bypass: ProxyBypassLayer::new(BypassRules::from_no_proxy(bypass.join(","))?),
        })
    }

    pub(super) fn http_service<S>(
        &self,
        inner: S,
    ) -> impl Service<Request, Output = S::Output, Error = BoxError> + Clone + use<S>
    where
        S: Service<Request> + Clone,
        S::Error: Into<BoxError>,
    {
        (
            self.bypass.clone(),
            ProxyAddressLayer::maybe(self.explicit.clone()),
            self.system.then(system_proxy_layer),
            ProxyRoutesLayer::new(),
            IntoErrLayer::into_box_error(),
        )
            .into_layer(inner)
    }

    pub(super) fn connector_service<S>(
        &self,
        inner: S,
    ) -> impl Service<ConnectRequest, Output = S::Output, Error = BoxError> + Clone + use<S>
    where
        S: Service<ConnectRequest> + Clone,
        S::Error: Into<BoxError>,
    {
        (
            self.bypass.clone(),
            ProxyAddressLayer::maybe(self.explicit.clone()),
            self.system
                .then(|| system_proxy_layer().into_connect_layer()),
            ProxyRoutesLayer::new(),
            IntoErrLayer::into_box_error(),
        )
            .into_layer(inner)
    }
}

fn system_proxy_layer() -> SystemProxyLayer<impl SystemProxyPacService + Clone> {
    // PAC fetches are bounded and deliberately direct: consulting the
    // unresolved system proxy while fetching its own policy can recurse.
    let pac_fetch_client = (
        TimeoutLayer::new(SYSTEM_PAC_FETCH_TIMEOUT),
        FileUriLayer::new(),
        DataUriLayer::new(),
        FollowRedirectLayer::with_policy(Limited::new(10)),
    )
        .into_layer(rama::http::client::EasyHttpWebClient::default());
    let pac_provider = PacScriptCacheLayer::new().into_layer(FetchPacScript::new(pac_fetch_client));
    let pac_resolver = std::env::home_dir().map_or_else(PacResolver::builder, |home| {
        PacResolver::builder().with_javascript_disk_cache(home, crate::cmd::pac::JS_CACHE_DIR)
    });
    let pac = SystemPacProxy::new(pac_provider).with_resolver_builder(pac_resolver);
    SystemProxyLayer::new().with_pac_service(pac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        extensions::ExtensionsRef,
        http::Body,
        net::client::{ConnectRequest, ProxyRoute},
        service::service_fn,
    };

    fn route_service<Input>()
    -> impl Service<Input, Output = Option<ProxyRoute>, Error = BoxError> + Clone
    where
        Input: ExtensionsRef + Send + 'static,
    {
        service_fn(|input: Input| async move {
            Ok::<_, BoxError>(input.extensions().get_ref::<ProxyRoute>().cloned())
        })
    }

    #[tokio::test]
    async fn explicit_proxy_and_bypass_apply_to_http_requests() {
        let proxy: ProxyAddress = "http://127.0.0.1:3128".parse().unwrap();
        let config =
            UpstreamProxyConfig::new(Some(proxy.clone()), false, &["example.test".to_owned()])
                .unwrap();
        let service = config.http_service(route_service::<Request>());

        let proxied = service
            .serve(
                Request::builder()
                    .uri("http://other.test/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(proxied, Some(ProxyRoute::Proxy(proxy)));

        let bypassed = service
            .serve(
                Request::builder()
                    .uri("https://api.example.test/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bypassed, Some(ProxyRoute::Direct));
    }

    #[tokio::test]
    async fn explicit_proxy_applies_to_raw_connect_requests() {
        let proxy: ProxyAddress = "socks5h://127.0.0.1:1080".parse().unwrap();
        let service = UpstreamProxyConfig::new(Some(proxy.clone()), false, &[])
            .unwrap()
            .connector_service(route_service::<ConnectRequest>());
        let input = ConnectRequest::new("origin.example:443".parse().unwrap())
            .with_application_protocol(rama::net::Protocol::HTTPS);

        assert_eq!(
            service.serve(input).await.unwrap(),
            Some(ProxyRoute::Proxy(proxy))
        );
    }

    #[tokio::test]
    async fn existing_route_is_preserved_and_explicit_proxy_is_authoritative() {
        let proxy: ProxyAddress = "http://127.0.0.1:3128".parse().unwrap();
        let service = UpstreamProxyConfig::new(Some(proxy.clone()), false, &[])
            .unwrap()
            .http_service(route_service::<Request>());

        let routed = Request::builder()
            .uri("http://origin.test/")
            .extension(ProxyRoute::Direct)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            service.serve(routed).await.unwrap(),
            Some(ProxyRoute::Direct)
        );

        let relative = Request::builder()
            .uri("/relative")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            service.serve(relative).await.unwrap(),
            Some(ProxyRoute::Proxy(proxy))
        );
    }
}
