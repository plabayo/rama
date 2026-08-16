//! Adapt the PAC evaluator to `rama-net`'s system-proxy layer.

use std::{fmt, num::NonZeroUsize, sync::Arc};

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorExt as _, extra::OpaqueError},
    layer::MapErr,
    service::{BoxService, service_fn},
};
use rama_net::{
    client::{
        BoxSystemProxyPacResolver, ProxyRoutes, SystemProxyPacRequest,
        box_system_proxy_pac_resolver,
    },
    uri::Uri,
};
use rama_utils::macros::generate_set_and_with;
use tokio::sync::Mutex;

use crate::{
    DEFAULT_PAC_MAX_ROUTES, PacResolver, PacResolverBuilder, PacScript, PacScriptCache,
    PacScriptCacheLayer,
};

type Provider = Arc<PacScriptCache<BoxService<Uri, PacScript, OpaqueError>>>;

/// Creates cached [`PacResolver`] services for system-configured PAC URLs.
///
/// The script provider is wrapped in [`PacScriptCacheLayer`], so a system PAC
/// URL is fetched at most once per cache TTL rather than once per request. The
/// compiled resolver is also reused until the operating system reports a
/// different URL. This type implements the PAC factory contract accepted by
/// [`SystemProxyLayer`][rama_net::client::SystemProxyLayer].
#[derive(Clone)]
pub struct SystemPacProxy {
    provider: Provider,
    builder: PacResolverBuilder,
    resolver: Arc<Mutex<Option<(Uri, Arc<PacResolver>)>>>,
    max_routes: Option<NonZeroUsize>,
}

impl fmt::Debug for SystemPacProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemPacProxy")
            .field("builder", &self.builder)
            .field("max_routes", &self.max_routes)
            .finish_non_exhaustive()
    }
}

impl SystemPacProxy {
    /// Create a system PAC factory with the standard script cache policy.
    pub fn new<P>(provider: P) -> Self
    where
        P: Service<Uri, Output = PacScript>,
        P::Error: Into<BoxError> + Send + Sync + 'static,
    {
        Self::with_cache_layer(provider, PacScriptCacheLayer::new())
    }

    /// Create a system PAC factory with a custom script cache policy.
    pub fn with_cache_layer<P>(provider: P, cache: PacScriptCacheLayer) -> Self
    where
        P: Service<Uri, Output = PacScript>,
        P::Error: Into<BoxError> + Send + Sync + 'static,
    {
        let provider = MapErr::into_opaque_error(provider).boxed();
        Self {
            provider: Arc::new(cache.into_layer(provider)),
            builder: PacResolver::builder(),
            resolver: Arc::new(Mutex::new(None)),
            max_routes: Some(DEFAULT_PAC_MAX_ROUTES),
        }
    }

    generate_set_and_with! {
        /// Configure the resolver used for a newly observed PAC URL.
        pub fn resolver_builder(mut self, builder: PacResolverBuilder) -> Self {
            self.builder = builder;
            self.resolver = Arc::new(Mutex::new(None));
            self
        }
    }

    generate_set_and_with! {
        /// Limit the number of routes published per request.
        ///
        /// The default is [`DEFAULT_PAC_MAX_ROUTES`]. Set `None` only when
        /// the system PAC script is trusted with an unbounded fallback list.
        pub fn max_routes(mut self, max_routes: Option<NonZeroUsize>) -> Self {
            self.max_routes = max_routes;
            self
        }
    }
}

impl Service<Uri> for SystemPacProxy {
    type Output = BoxSystemProxyPacResolver;
    type Error = OpaqueError;

    async fn serve(&self, script_uri: Uri) -> Result<Self::Output, Self::Error> {
        let resolver = {
            let mut state = self.resolver.lock().await;
            match state.as_ref() {
                Some((cached_uri, resolver)) if *cached_uri == script_uri => resolver.clone(),
                _ => {
                    let resolver = Arc::new(
                        self.builder
                            .clone()
                            .build(self.provider.clone(), script_uri.clone())
                            .map_err(|error| error.into_opaque_error())?,
                    );
                    *state = Some((script_uri, resolver.clone()));
                    resolver
                }
            }
        };
        let max_routes = self.max_routes;
        Ok(box_system_proxy_pac_resolver(service_fn(
            move |request: SystemProxyPacRequest| {
                let resolver = resolver.clone();
                async move {
                    let mut directives = resolver
                        .find_proxy(request.uri())
                        .await
                        .map_err(|error| error.into_opaque_error())?;
                    if let Some(max_routes) = max_routes {
                        directives.truncate(max_routes.get());
                    }
                    Ok::<Option<ProxyRoutes>, OpaqueError>(Some(directives.into_proxy_routes()))
                }
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use rama_core::{extensions::Extensions, service::service_fn};
    use rama_net::client::ProxyRoute;

    use super::*;

    #[tokio::test]
    async fn reuses_the_resolver_and_script_cache() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = service_fn({
            let fetches = fetches.clone();
            move |_uri: Uri| {
                fetches.fetch_add(1, Ordering::Relaxed);
                async {
                    Ok::<_, Infallible>(PacScript::from(
                        r#"function FindProxyForURL(url, host) {
                            return host === "direct.test"
                                ? "DIRECT"
                                : "PROXY proxy.test:8080; DIRECT";
                        }"#,
                    ))
                }
            }
        });
        let factory = SystemPacProxy::new(provider);
        let script_uri: Uri = "https://config.test/proxy.pac".parse().unwrap();

        let resolver = factory.serve(script_uri.clone()).await.unwrap();
        let routes = resolver
            .serve(
                SystemProxyPacRequest::new(
                    Extensions::new(),
                    "https://proxied.test/private".parse().unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(routes.as_slice()[0], ProxyRoute::Proxy(_)));
        assert!(matches!(routes.as_slice()[1], ProxyRoute::Direct));

        let resolver = factory.serve(script_uri).await.unwrap();
        let routes = resolver
            .serve(
                SystemProxyPacRequest::new(
                    Extensions::new(),
                    "https://direct.test/".parse().unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(routes.as_slice(), [ProxyRoute::Direct]));
        assert_eq!(fetches.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn caps_routes_at_the_shared_default() {
        let directives = (0..12)
            .map(|index| format!("PROXY proxy-{index}.test:8080"))
            .collect::<Vec<_>>()
            .join("; ");
        let script = format!("function FindProxyForURL(url, host) {{ return {directives:?}; }}");
        let factory = SystemPacProxy::new(crate::StaticPacScript::new(script));
        let resolver = factory
            .serve("pac:system-test".parse().unwrap())
            .await
            .unwrap();
        let routes = resolver
            .serve(
                SystemProxyPacRequest::new(
                    Extensions::new(),
                    "http://example.test/".parse().unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(routes.as_slice().len(), DEFAULT_PAC_MAX_ROUTES.get());
    }

    #[tokio::test]
    async fn resolver_is_reused_only_for_the_same_pac_uri() {
        let factory = SystemPacProxy::new(crate::StaticPacScript::new(
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
        ));
        let first_uri: Uri = "https://config.test/one.pac".parse().unwrap();
        let second_uri: Uri = "https://config.test/two.pac".parse().unwrap();

        factory.serve(first_uri.clone()).await.unwrap();
        let first = factory.resolver.lock().await.as_ref().unwrap().1.clone();
        factory.serve(first_uri).await.unwrap();
        let reused = factory.resolver.lock().await.as_ref().unwrap().1.clone();
        assert!(Arc::ptr_eq(&first, &reused));

        factory.serve(second_uri).await.unwrap();
        let replaced = factory.resolver.lock().await.as_ref().unwrap().1.clone();
        assert!(!Arc::ptr_eq(&first, &replaced));
    }

    #[test]
    fn debug_identifies_the_factory_without_exposing_provider_state() {
        let factory = SystemPacProxy::new(crate::StaticPacScript::new(
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
        ));
        let debug = format!("{factory:?}");
        assert!(debug.starts_with("SystemPacProxy"));
        assert!(debug.contains("max_routes"));
    }
}
