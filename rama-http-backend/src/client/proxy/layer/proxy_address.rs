use rama_core::{
    Context, Layer, Service,
    error::{ErrorContext, OpaqueError},
};
use rama_net::address::ProxyAddress;
use std::{fmt, future::Future};

#[derive(Debug, Clone, Default)]
/// A [`Layer`] which allows you to add a [`ProxyAddress`]
/// to the [`Context`] in order to have your client connector
/// make a connection via this proxy (e.g. by using [`HttpProxyConnectorLayer`]).
///
/// See [`HttpProxyAddressService`] for more information.
///
/// [`Context`]: rama_core::Context
/// [`HttpProxyConnectorLayer`]: crate::client::proxy::layer::HttpProxyConnectorLayer
pub struct HttpProxyAddressLayer {
    address: Option<ProxyAddress>,
    preserve: bool,
}

impl HttpProxyAddressLayer {
    /// Create a new [`HttpProxyAddressLayer`] that will create
    /// a service to set the given [`ProxyAddress`].
    pub fn new(address: ProxyAddress) -> Self {
        Self::maybe(Some(address))
    }

    /// Create a new [`HttpProxyAddressLayer`] which will create
    /// a service that will set the given [`ProxyAddress`] if it is not
    /// `None`.
    pub fn maybe(address: Option<ProxyAddress>) -> Self {
        Self {
            address,
            ..Default::default()
        }
    }

    /// Try to create a new [`HttpProxyAddressLayer`] which will establish
    /// a proxy connection over the environment variable `HTTP_PROXY`.
    pub fn try_from_env_default() -> Result<Self, OpaqueError> {
        Self::try_from_env("HTTP_PROXY")
    }

    /// Try to create a new [`HttpProxyAddressLayer`] which will establish
    /// a proxy connection over the given environment variable.
    pub fn try_from_env(key: impl AsRef<str>) -> Result<Self, OpaqueError> {
        let env_result = std::env::var(key.as_ref()).ok();
        let env_result_mapped = env_result.as_ref().and_then(|v| {
            let v = v.trim();
            if v.is_empty() { None } else { Some(v) }
        });

        let proxy_address = match env_result_mapped {
            Some(value) => Some(value.try_into().context("parse std env proxy info")?),
            None => None,
        };

        Ok(Self::maybe(proxy_address))
    }

    /// Preserve the existing [`ProxyAddress`] in the context if it already exists.
    pub fn preserve(mut self, preserve: bool) -> Self {
        self.preserve = preserve;
        self
    }

    /// Preserve the existing [`ProxyAddress`] in the context if it already exists.
    pub fn set_preserve(&mut self, preserve: bool) -> &mut Self {
        self.preserve = preserve;
        self
    }
}

impl<S> Layer<S> for HttpProxyAddressLayer {
    type Service = HttpProxyAddressService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpProxyAddressService::maybe(inner, self.address.clone()).preserve(self.preserve)
    }
}

/// A [`Service`] which allows you to add a [`ProxyAddress`]
/// to the [`Context`] in order to have your client connector
/// make a connection via this proxy (e.g. by using [`HttpProxyConnectorLayer`]).
///
/// [`Context`]: rama_core::Context
/// [`HttpProxyConnectorLayer`]: crate::client::proxy::layer::HttpProxyConnectorLayer
pub struct HttpProxyAddressService<S> {
    inner: S,
    address: Option<ProxyAddress>,
    preserve: bool,
}

impl<S: fmt::Debug> fmt::Debug for HttpProxyAddressService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProxyAddressService")
            .field("inner", &self.inner)
            .field("address", &self.address)
            .field("preserve", &self.preserve)
            .finish()
    }
}

impl<S: Clone> Clone for HttpProxyAddressService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            address: self.address.clone(),
            preserve: self.preserve,
        }
    }
}

impl<S> HttpProxyAddressService<S> {
    /// Create a new [`HttpProxyAddressService`] that will create
    /// a service to set the given [`ProxyAddress`].
    pub const fn new(inner: S, address: ProxyAddress) -> Self {
        Self::maybe(inner, Some(address))
    }

    /// Create a new [`HttpProxyAddressService`] which will create
    /// a service that will set the given [`ProxyAddress`] if it is not
    /// `None`.
    pub const fn maybe(inner: S, address: Option<ProxyAddress>) -> Self {
        Self {
            inner,
            address,
            preserve: false,
        }
    }

    /// Try to create a new [`HttpProxyAddressService`] which will establish
    /// a proxy connection over the environment variable `HTTP_PROXY`.
    pub fn try_from_env_default(inner: S) -> Result<Self, OpaqueError> {
        Self::try_from_env(inner, "HTTP_PROXY")
    }

    /// Try to create a new [`HttpProxyAddressService`] which will establish
    /// a proxy connection over the given environment variable.
    pub fn try_from_env(inner: S, key: impl AsRef<str>) -> Result<Self, OpaqueError> {
        let env_result = std::env::var(key.as_ref()).ok();
        let env_result_mapped = env_result.as_ref().and_then(|v| {
            let v = v.trim();
            if v.is_empty() { None } else { Some(v) }
        });

        let proxy_address = match env_result_mapped {
            Some(value) => Some(value.try_into().context("parse std env proxy info")?),
            None => None,
        };

        Ok(Self::maybe(inner, proxy_address))
    }

    /// Preserve the existing [`ProxyAddress`] in the context if it already exists.
    pub const fn preserve(mut self, preserve: bool) -> Self {
        self.preserve = preserve;
        self
    }

    /// Preserve the existing [`ProxyAddress`] in the context if it already exists.
    pub fn set_preserve(&mut self, preserve: bool) -> &mut Self {
        self.preserve = preserve;
        self
    }
}

impl<S, State, Request> Service<State, Request> for HttpProxyAddressService<S>
where
    S: Service<State, Request>,
    State: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        if let Some(ref address) = self.address {
            if !self.preserve || !ctx.contains::<ProxyAddress>() {
                tracing::trace!(authority = %address.authority, "setting proxy address");
                ctx.insert(address.clone());
            }
        }
        self.inner.serve(ctx, req)
    }
}
