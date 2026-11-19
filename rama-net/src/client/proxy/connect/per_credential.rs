use std::sync::LazyLock;

use ahash::RandomState;
use rama_core::extensions::{Extension, Extensions, ExtensionsRef};

use crate::{
    address::ProxyAddress,
    client::pool::{PoolPartition, ReuseKey},
    user::ProxyCredential,
};

#[cfg(doc)]
use super::ProxyConnectionExtensions;

/// Give a connection to a proxy an identity of its own per credential.
///
/// Connections to a proxy are shared across credentials: each request and each
/// `CONNECT` carries its own `Proxy-Authorization`. That is the default, so a
/// proxy that binds its authentication to the connection (NTLM, Negotiate) or
/// a provider that keeps session state per connection needs this, or its connections to the proxy
/// serve requests of another credential.
///
/// Requests that reach the same proxy with the same credential still share.
///
/// It decides this for the connection to the proxy itself. Tunnels
/// through a proxy are always per credential.
///
/// Ask for it per request or per route by putting it in the route's
/// [`ProxyConnectionExtensions`], or for a whole client by installing
/// [`ProxyConnectionPerCredentialLayer`] in front of the proxy connectors.
#[derive(Debug, Clone, Copy, Default, Extension)]
#[extension(tags(net, proxy))]
pub struct ProxyConnectionPerCredential;

/// Installs [`ProxyConnectionPerCredential`] on every request it passes on.
///
/// Put it in front of the proxy connectors, above the layer that selects the
/// route, so the connection they dial for a request is identified by the
/// credential of that route.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProxyConnectionPerCredentialLayer;

impl<S> rama_core::Layer<S> for ProxyConnectionPerCredentialLayer {
    type Service = ProxyConnectionPerCredentialService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyConnectionPerCredentialService { inner }
    }
}

/// The service of [`ProxyConnectionPerCredentialLayer`].
#[derive(Debug, Clone)]
pub struct ProxyConnectionPerCredentialService<S> {
    inner: S,
}

impl<S, Input> rama_core::Service<Input> for ProxyConnectionPerCredentialService<S>
where
    S: rama_core::Service<Input>,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        input.extensions().insert(ProxyConnectionPerCredential);
        self.inner.serve(input).await
    }
}

// One random key per process: a partition shows up in logs, and a key nobody else
// knows keeps a leaked one from being guessed back to a weak password.
static CREDENTIAL_HASHER: LazyLock<RandomState> = LazyLock::new(RandomState::new);

pub(super) fn credential_partition(
    proxy: &ProxyAddress,
    leg: &Extensions,
) -> Option<PoolPartition> {
    let credential = proxy.credential.as_ref()?;
    leg.get_ref::<ProxyConnectionPerCredential>()?;
    Some(PoolPartition::new(ReuseKey::from_bits::<ProxyCredential>(
        CREDENTIAL_HASHER.hash_one(credential).into(),
    )))
}
