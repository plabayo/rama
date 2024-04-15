use super::{ProxyCredentials, ProxyFilter, RequestContext, StringFilter};
use crate::http::Version;
use venndb::VennDB;

#[derive(Debug, Clone, VennDB)]
/// The selected proxy to use to connect to the proxy.
pub struct Proxy {
    #[venndb(key)]
    /// Unique identifier of the proxy.
    pub id: String,

    /// True if the proxy supports TCP connections.
    pub tcp: bool,

    /// True if the proxy supports UDP connections.
    pub udp: bool,

    /// http-proxy enabled
    pub http: bool,

    /// socks5-proxy enabled
    pub socks5: bool,

    /// Proxy is located in a datacenter.
    pub datacenter: bool,

    /// Proxy's IP is labeled as residential.
    pub residential: bool,

    /// Proxy's IP originates from a mobile network.
    pub mobile: bool,

    /// The address of the proxy to use to connect to the proxy,
    /// containing the port and the host.
    pub address: String,

    #[venndb(filter, any)]
    /// Pool ID of the proxy.
    pub pool_id: Option<StringFilter>,

    #[venndb(filter, any)]
    /// Country of the proxy.
    pub country: Option<StringFilter>,

    #[venndb(filter, any)]
    /// City of the proxy.
    pub city: Option<StringFilter>,

    #[venndb(filter, any)]
    /// Mobile carrier of the proxy.
    pub carrier: Option<StringFilter>,

    /// The optional credentials to use to authenticate with the proxy.
    ///
    /// See [`ProxyCredentials`] for more information.
    pub credentials: Option<ProxyCredentials>,
}

impl Proxy {
    /// Check if the proxy is a match for the given[`RequestContext`] and [`ProxyFilter`].
    ///
    /// TODO: add unit tests for this?!
    pub fn is_match(&self, ctx: &RequestContext, filter: &ProxyFilter) -> bool {
        if (ctx.http_version == Version::HTTP_3 && !self.socks5 && !self.udp)
            || (ctx.http_version != Version::HTTP_3 && !self.tcp)
        {
            return false;
        }

        return filter
            .country
            .as_ref()
            .map(|c| Some(c) == self.country.as_ref())
            .unwrap_or(true)
            && filter
                .city
                .as_ref()
                .map(|c| Some(c) == self.city.as_ref())
                .unwrap_or(true)
            && filter
                .pool_id
                .as_ref()
                .map(|p| Some(p) == self.pool_id.as_ref())
                .unwrap_or(true)
            && filter
                .carrier
                .as_ref()
                .map(|c| Some(c) == self.carrier.as_ref())
                .unwrap_or(true)
            && filter
                .datacenter
                .map(|d| d == self.datacenter)
                .unwrap_or(true)
            && filter
                .residential
                .map(|r| r == self.residential)
                .unwrap_or(true)
            && filter.mobile.map(|m| m == self.mobile).unwrap_or(true);
    }
}
