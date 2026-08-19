use rama_net::client::ProxyRoutes;

/// What to route through when PAC resolution fails for any reason, including
/// script fetch, parse, execution, timeout, or host-function budget failure.
#[derive(Debug, Clone, Default)]
pub enum PacFailurePolicy {
    /// Fail the request. The default: silently sending traffic
    /// unproxied is the kind of surprise a proxy must not spring.
    #[default]
    Fail,
    /// Connect without a proxy, as browsers do. This is deliberately
    /// fail-open: an unavailable or resource-exhausted script can cause
    /// traffic to bypass the proxy.
    Direct,
    /// Route through these instead. Whether this is fail-open or fail-closed
    /// depends entirely on the supplied routes.
    Routes(ProxyRoutes),
}
