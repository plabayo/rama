//! The PAC javascript environment: the host functions a PAC script may
//! call, registered on a [`JsRuntimeBuilder`].

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use jiff::Zoned;
use rama_core::error::{BoxError, BoxErrorExt};
use rama_core::telemetry::tracing;
use rama_dns::client::{
    GlobalDnsResolver,
    resolver::{BoxDnsAddressResolver, DnsAddressResolver},
};
use rama_js::{JsArg, JsArgs, JsRuntimeBuilder, JsStr, JsValue};
use rama_net::address::Host;
use rama_net::address::ip::ipnet::{IpNet, Ipv4Net};
use rama_utils::macros::generate_set_and_with;

mod dns;
mod local_ip;
mod predicate;
mod time;

use dns::PacDnsBridge;
pub use local_ip::{DEFAULT_LOCAL_IP_SCOPES, PacLocalAddresses};

/// A typed host-function argument that is absent when the script passed
/// something that is not one.
///
/// PAC host functions answer `null`/`false` for a malformed argument
/// rather than throwing, so the typed extraction must not fail the call.
struct Lenient<T>(Option<T>);

impl<T: JsArg> JsArg for Lenient<T> {
    fn from_js(value: JsValue) -> Result<Self, rama_js::JsError> {
        Ok(Self(T::from_js(value).ok()))
    }

    fn from_missing_js_arg() -> Result<Self, rama_js::JsError> {
        Ok(Self(None))
    }
}

/// The clock a PAC environment reads the current time from.
pub type PacClock = Arc<dyn Fn() -> Zoned + Send + Sync + 'static>;

/// Builds the PAC javascript environment.
///
/// Registering it on a [`JsRuntimeBuilder`] adds every standard PAC host
/// function, including the Microsoft IPv6 (`*Ex`) extensions.
#[derive(Clone)]
pub struct PacEnv {
    resolver: Option<BoxDnsAddressResolver>,
    dns_timeout: Duration,
    local_addresses: PacLocalAddresses,
    clock: Option<PacClock>,
    promote_ipv4_in_net: bool,
}

impl std::fmt::Debug for PacEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacEnv")
            .field("dns_timeout", &self.dns_timeout)
            .field("local_addresses", &self.local_addresses)
            .field("promote_ipv4_in_net", &self.promote_ipv4_in_net)
            .finish_non_exhaustive()
    }
}

impl Default for PacEnv {
    fn default() -> Self {
        Self {
            resolver: None,
            dns_timeout: Self::DEFAULT_DNS_TIMEOUT,
            local_addresses: PacLocalAddresses::default(),
            clock: None,
            promote_ipv4_in_net: true,
        }
    }
}

impl PacEnv {
    /// Default per-lookup timeout for the dns host functions.
    pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);

    /// Create a PAC environment with the default configuration: the
    /// global dns resolver and the system clock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Resolve names through this resolver instead of the
        /// [`GlobalDnsResolver`].
        pub fn resolver(mut self, resolver: Option<BoxDnsAddressResolver>) -> Self {
            self.resolver = resolver;
            self
        }
    }

    /// The timeout one dns lookup gets.
    #[must_use]
    pub fn dns_timeout(&self) -> Duration {
        self.dns_timeout
    }

    generate_set_and_with! {
        /// Timeout for a single dns lookup made by a host function
        /// (defaults to [`Self::DEFAULT_DNS_TIMEOUT`]).
        ///
        /// A lookup that exceeds it reports the host as unresolvable
        /// rather than failing the evaluation.
        pub fn dns_timeout(mut self, dns_timeout: Duration) -> Self {
            self.dns_timeout = dns_timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Which local addresses `myIpAddress()` and `myIpAddressEx()`
        /// disclose to the script (defaults to browser behaviour, see
        /// [`PacLocalAddresses`]).
        pub fn local_addresses(mut self, local_addresses: PacLocalAddresses) -> Self {
            self.local_addresses = local_addresses;
            self
        }
    }

    generate_set_and_with! {
        /// Compare an ipv4 address against an ipv6 `isInNetEx` prefix as
        /// its v4-mapped form, and vice versa (defaults to `true`, which
        /// is what browsers do).
        ///
        /// Note this makes an ipv6 catch-all such as `::/0` match ipv4
        /// addresses too; disable it to keep families strictly apart.
        pub fn promote_ipv4_in_net(mut self, promote_ipv4_in_net: bool) -> Self {
            self.promote_ipv4_in_net = promote_ipv4_in_net;
            self
        }
    }

    generate_set_and_with! {
        /// Read the current time from this clock instead of the system
        /// one, so the time-based host functions can be pinned in tests.
        pub fn clock(mut self, clock: Option<PacClock>) -> Self {
            self.clock = clock;
            self
        }
    }

    /// Set the dns resolver, taking any [`DnsAddressResolver`].
    #[must_use]
    pub fn with_dns_resolver(self, resolver: impl DnsAddressResolver) -> Self {
        self.with_resolver(resolver.into_box_dns_address_resolver())
    }

    /// Register every PAC host function on the given runtime builder.
    ///
    /// Requires an ambient tokio runtime: the dns host functions are
    /// synchronous and block the script's worker thread on it.
    pub fn register(self, builder: JsRuntimeBuilder) -> Result<JsRuntimeBuilder, BoxError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_e| BoxError::from_static_str("pac env requires a tokio runtime"))?;
        let resolver = self
            .resolver
            .unwrap_or_else(|| GlobalDnsResolver::new().into_box_dns_address_resolver());
        let bridge = PacDnsBridge::new(runtime, resolver, self.dns_timeout);
        let clock = self.clock.unwrap_or_else(|| Arc::new(Zoned::now));

        Ok(register_host_fns(
            builder,
            bridge,
            self.local_addresses,
            clock,
            self.promote_ipv4_in_net,
        ))
    }
}

fn register_host_fns(
    builder: JsRuntimeBuilder,
    bridge: PacDnsBridge,
    local_addresses: PacLocalAddresses,
    clock: PacClock,
    promote_ipv4: bool,
) -> JsRuntimeBuilder {
    let builder = builder
        // ── host shape predicates ──────────────────────────────────
        // these five are string predicates by definition: a pac script may
        // pass any string, so they must not reject on host syntax
        .with_fn("isPlainHostName", |host: Option<JsStr>| {
            host.is_some_and(|host| predicate::is_plain_host_name(&host))
        })
        .with_fn(
            "dnsDomainIs",
            |host: Option<JsStr>, domain: Option<JsStr>| match (host, domain) {
                (Some(host), Some(domain)) => predicate::dns_domain_is(&host, &domain),
                _ => false,
            },
        )
        .with_fn(
            "localHostOrDomainIs",
            |host: Option<JsStr>, hostdom: Option<JsStr>| match (host, hostdom) {
                (Some(host), Some(hostdom)) => predicate::local_host_or_domain_is(&host, &hostdom),
                _ => false,
            },
        )
        .with_fn("dnsDomainLevels", |host: Option<JsStr>| {
            host.map_or(0, |host| predicate::dns_domain_levels(&host))
        })
        .with_fn(
            "shExpMatch",
            |input: Option<JsStr>, pattern: Option<JsStr>| match (input, pattern) {
                (Some(input), Some(pattern)) => predicate::sh_exp_match(&input, &pattern),
                _ => false,
            },
        )
        // `false` for a malformed list, like browsers: a script that
        // splits the result then fails loudly instead of seeing ""
        .with_fn("sortIpAddressList", |list: Option<JsStr>| {
            list.and_then(|list| predicate::sort_ip_address_list(&list))
                .map_or(JsValue::Bool(false), |sorted| {
                    JsValue::String(sorted.into())
                })
        })
        .with_fn("getClientVersion", || "1.0")
        .with_fn("alert", |message: JsArgs| {
            // script-controlled text must not forge log lines
            let message: String = message
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .flat_map(char::escape_debug)
                .collect();
            tracing::info!(target: "rama_pac::alert", "pac alert: {message}");
        });

    // ── name resolution ────────────────────────────────────────────
    let builder = {
        let resolve = bridge.clone();
        let resolve_ex = bridge.clone();
        let resolvable = bridge.clone();
        let resolvable_ex = bridge.clone();
        let in_net = bridge.clone();
        let in_net_ex = bridge;

        builder
            // an unresolvable or malformed host is `null`/`false`, never a
            // throw: pac scripts branch on the value, not on an exception
            .with_fn("dnsResolve", move |host: Lenient<Host>| {
                host.0
                    .and_then(|host| resolve.lookup(&host, false).first().map(IpAddr::to_string))
            })
            .with_fn("dnsResolveEx", move |host: Lenient<Host>| {
                host.0.map_or_else(String::new, |host| {
                    predicate::join_addresses(resolve_ex.lookup_all(&host))
                })
            })
            .with_fn("isResolvable", move |host: Lenient<Host>| {
                host.0
                    .is_some_and(|host| !resolvable.lookup(&host, false).is_empty())
            })
            .with_fn("isResolvableEx", move |host: Lenient<Host>| {
                host.0
                    .is_some_and(|host| !resolvable_ex.lookup(&host, true).is_empty())
            })
            .with_fn(
                "isInNet",
                move |host: Lenient<Host>, pattern: Lenient<Ipv4Addr>, mask: Lenient<Ipv4Addr>| {
                    match (host.0, pattern.0, mask.0) {
                        (Some(host), Some(pattern), Some(mask)) => {
                            is_in_net(&in_net, &host, pattern, mask)
                        }
                        _ => false,
                    }
                },
            )
            .with_fn(
                "isInNetEx",
                move |host: Lenient<Host>, prefix: Lenient<IpNet>| match (host.0, prefix.0) {
                    (Some(host), Some(prefix)) => {
                        is_in_net_ex(&in_net_ex, &host, prefix, promote_ipv4)
                    }
                    _ => false,
                },
            )
    };

    // ── local address ──────────────────────────────────────────────
    let local_ex = local_addresses.clone();
    let builder = builder
        .with_fn("myIpAddress", move || {
            local_addresses.resolve_ipv4().to_string()
        })
        // the Ex variant lists every address, `;`-separated
        .with_fn("myIpAddressEx", move || {
            predicate::join_addresses(local_ex.resolve())
        });

    // ── date and time ──────────────────────────────────────────────
    let weekday_clock = clock.clone();
    let date_clock = clock.clone();
    let time_clock = clock;
    builder
        .with_fn("weekdayRange", move |args: JsArgs| {
            time::weekday_range(&weekday_clock(), &string_args(&args))
        })
        .with_fn("dateRange", move |args: JsArgs| {
            time::date_range(&date_clock(), &string_args(&args))
        })
        .with_fn("timeRange", move |args: JsArgs| {
            time::time_range(&time_clock(), &string_args(&args))
        })
}

fn string_args(args: &JsArgs) -> Vec<String> {
    args.iter()
        .filter(|arg| !arg.is_null_or_undefined())
        .map(ToString::to_string)
        .collect()
}

/// `isInNet(host, pattern, mask)`: dotted-quad netmask, ipv4 only.
fn is_in_net(bridge: &PacDnsBridge, host: &Host, pattern: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let Ok(net) = Ipv4Net::with_netmask(pattern, mask) else {
        return false;
    };
    bridge
        .lookup(host, false)
        .into_iter()
        .any(|address| match address {
            IpAddr::V4(address) => net.contains(&address),
            IpAddr::V6(_) => false,
        })
}

/// `isInNetEx(host, prefix)`: CIDR prefix, either address family.
///
/// With `promote_ipv4`, an ipv4 address is compared against an ipv6
/// prefix as its v4-mapped form (and vice versa), which is what
/// browsers do; without it a family mismatch is simply `false`.
fn is_in_net_ex(bridge: &PacDnsBridge, host: &Host, net: IpNet, promote_ipv4: bool) -> bool {
    bridge
        .lookup(host, true)
        .into_iter()
        .any(|address| ip_in_net(net, address, promote_ipv4))
}

fn ip_in_net(net: IpNet, address: IpAddr, promote_ipv4: bool) -> bool {
    if net.contains(&address) {
        return true;
    }
    if !promote_ipv4 {
        return false;
    }
    match (net, address) {
        (IpNet::V6(_), IpAddr::V4(address)) => net.contains(&IpAddr::V6(address.to_ipv6_mapped())),
        // an ipv4-mapped answer still belongs to its ipv4 network
        (IpNet::V4(_), IpAddr::V6(address)) => address
            .to_ipv4_mapped()
            .is_some_and(|address| net.contains(&IpAddr::V4(address))),
        _ => false,
    }
}
