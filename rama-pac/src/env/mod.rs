//! The PAC javascript environment: the host functions a PAC script may
//! call, registered on a [`JsRuntimeBuilder`].

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use jiff::Zoned;
use rama_core::error::{BoxError, BoxErrorExt};
use rama_core::telemetry::tracing;
use rama_dns::client::{
    GlobalDnsResolver,
    resolver::{BoxDnsAddressResolver, DnsAddressResolver},
};
use rama_js::{JsArgs, JsRuntimeBuilder, JsValue};
use rama_net::address::ip::ipnet::{IpNet, Ipv4Net};
use rama_utils::macros::generate_set_and_with;

mod dns;
mod predicate;
mod time;

use dns::PacDnsBridge;
use predicate::arg_str;

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
    my_ip: Option<IpAddr>,
    clock: Option<PacClock>,
}

impl std::fmt::Debug for PacEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacEnv")
            .field("dns_timeout", &self.dns_timeout)
            .field("my_ip", &self.my_ip)
            .finish_non_exhaustive()
    }
}

impl Default for PacEnv {
    fn default() -> Self {
        Self {
            resolver: None,
            dns_timeout: Self::DEFAULT_DNS_TIMEOUT,
            my_ip: None,
            clock: None,
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
        /// Report this address from `myIpAddress()` / `myIpAddressEx()`
        /// instead of asking the OS which source address it would route
        /// from. Only one address is reported, where the reference
        /// `myIpAddressEx()` lists every local address.
        pub fn my_ip(mut self, my_ip: Option<IpAddr>) -> Self {
            self.my_ip = my_ip;
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
        let my_ip = self.my_ip.unwrap_or_else(dns::detect_my_ip);
        let clock = self.clock.unwrap_or_else(|| Arc::new(Zoned::now));

        Ok(register_host_fns(builder, bridge, my_ip, clock))
    }
}

fn register_host_fns(
    builder: JsRuntimeBuilder,
    bridge: PacDnsBridge,
    my_ip: IpAddr,
    clock: PacClock,
) -> JsRuntimeBuilder {
    let builder = builder
        // ── host shape predicates ──────────────────────────────────
        .with_fn("isPlainHostName", |host: JsValue| {
            arg_str(&host).is_some_and(|host| predicate::is_plain_host_name(&host))
        })
        .with_fn("dnsDomainIs", |host: JsValue, domain: JsValue| {
            match (arg_str(&host), arg_str(&domain)) {
                (Some(host), Some(domain)) => predicate::dns_domain_is(&host, &domain),
                _ => false,
            }
        })
        .with_fn(
            "localHostOrDomainIs",
            |host: JsValue, hostdom: JsValue| match (arg_str(&host), arg_str(&hostdom)) {
                (Some(host), Some(hostdom)) => predicate::local_host_or_domain_is(&host, &hostdom),
                _ => false,
            },
        )
        .with_fn("dnsDomainLevels", |host: JsValue| {
            arg_str(&host).map_or(0, |host| predicate::dns_domain_levels(&host))
        })
        .with_fn("shExpMatch", |input: JsValue, pattern: JsValue| {
            match (arg_str(&input), arg_str(&pattern)) {
                (Some(input), Some(pattern)) => predicate::sh_exp_match(&input, &pattern),
                _ => false,
            }
        })
        .with_fn("sortIpAddressList", |list: JsValue| {
            arg_str(&list).map_or_else(String::new, |list| predicate::sort_ip_address_list(&list))
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
            .with_fn("dnsResolve", move |host: JsValue| {
                arg_str(&host)
                    .and_then(|host| resolve.lookup(&host, false).first().map(IpAddr::to_string))
            })
            .with_fn("dnsResolveEx", move |host: JsValue| {
                arg_str(&host).map_or_else(String::new, |host| {
                    predicate::join_addresses(resolve_ex.lookup_all(&host))
                })
            })
            .with_fn("isResolvable", move |host: JsValue| {
                arg_str(&host).is_some_and(|host| !resolvable.lookup(&host, false).is_empty())
            })
            .with_fn("isResolvableEx", move |host: JsValue| {
                arg_str(&host).is_some_and(|host| !resolvable_ex.lookup(&host, true).is_empty())
            })
            .with_fn(
                "isInNet",
                move |host: JsValue, pattern: JsValue, mask: JsValue| match (
                    arg_str(&host),
                    arg_str(&pattern),
                    arg_str(&mask),
                ) {
                    (Some(host), Some(pattern), Some(mask)) => {
                        is_in_net(&in_net, &host, &pattern, &mask)
                    }
                    _ => false,
                },
            )
            .with_fn("isInNetEx", move |host: JsValue, prefix: JsValue| {
                match (arg_str(&host), arg_str(&prefix)) {
                    (Some(host), Some(prefix)) => is_in_net_ex(&in_net_ex, &host, &prefix),
                    _ => false,
                }
            })
    };

    // ── local address ──────────────────────────────────────────────
    let builder = builder
        .with_fn("myIpAddress", move || {
            // classic callers expect an ipv4 dotted quad
            match my_ip {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(_) => std::net::Ipv4Addr::LOCALHOST.to_string(),
            }
        })
        .with_fn("myIpAddressEx", move || my_ip.to_string());

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
    args.iter().filter_map(arg_str).collect()
}

/// `isInNet(host, pattern, mask)`: dotted-quad netmask, ipv4 only.
fn is_in_net(bridge: &PacDnsBridge, host: &str, pattern: &str, mask: &str) -> bool {
    let (Ok(pattern), Ok(mask)) = (pattern.parse(), mask.parse()) else {
        return false;
    };
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
fn is_in_net_ex(bridge: &PacDnsBridge, host: &str, prefix: &str) -> bool {
    let Ok(net) = prefix.parse::<IpNet>() else {
        return false;
    };
    bridge
        .lookup(host, true)
        .into_iter()
        .any(|address| net.contains(&address))
}
