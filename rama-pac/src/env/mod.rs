//! The PAC javascript environment: the host functions a PAC script may
//! call, registered on a [`JsRuntimeBuilder`].

use std::borrow::Cow;
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
use rama_net::address::ip::ipnet::IpNet;
use rama_utils::macros::generate_set_and_with;
use rama_utils::octets::kib;

mod budget;
mod dns;
mod local_ip;
mod predicate;
mod time;

pub(crate) use budget::PacBudget;
use dns::PacDnsBridge;
pub use local_ip::{DEFAULT_LOCAL_IP_SCOPES, PacLocalAddresses};
pub use predicate::PacShExpMatch;

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
    max_lookups_per_evaluation: u32,
    max_glob_steps_per_evaluation: u64,
    max_alerts_per_evaluation: u32,
    max_blocking_per_evaluation: Duration,
    sh_exp_match: PacShExpMatch,
    local_addresses: PacLocalAddresses,
    clock: Option<PacClock>,
    promote_ipv4_in_net: bool,
}

impl std::fmt::Debug for PacEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacEnv")
            .field("dns_timeout", &self.dns_timeout)
            .field(
                "max_lookups_per_evaluation",
                &self.max_lookups_per_evaluation,
            )
            .field(
                "max_glob_steps_per_evaluation",
                &self.max_glob_steps_per_evaluation,
            )
            .field("max_alerts_per_evaluation", &self.max_alerts_per_evaluation)
            .field("sh_exp_match", &self.sh_exp_match)
            .field(
                "max_blocking_per_evaluation",
                &self.max_blocking_per_evaluation,
            )
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
            max_lookups_per_evaluation: Self::DEFAULT_MAX_LOOKUPS_PER_EVALUATION,
            max_glob_steps_per_evaluation: Self::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION,
            max_alerts_per_evaluation: Self::DEFAULT_MAX_ALERTS_PER_EVALUATION,
            max_blocking_per_evaluation: Self::DEFAULT_MAX_BLOCKING_PER_EVALUATION,
            sh_exp_match: PacShExpMatch::default(),
            local_addresses: PacLocalAddresses::default(),
            clock: None,
            promote_ipv4_in_net: true,
        }
    }
}

impl PacEnv {
    /// Default per-lookup timeout for the dns host functions.
    pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);

    /// Default number of dns lookups one evaluation may make.
    ///
    /// Generous for any real policy — reference scripts resolve the request
    /// host and little else — while keeping a hostile script from turning
    /// one request into an unbounded burst of queries.
    pub const DEFAULT_MAX_LOOKUPS_PER_EVALUATION: u32 = 64;

    /// Default number of character comparisons `shExpMatch` may spend in one
    /// evaluation, across every call it makes.
    ///
    /// Glob matching is native work no deadline can interrupt, so it needs a
    /// bound of its own. Far above what a real policy spends — a rule set
    /// testing a url costs thousands of steps, not millions — and exhausting
    /// it fails the evaluation rather than answering `false`, so a padded url
    /// cannot quietly stop a rule from matching.
    pub const DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION: u64 = 50_000_000;

    /// Default number of `alert` calls one evaluation may write to the log.
    ///
    /// Diagnostics for a script author, not a channel a script may use to
    /// fill an operator's disk.
    pub const DEFAULT_MAX_ALERTS_PER_EVALUATION: u32 = 32;

    /// Default wall clock the host functions may block one evaluation for.
    ///
    /// Name resolution blocks the worker thread, and the execution time
    /// limit cannot interrupt it, so the lookup *count* alone would still let
    /// one evaluation hold its worker for count times the dns timeout.
    pub const DEFAULT_MAX_BLOCKING_PER_EVALUATION: Duration = Duration::from_secs(15);

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

    /// How many dns lookups one evaluation may make.
    #[must_use]
    pub fn max_lookups_per_evaluation(&self) -> u32 {
        self.max_lookups_per_evaluation
    }

    /// How many `shExpMatch` steps one evaluation may spend.
    #[must_use]
    pub fn max_glob_steps_per_evaluation(&self) -> u64 {
        self.max_glob_steps_per_evaluation
    }

    /// How many `alert` calls one evaluation may log.
    #[must_use]
    pub fn max_alerts_per_evaluation(&self) -> u32 {
        self.max_alerts_per_evaluation
    }

    /// How long the host functions may block one evaluation.
    #[must_use]
    pub fn max_blocking_per_evaluation(&self) -> Duration {
        self.max_blocking_per_evaluation
    }

    pub(crate) fn budget(&self) -> PacBudget {
        PacBudget {
            lookups: self.max_lookups_per_evaluation,
            glob_steps: self.max_glob_steps_per_evaluation,
            alerts: self.max_alerts_per_evaluation,
            blocking: self.max_blocking_per_evaluation,
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
        /// How many dns lookups one evaluation may make before further ones
        /// report their host as unresolvable (defaults to
        /// [`Self::DEFAULT_MAX_LOOKUPS_PER_EVALUATION`]).
        ///
        /// Only enforced for callers that arm the budget per evaluation, as
        /// [`PacResolver`][crate::PacResolver] does.
        pub fn max_lookups_per_evaluation(mut self, lookups: u32) -> Self {
            self.max_lookups_per_evaluation = lookups;
            self
        }
    }

    generate_set_and_with! {
        /// How `shExpMatch` reads its pattern (defaults to
        /// [`PacShExpMatch::Reference`], what browsers do).
        pub fn sh_exp_match(mut self, sh_exp_match: PacShExpMatch) -> Self {
            self.sh_exp_match = sh_exp_match;
            self
        }
    }

    generate_set_and_with! {
        /// How long the host functions may block one evaluation before the
        /// rest fail it (defaults to
        /// [`Self::DEFAULT_MAX_BLOCKING_PER_EVALUATION`]).
        pub fn max_blocking_per_evaluation(mut self, blocking: Duration) -> Self {
            self.max_blocking_per_evaluation = blocking;
            self
        }
    }

    generate_set_and_with! {
        /// How many `alert` calls one evaluation may write to the log
        /// before the rest are dropped (defaults to
        /// [`Self::DEFAULT_MAX_ALERTS_PER_EVALUATION`]).
        pub fn max_alerts_per_evaluation(mut self, alerts: u32) -> Self {
            self.max_alerts_per_evaluation = alerts;
            self
        }
    }

    generate_set_and_with! {
        /// How many `shExpMatch` character comparisons one evaluation may
        /// spend before the evaluation fails (defaults to
        /// [`Self::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION`]).
        pub fn max_glob_steps_per_evaluation(mut self, steps: u64) -> Self {
            self.max_glob_steps_per_evaluation = steps;
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
            self.sh_exp_match,
        ))
    }
}

fn register_host_fns(
    builder: JsRuntimeBuilder,
    bridge: PacDnsBridge,
    local_addresses: PacLocalAddresses,
    clock: PacClock,
    promote_ipv4: bool,
    sh_exp_match: PacShExpMatch,
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
            move |input: Option<JsStr>, pattern: Option<JsStr>| match (input, pattern) {
                (Some(input), Some(pattern)) => {
                    predicate::sh_exp_match(&input, &pattern, sh_exp_match)
                        .map_err(|err| rama_js::JsError::throw(err.to_string()))
                }
                _ => Ok(false),
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
        .with_fn("alert", |args: JsArgs| {
            // past the cap the line is dropped rather than failing the
            // evaluation: losing a diagnostic is not a routing decision
            if !budget::take_alert() {
                return;
            }
            let message = alert_message(&args);
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
            .with_fn("dnsResolve", move |host: Lenient<Host>| match host.0 {
                Some(host) => resolve
                    .lookup(&host, false)
                    .map(|addresses| addresses.first().map(IpAddr::to_string))
                    .map_err(throw),
                None => Ok(None),
            })
            .with_fn("dnsResolveEx", move |host: Lenient<Host>| match host.0 {
                Some(host) => resolve_ex
                    .lookup_all(&host)
                    .map(predicate::join_addresses)
                    .map_err(throw),
                None => Ok(String::new()),
            })
            .with_fn("isResolvable", move |host: Lenient<Host>| match host.0 {
                Some(host) => resolvable
                    .lookup(&host, false)
                    .map(|addresses| !addresses.is_empty())
                    .map_err(throw),
                None => Ok(false),
            })
            .with_fn("isResolvableEx", move |host: Lenient<Host>| match host.0 {
                Some(host) => resolvable_ex
                    .lookup(&host, true)
                    .map(|addresses| !addresses.is_empty())
                    .map_err(throw),
                None => Ok(false),
            })
            .with_fn(
                "isInNet",
                move |host: Lenient<Host>, pattern: Lenient<Ipv4Addr>, mask: Lenient<Ipv4Addr>| {
                    match (host.0, pattern.0, mask.0) {
                        (Some(host), Some(pattern), Some(mask)) => {
                            is_in_net(&in_net, &host, pattern, mask)
                        }
                        _ => Ok(false),
                    }
                },
            )
            .with_fn(
                "isInNetEx",
                move |host: Lenient<Host>, prefix: Lenient<IpNet>| match (host.0, prefix.0) {
                    (Some(host), Some(prefix)) => {
                        is_in_net_ex(&in_net_ex, &host, prefix, promote_ipv4)
                    }
                    _ => Ok(false),
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

/// Arm the per-evaluation budgets for the evaluation about to run on this
/// thread. Must be called on the worker thread itself, since the budgets
/// are thread-local.
pub(crate) fn arm_evaluation_budget(budget: PacBudget) {
    budget::arm(budget);
}

/// Longest `alert` message written to the log: a script must not be able
/// to choose how much is logged per call.
const MAX_ALERT_MESSAGE_BYTES: usize = kib(1);

/// The `alert` arguments as one escaped, length-capped log message.
fn alert_message(args: &JsArgs) -> String {
    let mut message = String::new();
    let mut truncated = false;

    'args: for arg in args.iter() {
        if message.len() >= MAX_ALERT_MESSAGE_BYTES {
            truncated = true;
            break;
        }
        if !message.is_empty() {
            message.push(' ');
        }
        let text = arg.as_str().map_or_else(
            // a non-string argument is rendered under the same budget, so a
            // script cannot make the host build a huge string first
            || Cow::Owned(bounded_render(arg, MAX_ALERT_MESSAGE_BYTES)),
            Cow::Borrowed,
        );
        // script-controlled text must not forge log lines
        for part in text.chars().flat_map(char::escape_debug) {
            if message.len() >= MAX_ALERT_MESSAGE_BYTES {
                truncated = true;
                break 'args;
            }
            message.push(part);
        }
    }

    if truncated {
        message.push('…');
    }
    message
}

/// Render a value for the log, stopping at `budget` bytes.
///
/// `Display` on a nested value walks the whole graph, so a script could
/// otherwise make the host build megabytes before anything caps it.
fn bounded_render(value: &rama_js::JsValue, budget: usize) -> String {
    use std::fmt::Write as _;

    struct Bounded {
        out: String,
        budget: usize,
    }

    impl std::fmt::Write for Bounded {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            let room = self.budget.saturating_sub(self.out.len());
            if room == 0 {
                return Err(std::fmt::Error);
            }
            if s.len() <= room {
                self.out.push_str(s);
                return Ok(());
            }
            let mut cut = room;
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            self.out.push_str(&s[..cut]);
            Err(std::fmt::Error)
        }
    }

    let mut bounded = Bounded {
        out: String::new(),
        budget,
    };
    let _stopped_at_budget = write!(bounded, "{value}");
    bounded.out
}

/// Widest date/time call: six numbers plus the trailing `"GMT"`.
const MAX_TIME_ARGS: usize = 7;

/// Stringify the arguments of a variadic date/time host function.
///
/// `null` and `undefined` are kept as the unparsable strings they render
/// as: dropping them would turn a call with a missing bound into a
/// shorter, matching form of the same function.
fn string_args(args: &JsArgs) -> Vec<String> {
    args.iter()
        // one over the widest form, so an over-long call matches no arm
        .take(MAX_TIME_ARGS + 1)
        .map(ToString::to_string)
        .collect()
}

/// `isInNet(host, pattern, mask)`: dotted-quad netmask, ipv4 only.
///
/// The mask is applied bitwise, so a non-contiguous one is honoured just
/// as the reference implementations honour it.
fn is_in_net(
    bridge: &PacDnsBridge,
    host: &Host,
    pattern: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<bool, rama_js::JsError> {
    let (pattern, mask) = (u32::from(pattern), u32::from(mask));
    Ok(bridge
        .lookup(host, false)
        .map_err(throw)?
        .into_iter()
        .any(|address| match address {
            IpAddr::V4(address) => u32::from(address) & mask == pattern & mask,
            IpAddr::V6(_) => false,
        }))
}

/// `isInNetEx(host, prefix)`: CIDR prefix, either address family.
///
/// With `promote_ipv4`, an ipv4 address is compared against an ipv6
/// prefix as its v4-mapped form (and vice versa), which is what
/// browsers do; without it a family mismatch is simply `false`.
fn is_in_net_ex(
    bridge: &PacDnsBridge,
    host: &Host,
    net: IpNet,
    promote_ipv4: bool,
) -> Result<bool, rama_js::JsError> {
    Ok(bridge
        .lookup(host, true)
        .map_err(throw)?
        .into_iter()
        .any(|address| ip_in_net(net, address, promote_ipv4)))
}

/// A budget a script spent is not an answer: it fails the evaluation, so
/// nothing it exhausts can quietly turn a rule off.
fn throw(err: impl std::fmt::Display) -> rama_js::JsError {
    rama_js::JsError::throw(err.to_string())
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
