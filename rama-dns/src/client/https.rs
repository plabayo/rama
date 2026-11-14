//! Connector-free HTTPS service discovery (RFC 9460).
//!
//! The caller supplies its protocol and ECH capabilities and owns connection
//! policy, deadlines and attempts. Caching remains the resolver's responsibility.

use std::num::NonZeroUsize;

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    futures::StreamExt as _,
};
use rama_net::{
    address::{Domain, HostWithPort},
    tls::ApplicationProtocol,
};
use rama_utils::macros::generate_set_and_with;
use rand::seq::SliceRandom as _;

use super::{
    GlobalDnsResolver,
    resolver::{DnsServiceBindingResolver, ServiceBindingRecord},
};
use crate::wire::SvcParamKey;

/// One compatible HTTPS record and its effective physical endpoint.
#[derive(Debug, Clone)]
pub struct HttpsServiceBinding {
    /// Original owner and RDATA, including ECH configuration and address hints.
    pub record: ServiceBindingRecord,
    /// Physical endpoint; the caller retains its original authentication name.
    pub target: HostWithPort,
    /// Compatible protocols in the caller's preference order, without duplicates.
    pub protocols: Vec<ApplicationProtocol>,
}

/// The result of one bounded HTTPS alias traversal.
///
/// This is lookup data, not an extension or a cache. A failed lookup retains the
/// final alias endpoint where RFC 9460 allows that optional fallback. Callers
/// decide whether a resolution failure is fatal under their resolver policy.
#[derive(Debug, Default)]
pub struct HttpsServiceBindings {
    /// Compatible records, ordered by increasing priority and shuffled within it.
    bindings: Vec<HttpsServiceBinding>,
    /// Bare final AliasMode endpoint, tried after records in optional mode only.
    alias_target: Option<HostWithPort>,
    alias_followed: bool,
    /// ECH-capable discovery found only ECH-bearing compatible endpoints.
    /// RFC 9848 forbids bare endpoint fallback for this authority in that case.
    ech_reliant: bool,
    /// Lookup failed; no partially validated records are exposed.
    failure: Option<BoxError>,
}

impl HttpsServiceBindings {
    /// Compatible records in connection-attempt order.
    pub fn bindings(&self) -> &[HttpsServiceBinding] {
        &self.bindings
    }

    /// Optional bare alias fallback, usable only when the caller allows it.
    pub fn alias_target(&self) -> Option<&HostWithPort> {
        self.alias_target.as_ref()
    }

    /// Whether discovery followed HTTPS AliasMode (distinct from DNS CNAME).
    pub fn followed_alias(&self) -> bool {
        self.alias_followed
    }

    /// Whether compatible endpoints require ECH-reliant behavior.
    pub fn ech_reliant(&self) -> bool {
        self.ech_reliant
    }

    /// Actual resolver/record failure. Loops and chain exhaustion act as absence.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.failure.as_deref()
    }
}

/// Shared HTTPS record interpretation for discovery layers and custom stacks.
#[derive(Debug, Clone)]
pub struct HttpsServiceBindingLookup<R = GlobalDnsResolver> {
    resolver: R,
    max_aliases: NonZeroUsize,
    max_records: NonZeroUsize,
}

impl Default for HttpsServiceBindingLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpsServiceBindingLookup {
    /// Use Rama's global resolver without adding another cache.
    pub fn new() -> Self {
        Self {
            resolver: GlobalDnsResolver::new(),
            max_aliases: NonZeroUsize::MIN.saturating_add(7),
            max_records: NonZeroUsize::MIN.saturating_add(63),
        }
    }
}

impl<R> HttpsServiceBindingLookup<R> {
    /// Use the caller's resolver, retaining the lookup limits.
    pub fn with_resolver<T>(self, resolver: T) -> HttpsServiceBindingLookup<T> {
        HttpsServiceBindingLookup {
            resolver,
            max_aliases: self.max_aliases,
            max_records: self.max_records,
        }
    }

    generate_set_and_with! {
        /// Bound followed AliasMode records (default eight, never zero).
        pub fn max_aliases(mut self, limit: NonZeroUsize) -> Self {
            self.max_aliases = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Bound each complete RRset after resolver limits (default 64).
        /// Oversized sets fail atomically.
        pub fn max_records(mut self, limit: NonZeroUsize) -> Self {
            self.max_records = limit;
            self
        }
    }
}

impl<R: DnsServiceBindingResolver> HttpsServiceBindingLookup<R> {
    /// Discover HTTPS services for an already-secure authority.
    ///
    /// IP literals do no DNS work. `ech_capable` means a selected TLS backend
    /// supports real ECH; decoding the DNS parameter alone is not support.
    /// The result describes conditional reliance: evaluate it with final TLS
    /// intent and the selected backend before sending a ClientHello. No ECH
    /// ClientHello may race this lookup. Bound the overall lookup deadline.
    pub async fn lookup(
        &self,
        authority: &HostWithPort,
        protocols: &[ApplicationProtocol],
        ech_capable: bool,
    ) -> HttpsServiceBindings {
        self.lookup_with_shuffle(authority, protocols, ech_capable, |records| {
            records.shuffle(&mut rand::rng());
        })
        .await
    }

    async fn lookup_with_shuffle(
        &self,
        authority: &HostWithPort,
        protocols: &[ApplicationProtocol],
        ech_capable: bool,
        mut shuffle: impl FnMut(&mut [ServiceBindingRecord]) + Send,
    ) -> HttpsServiceBindings {
        let mut result = HttpsServiceBindings::default();
        let Ok(domain) = authority.host.try_as_domain() else {
            return result;
        };
        // RFC 6761 names are answered locally, not sent to a DNS server.
        if domain.is_loopback() {
            return result;
        }
        let mut name = if authority.port == 443 {
            domain.into_owned()
        } else {
            match Domain::try_from(format!("_{}._https.{}", authority.port, domain)) {
                Ok(name) => name,
                Err(error) => {
                    result.failure = Some(error.into());
                    return result;
                }
            }
        };
        let mut visited = Vec::new();
        loop {
            if name.is_loopback() {
                return result;
            }
            if visited.contains(&name) {
                result.alias_target = None;
                // RFC 9460: loops behave as if no HTTPS record existed.
                return result;
            }
            visited.push(name.clone());
            let mut records = Vec::new();
            let mut answers = std::pin::pin!(self.resolver.lookup_https(name.clone()));
            while let Some(answer) = answers.next().await {
                match answer {
                    Ok(record) if records.len() < self.max_records.get() => records.push(record),
                    Ok(_) => {
                        result.failure = Some(BoxError::from_static_str(
                            "HTTPS RRset exceeds record limit",
                        ));
                        return result;
                    }
                    Err(error) => {
                        result.failure = Some(error.into());
                        return result;
                    }
                }
            }
            // Shuffle before stable sorting, including choosing between aliases.
            shuffle(&mut records);
            if let Some(alias) = records.iter().find(|record| record.binding.is_alias_mode()) {
                if visited.len() > self.max_aliases.get() {
                    // RFC 9460 3.1: chain exhaustion returns to the authority.
                    result.alias_target = None;

                    return result;
                }
                let Some(target) = alias.binding.target().to_domain() else {
                    // AliasMode root means the service is not available. It is
                    // not the owner substitution used by ServiceMode.
                    result.alias_target = None;
                    return result;
                };
                result.alias_followed = true;
                name = target;
                result.alias_target = Some(HostWithPort::new(name.clone().into(), authority.port));
                continue;
            }
            records.sort_by_key(|record| record.binding.priority());
            result.bindings = records
                .into_iter()
                .filter_map(|record| compatible(record, authority.port, protocols, ech_capable))
                .collect();
            result.ech_reliant = ech_capable
                && !result.bindings.is_empty()
                && result
                    .bindings
                    .iter()
                    .all(|binding| binding.record.binding.ech_config_list().is_some());
            return result;
        }
    }
}

fn compatible(
    record: ServiceBindingRecord,
    origin_port: u16,
    supported: &[ApplicationProtocol],
    ech_capable: bool,
) -> Option<HttpsServiceBinding> {
    let binding = &record.binding;
    if binding.mandatory_keys().is_some_and(|keys| {
        keys.iter().any(|key| !match key {
            SvcParamKey::Mandatory
            | SvcParamKey::Alpn
            | SvcParamKey::NoDefaultAlpn
            | SvcParamKey::Port
            | SvcParamKey::Ipv4Hint
            | SvcParamKey::Ipv6Hint => true,
            SvcParamKey::Ech => ech_capable,
            _ => false,
        })
    }) {
        return None;
    }
    let target = if binding.target().is_root() {
        &record.owner
    } else {
        binding.target()
    };
    let target = HostWithPort::new(
        target.to_domain()?.into(),
        binding.port().unwrap_or(origin_port),
    );
    if target.port == 0 {
        return None;
    }
    let mut protocols = Vec::new();
    for protocol in supported {
        if protocols.contains(protocol) {
            continue;
        }
        let advertised = binding
            .alpn_protocols()
            .is_some_and(|alpn| alpn.application_protocols().any(|p| &p == protocol));
        let default = !binding.has_no_default_alpn() && protocol == &ApplicationProtocol::HTTP_11;
        if advertised || default {
            protocols.push(protocol.clone());
        }
    }
    if protocols.is_empty() {
        return None;
    }
    Some(HttpsServiceBinding {
        record,
        target,
        protocols,
    })
}

#[cfg(test)]
mod tests;
