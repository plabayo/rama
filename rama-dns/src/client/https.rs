//! Connector-free HTTPS service discovery (RFC 9460).
//!
//! The caller supplies its protocol and ECH capabilities and owns connection
//! policy, deadlines and attempts. Caching remains the resolver's responsibility.

use std::num::NonZeroUsize;

use rama_core::{
    error::BoxError,
    futures::{Stream, StreamExt as _},
};
use rama_net::{
    address::{Domain, HostWithPort},
    tls::ApplicationProtocol,
};
use rama_utils::macros::nonzero;
use rand::seq::SliceRandom as _;

use super::resolver::{DnsServiceBindingResolver, ServiceBindingRecord};
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
    /// Capability the lookup ran with, so subsets recompute reliance identically.
    ech_capable: bool,
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

    /// This result as if the same authority had been looked up for only `protocol`.
    /// Reliance is recomputed over the remaining endpoints; a resolution failure
    /// stays with the original result.
    #[must_use]
    pub fn restricted_to(&self, protocol: &ApplicationProtocol) -> Self {
        let bindings: Vec<_> = self
            .bindings
            .iter()
            .filter(|binding| binding.protocols.contains(protocol))
            .map(|binding| HttpsServiceBinding {
                record: binding.record.clone(),
                target: binding.target.clone(),
                protocols: vec![protocol.clone()],
            })
            .collect();
        Self {
            ech_reliant: ech_reliant(&bindings, self.ech_capable),
            bindings,
            alias_target: self.alias_target.clone(),
            alias_followed: self.alias_followed,
            ech_capable: self.ech_capable,
            failure: None,
        }
    }

    /// Require successful discovery, preserving the original resolver or record error.
    /// Successful empty answers remain valid. This is caller policy, not evidence
    /// that the resolver authenticated its answer.
    pub fn into_result(mut self) -> Result<Self, BoxError> {
        match self.failure.take() {
            Some(error) => Err(error),
            None => Ok(self),
        }
    }

    /// Actual resolver/record failure. Loops and chain exhaustion act as absence.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.failure.as_deref()
    }
}

/// Default maximum number of HTTPS AliasMode records to follow.
/// This traversal limit is independent of per-RRset resolver limits.
pub const DEFAULT_HTTPS_ALIAS_LIMIT: NonZeroUsize = nonzero!(8);

/// Collect a complete SVCB or HTTPS RRset, ordered by increasing priority with
/// random ordering among equal priorities (including AliasMode records).
///
/// Any stream error discards the entire RRset. No implicit record limit applies;
/// use [`super::resolver::BoundedDnsResolver`] to bound resolver output and apply
/// a caller-owned deadline to pending streams.
pub async fn order_service_binding_records<S, E>(
    records: S,
) -> Result<Vec<ServiceBindingRecord>, BoxError>
where
    S: Stream<Item = Result<ServiceBindingRecord, E>>,
    E: Into<BoxError>,
{
    order_records_with_shuffle(records, |records| records.shuffle(&mut rand::rng())).await
}

async fn order_records_with_shuffle<S, E>(
    records: S,
    mut shuffle: impl FnMut(&mut [ServiceBindingRecord]),
) -> Result<Vec<ServiceBindingRecord>, BoxError>
where
    S: Stream<Item = Result<ServiceBindingRecord, E>>,
    E: Into<BoxError>,
{
    let mut ordered = Vec::new();
    let mut records = std::pin::pin!(records);
    while let Some(record) = records.next().await {
        ordered.push(record.map_err(Into::into)?);
    }
    shuffle(&mut ordered);
    ordered.sort_by_key(|record| record.binding.priority());
    Ok(ordered)
}

/// Discover HTTPS services using a borrowed resolver, following at most
/// `max_aliases` AliasMode records. Use [`DEFAULT_HTTPS_ALIAS_LIMIT`] for the
/// standard traversal bound and [`super::resolver::BoundedDnsResolver`] for
/// independently configured per-RRset limits.
///
/// IP literals and loopback names do no DNS work. The caller owns the overall
/// deadline. Complete this lookup before sending an ECH ClientHello; evaluate
/// the returned reliance with final TLS intent and backend capability.
pub async fn lookup_https_service_bindings<R: DnsServiceBindingResolver>(
    resolver: &R,
    authority: &HostWithPort,
    protocols: &[ApplicationProtocol],
    ech_capable: bool,
    max_aliases: NonZeroUsize,
) -> HttpsServiceBindings {
    lookup_with_shuffle(
        resolver,
        authority,
        protocols,
        ech_capable,
        max_aliases,
        |records| records.shuffle(&mut rand::rng()),
    )
    .await
}

async fn lookup_with_shuffle<R: DnsServiceBindingResolver>(
    resolver: &R,
    authority: &HostWithPort,
    protocols: &[ApplicationProtocol],
    ech_capable: bool,
    max_aliases: NonZeroUsize,
    mut shuffle: impl FnMut(&mut [ServiceBindingRecord]) + Send,
) -> HttpsServiceBindings {
    let mut result = HttpsServiceBindings {
        ech_capable,
        ..Default::default()
    };
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
        let records =
            match order_records_with_shuffle(resolver.lookup_https(name.clone()), &mut shuffle)
                .await
            {
                Ok(records) => records,
                Err(error) => {
                    result.failure = Some(error);
                    return result;
                }
            };
        if let Some(alias) = records.iter().find(|record| record.binding.is_alias_mode()) {
            if visited.len() > max_aliases.get() {
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
        result.bindings = records
            .into_iter()
            .filter_map(|record| {
                HttpsServiceBinding::from_record(record, authority.port, protocols, ech_capable)
            })
            .collect();
        result.ech_reliant = ech_reliant(&result.bindings, ech_capable);
        return result;
    }
}

/// RFC 9848: reliant only when every compatible endpoint offers ECH.
fn ech_reliant(bindings: &[HttpsServiceBinding], ech_capable: bool) -> bool {
    ech_capable
        && !bindings.is_empty()
        && bindings
            .iter()
            .all(|binding| binding.record.binding.ech_config_list().is_some())
}

impl HttpsServiceBinding {
    /// Interpret one HTTPS ServiceMode record without resolving or selecting it.
    /// Returns `None` for AliasMode records, unsupported mandatory parameters,
    /// incompatible protocols or unusable endpoints. The caller retains its
    /// original authentication name; the returned target is only a physical endpoint.
    pub fn from_record(
        record: ServiceBindingRecord,
        origin_port: u16,
        supported: &[ApplicationProtocol],
        ech_capable: bool,
    ) -> Option<Self> {
        let binding = &record.binding;
        if binding.is_alias_mode() {
            return None;
        }
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
            let default =
                !binding.has_no_default_alpn() && protocol == &ApplicationProtocol::HTTP_11;
            if advertised || default {
                protocols.push(protocol.clone());
            }
        }
        if protocols.is_empty() {
            return None;
        }
        Some(Self {
            record,
            target,
            protocols,
        })
    }
}

#[cfg(test)]
mod tests;
