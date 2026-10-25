//! Opt-in HTTP/3 connection coalescing across origins one certificate covers.

use crate::client::pool::connection_version_requirement;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, Extensions, ExtensionsRef as _},
    telemetry::tracing,
};
use rama_http_types::{
    Version,
    conn::{HttpOrigin, HttpServiceSource, SelectedHttpService},
};
use rama_net::{
    address::Host,
    client::{
        ConnectRequest, ConnectorTarget,
        pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey},
    },
    tls::ApplicationProtocol,
};
use rama_quic::{Connection, tls::QuicClientConfigProvider};
use rama_tls::client::{
    NegotiatedTlsParameters, TlsClientConfig, TlsServerAuthenticatedAliases,
    TlsServerAuthentication,
};
use std::{slice, sync::Arc};

/// HTTPS origins that may share one HTTP/3 connection ([RFC 9114 §3.3]).
///
/// Insert it, shared through an `Arc`, on requests whose configured HTTP/3
/// [`HttpServiceCandidate`] targets a literal IP address. Such requests for any
/// of these origins share a connection to that same endpoint once its
/// certificate was verified for their host, under the same TLS policy and wire
/// preferences, as browsers coalesce origins that resolve to the same address.
/// Request authorities are unchanged. A connection that cannot be verified
/// serves only its own origin; a `421 Misdirected Request` retires it.
///
/// [RFC 9114 §3.3]: https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3
/// [`HttpServiceCandidate`]: rama_http_types::conn::HttpServiceCandidate
#[derive(Debug, PartialEq, Eq, Hash, Extension)]
#[extension(tags(http))]
pub struct Http3Coalescing {
    origins: Box<[HttpOrigin]>,
}

impl Http3Coalescing {
    /// Most origins one set may hold: each is checked against every new certificate.
    pub const MAX_ORIGINS: usize = 16;

    /// Create a set of 1 to [`Self::MAX_ORIGINS`] distinct HTTPS origins.
    ///
    /// Equal sets are equal regardless of order, so they share connections.
    pub fn try_new(origins: impl IntoIterator<Item = HttpOrigin>) -> Result<Self, BoxError> {
        let mut accepted = Vec::new();
        for origin in origins {
            if accepted.len() == Self::MAX_ORIGINS {
                return Err(BoxError::from_static_str(
                    "HTTP/3 coalescing origin limit exceeded",
                ));
            }
            if !origin.is_secure() {
                return Err(BoxError::from_static_str(
                    "HTTP/3 coalescing requires HTTPS origins",
                ));
            }
            if accepted.contains(&origin) {
                return Err(BoxError::from_static_str(
                    "HTTP/3 coalescing contains a duplicate origin",
                ));
            }
            accepted.push(origin);
        }
        if accepted.is_empty() {
            return Err(BoxError::from_static_str(
                "HTTP/3 coalescing requires an origin",
            ));
        }
        accepted.sort_unstable_by(|left, right| {
            let (left, right) = (left.authority(), right.authority());
            left.host
                .cmp(&right.host)
                .then_with(|| left.port.cmp(&right.port))
        });
        Ok(Self {
            origins: accepted.into_boxed_slice(),
        })
    }

    /// The origins, in canonical order.
    pub fn iter(&self) -> slice::Iter<'_, HttpOrigin> {
        self.origins.iter()
    }

    fn contains(&self, origin: &HttpOrigin) -> bool {
        self.origins.contains(origin)
    }
}

/// The coalescing set of a configured HTTP/3 selection to a literal IP endpoint.
fn configured(extensions: &Extensions) -> Option<(Arc<Http3Coalescing>, &SelectedHttpService)> {
    let group = extensions.get_arc::<Http3Coalescing>()?;
    let selected = extensions.get_ref::<SelectedHttpService>()?;
    let ConnectorTarget(target) = extensions.get_ref::<ConnectorTarget>()?;
    let candidate = &selected.candidate;
    (candidate.source == HttpServiceSource::Configured
        && candidate.protocol == ApplicationProtocol::HTTP_3
        && &candidate.target == target
        && matches!(target.host, Host::Address(_))
        && group.contains(&selected.origin))
    .then_some((group, selected))
}

/// The set whose origins share this input's pool identity, if any.
pub(crate) fn pool_group(input: &ConnectRequest) -> Option<Arc<Http3Coalescing>> {
    let (group, selected) = configured(input.extensions())?;
    (selected.origin.authority() == &input.authority
        && connection_version_requirement(input) == Some(Version::HTTP_3))
    .then_some(group)
}

/// Names to verify on a new connection's certificate once it is established.
#[derive(Debug)]
pub(super) struct PendingAliases {
    group: Arc<Http3Coalescing>,
    tls: TlsClientConfig,
}

impl PendingAliases {
    /// Only an opted-in connection authenticated as its own origin can vouch for others.
    pub(super) fn new(
        input: &ConnectRequest,
        tls: TlsClientConfig,
        authenticated: Option<&Host>,
    ) -> Option<Self> {
        let group = pool_group(input)?;
        (authenticated == Some(&input.authority.host)).then_some(Self { group, tls })
    }

    pub(super) fn verify(self, connection: &Connection, provider: &dyn QuicClientConfigProvider) {
        let extensions = connection.extensions();
        let Some(primary) = extensions
            .get_ref::<TlsServerAuthentication>()
            .and_then(|authentication| authentication.0.clone())
        else {
            return;
        };
        let Some(leaf) = extensions
            .get_ref::<NegotiatedTlsParameters>()
            .and_then(|tls| tls.peer_certificate_chain.as_deref())
            .and_then(|chain| chain.first())
        else {
            tracing::debug!("HTTP/3 coalescing: no peer certificate; serving own origin only");
            return;
        };
        let mut aliases = Vec::new();
        for origin in self.group.iter() {
            let name = &origin.authority().host;
            if name != &primary
                && !aliases.contains(name)
                && provider.peer_matches_name(self.tls.as_extensions(), leaf, name)
            {
                aliases.push(name.clone());
            }
        }
        extensions.insert(TlsServerAuthenticatedAliases::new(primary, aliases));
    }
}

/// Restrict a connection filed under a coalesced pool identity to the origins it
/// was verified for, or else its own; any QUIC connector's connections get this.
pub(crate) fn restrict_reuse(request: &Extensions, connection: &Extensions) {
    let Some((_, selected)) = configured(request) else {
        return;
    };
    let verified = connection
        .get_ref::<TlsServerAuthentication>()
        .zip(connection.get_arc::<TlsServerAuthenticatedAliases>())
        .filter(|(current, aliases)| current.0.as_ref() == Some(aliases.primary()));
    let scope = match verified {
        Some((_, aliases)) => Scope::Verified(aliases),
        None => Scope::Origin(selected.origin.clone()),
    };
    let restriction = ConnectionReuse::restriction(CoalescingReuse(Arc::new(scope)));
    connection.insert(match connection.get_ref::<ConnectionReuse>() {
        Some(reuse) => reuse.clone().and(restriction),
        None => restriction,
    });
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum Scope {
    Origin(HttpOrigin),
    Verified(Arc<TlsServerAuthenticatedAliases>),
}

#[derive(Debug)]
struct CoalescingReuse(Arc<Scope>);

impl ConnectionReusePolicy for CoalescingReuse {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::from_arc(self.0.clone())
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }

    // The pool identity already pins the set, endpoint, TLS policy and wire preferences.
    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        let selected = input.get_ref::<SelectedHttpService>()?;
        let permitted = match self.0.as_ref() {
            Scope::Origin(origin) => &selected.origin == origin,
            Scope::Verified(aliases) => aliases.covers(&selected.origin.authority().host),
        };
        permitted.then(ReuseKey::of::<Self>)
    }
}
