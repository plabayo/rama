//! Logical HTTP origins, service candidates and connection-selection metadata.
//!
//! Discovery supplies immutable candidates. A connector selects one before
//! pooling and records the established service only after validating the peer.
//! These types do not impose Alt-Svc or DNS freshness and retry rules.

use std::sync::Arc;

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extension,
};
use rama_net::{
    Protocol,
    address::{Host, HostWithPort},
    tls::ApplicationProtocol,
};

/// An HTTP origin, including its scheme and effective port.
///
/// Alternative services change the dial target, never this authentication and
/// request identity. HTTP and HTTPS origins remain distinct even at the same port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpOrigin {
    protocol: Protocol,
    authority: HostWithPort,
}

impl HttpOrigin {
    /// Validate an HTTP(S) scheme and network-usable origin authority.
    pub fn new(protocol: Protocol, authority: HostWithPort) -> Result<Self, BoxError> {
        if protocol != Protocol::HTTP && protocol != Protocol::HTTPS {
            return Err(BoxError::from_static_str(
                "HTTP service origin requires HTTP or HTTPS",
            ));
        }
        if authority.port == 0 {
            return Err(BoxError::from_static_str(
                "HTTP service origin requires a nonzero port",
            ));
        }
        let host = if let Ok(ip) = authority.host.try_as_ip() {
            Host::from(ip)
        } else {
            Host::from(authority.host.try_into_domain()?)
        };
        Ok(Self {
            protocol,
            authority: HostWithPort::new(host.canonicalize(), authority.port),
        })
    }

    /// Logical HTTP scheme.
    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    /// Logical host and effective port, independently of the dial target.
    pub fn authority(&self) -> &HostWithPort {
        &self.authority
    }

    /// Whether the logical origin uses HTTPS.
    pub fn is_secure(&self) -> bool {
        self.protocol == Protocol::HTTPS
    }
}

/// Where a service candidate was learned.
///
/// Discovery sources have different authorization, freshness and request-header
/// rules. Merely selecting an endpoint must not turn it into an Alt-Svc hint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HttpServiceSource {
    /// Explicit application configuration, independent of response advertisements.
    #[default]
    Configured,
    /// An HTTP Alt-Svc advertisement.
    AltSvc,
}

/// A protocol and endpoint offered for a logical HTTP origin.
///
/// The protocol identifies the required negotiated application protocol; it is
/// not permission to downgrade the request or skip origin authentication.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpServiceCandidate {
    protocol: ApplicationProtocol,
    target: HostWithPort,
    source: HttpServiceSource,
}

impl HttpServiceCandidate {
    /// Describe an endpoint and the protocol it must provide.
    pub fn new(protocol: ApplicationProtocol, target: HostWithPort) -> Self {
        Self {
            protocol,
            target: target.canonicalize(),
            source: HttpServiceSource::Configured,
        }
    }

    /// Record the discovery mechanism whose policies apply to this candidate.
    #[must_use]
    pub fn with_source(mut self, source: HttpServiceSource) -> Self {
        self.source = source;
        self
    }

    /// Discovery mechanism, preserved in selection and establishment metadata.
    pub fn source(&self) -> HttpServiceSource {
        self.source
    }

    /// Required application protocol.
    pub fn protocol(&self) -> &ApplicationProtocol {
        &self.protocol
    }

    /// Physical endpoint, independently of the logical origin.
    pub fn target(&self) -> &HostWithPort {
        &self.target
    }
}

/// An immutable, ordered discovery snapshot for one origin.
///
/// Cloning shares the collection. Discovery-specific freshness and availability
/// remain with the source; inspect those before trying a cached candidate.
#[derive(Clone, Debug, Extension)]
#[extension(tags(http))]
pub struct HttpServiceCandidates {
    origin: HttpOrigin,
    candidates: Arc<[HttpServiceCandidate]>,
}

impl HttpServiceCandidates {
    /// Create a new discovery snapshot in preference order.
    pub fn new(origin: HttpOrigin, candidates: impl Into<Arc<[HttpServiceCandidate]>>) -> Self {
        Self {
            origin,
            candidates: candidates.into(),
        }
    }

    /// The origin all candidates serve.
    pub fn origin(&self) -> &HttpOrigin {
        &self.origin
    }

    /// Candidates in source preference order.
    pub fn iter(&self) -> std::slice::Iter<'_, HttpServiceCandidate> {
        self.candidates.iter()
    }

    /// Candidate at the given stable snapshot index.
    pub fn get(&self, index: usize) -> Option<&HttpServiceCandidate> {
        self.candidates.get(index)
    }

    /// Number of advertised candidates, including any since expired or suppressed.
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Whether this snapshot has no candidates.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Whether both handles refer to the same origin and discovery snapshot.
    ///
    /// This compares ephemeral advertisement identity, not candidate equality.
    /// A delayed failure must not suppress a newer advertisement of the same
    /// endpoint. It is not a connection-pool or authentication identity.
    pub fn same_advertisement(&self, other: &Self) -> bool {
        self.origin == other.origin && Arc::ptr_eq(&self.candidates, &other.candidates)
    }
}

/// One candidate selected for an isolated connection attempt.
#[derive(Clone, Debug, Extension)]
#[extension(tags(http))]
pub struct SelectedHttpService {
    origin: HttpOrigin,
    candidate: HttpServiceCandidate,
}

impl SelectedHttpService {
    /// Record a decision before connection establishment.
    pub fn new(origin: HttpOrigin, candidate: HttpServiceCandidate) -> Self {
        Self { origin, candidate }
    }

    /// Original request and authentication identity.
    pub fn origin(&self) -> &HttpOrigin {
        &self.origin
    }

    /// Endpoint and protocol selected for this attempt.
    pub fn candidate(&self) -> &HttpServiceCandidate {
        &self.candidate
    }
}

/// An alternative whose protocol and origin authorization were verified.
///
/// Publish only after successful establishment, and retain on pool reuse. A
/// selected candidate alone is not evidence that this service was established.
/// For HTTP origins, authorization includes RFC 8164's additional requirements;
/// a TLS handshake alone is insufficient.
#[derive(Clone, Debug, Extension)]
#[extension(tags(http))]
pub struct EstablishedHttpService {
    origin: HttpOrigin,
    candidate: HttpServiceCandidate,
}

impl EstablishedHttpService {
    /// Record an alternative after validating protocol and origin authorization.
    pub fn new(origin: HttpOrigin, candidate: HttpServiceCandidate) -> Self {
        Self { origin, candidate }
    }

    /// Original request and authenticated origin identity.
    pub fn origin(&self) -> &HttpOrigin {
        &self.origin
    }

    /// Verified protocol and connected endpoint.
    pub fn candidate(&self) -> &HttpServiceCandidate {
        &self.candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_canonicalize_hosts_and_preserve_scheme_and_port() {
        let origin = |protocol, authority: &str| {
            HttpOrigin::new(protocol, authority.parse().unwrap()).unwrap()
        };
        let https = origin(Protocol::HTTPS, "EXAMPLE.com:443");
        assert_eq!(https, origin(Protocol::HTTPS, "example.com:443"));
        assert_ne!(https, origin(Protocol::HTTP, "example.com:443"));
        assert_ne!(https, origin(Protocol::HTTPS, "example.com:8443"));
        HttpOrigin::new(Protocol::WS, "example.com:21".parse().unwrap()).unwrap_err();
        HttpOrigin::new(Protocol::HTTPS, "example.com:0".parse().unwrap()).unwrap_err();
        HttpOrigin::new(Protocol::HTTPS, "[v1.a]:443".parse().unwrap()).unwrap_err();
    }

    #[test]
    fn provenance_survives_selection_and_establishment() {
        let origin = HttpOrigin::new(Protocol::HTTPS, "example.com:443".parse().unwrap()).unwrap();
        let configured = HttpServiceCandidate::new(
            ApplicationProtocol::HTTP_2,
            "alt.example:8443".parse().unwrap(),
        );
        assert_eq!(configured.source(), HttpServiceSource::Configured);
        let advertised = configured.with_source(HttpServiceSource::AltSvc);
        let selected = SelectedHttpService::new(origin.clone(), advertised.clone());
        let established = EstablishedHttpService::new(origin, advertised);
        assert_eq!(selected.candidate().source(), HttpServiceSource::AltSvc);
        assert_eq!(established.candidate().source(), HttpServiceSource::AltSvc);
    }

    #[test]
    fn snapshots_share_storage_but_new_advertisements_have_new_identity() {
        let origin = HttpOrigin::new(Protocol::HTTPS, "example.com:443".parse().unwrap()).unwrap();
        let candidate = HttpServiceCandidate::new(
            ApplicationProtocol::HTTP_2,
            "alt.example:8443".parse().unwrap(),
        );
        let first = HttpServiceCandidates::new(origin.clone(), vec![candidate.clone()]);
        assert!(first.same_advertisement(&first.clone()));
        let replacement = HttpServiceCandidates::new(origin, vec![candidate]);
        assert!(!first.same_advertisement(&replacement));
        assert_eq!(first.get(0), replacement.get(0));
    }
}
