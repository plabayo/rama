//! Per-connection, two-stage client authentication for the MITM relay.
//!
//! A policy selects a plan from the upstream request and flow extensions. The
//! plan configures ingress TLS, then resolves an egress credential only after
//! the complete ingress handshake. Use ordinary Rama services/layers for lookup,
//! matching, fallback and admission; the relay does not own credential storage.

#![doc = include_str!("client_auth/README.md")]

use rama_boring::{
    ssl::{CertificateSelection, SslCredential, SslRef, SslSignatureAlgorithm},
    x509::X509,
};
use rama_core::{
    Service,
    error::BoxError,
    extensions::{Extension, Extensions},
    layer::MapErr,
    service::{BoxService, service_fn},
};
use rama_net::address::Host;
use std::{convert::Infallible, fmt};

/// Owned upstream CertificateRequest hints, not trust anchors or proof of identity.
#[derive(Debug, Clone)]
pub struct TlsMitmCertificateRequest {
    pub signature_algorithms: Vec<SslSignatureAlgorithm>,
    pub certificate_types: Vec<u8>,
    /// DER-encoded distinguished names, in wire order.
    pub certificate_authorities: Vec<Vec<u8>>,
}

impl TlsMitmCertificateRequest {
    pub(super) fn from_selection(selection: &CertificateSelection<'_>) -> Self {
        Self {
            signature_algorithms: selection.peer_verify_algorithms().to_vec(),
            certificate_types: selection.certificate_types().to_vec(),
            certificate_authorities: selection.requested_ca_names().map(<[u8]>::to_vec).collect(),
        }
    }
}

/// Input to the first stage. `None` still permits independent ingress admission.
#[derive(Debug, Clone)]
pub struct TlsMitmClientAuthInput {
    pub request: Option<TlsMitmCertificateRequest>,
    pub extensions: Extensions,
    pub server_name: Option<Host>,
    /// The upstream certificate, subject to the configured egress verification policy.
    pub server_certificate: X509,
}

/// Ingress TLS authentication completed, including proof of private-key possession.
/// The configured ingress verifier defines which identities are trusted.
#[derive(Debug)]
pub struct TlsMitmClientIdentity {
    chain: Vec<X509>,
}

impl TlsMitmClientIdentity {
    /// Leaf first. Empty when the ingress client did not authenticate.
    pub fn certificate_chain(&self) -> &[X509] {
        &self.chain
    }

    pub fn leaf(&self) -> Option<&X509> {
        self.chain.first()
    }

    pub(super) fn from_completed_handshake(ssl: &SslRef) -> Self {
        // Server-side peer_cert_chain excludes the leaf.
        let mut chain = Vec::new();
        if let Some(leaf) = ssl.peer_certificate() {
            chain.push(leaf);
            if let Some(rest) = ssl.peer_cert_chain() {
                chain.extend(rest.iter().map(ToOwned::to_owned));
            }
        }
        Self { chain }
    }
}

type ConfigureIngress = Box<dyn FnOnce(&mut SslRef) -> Result<(), BoxError> + Send>;

/// Second stage: configure ingress, then resolve the egress credential.
/// Returning `None` deliberately sends no certificate, which only optional
/// upstream authentication can accept. Errors reject the connection.
/// A credential returned when upstream requested none is rejected as a policy error.
pub struct TlsMitmClientAuthPlan {
    pub(super) configure: Option<ConfigureIngress>,
    pub(super) resolve: BoxService<TlsMitmClientIdentity, Option<SslCredential>, BoxError>,
}

impl fmt::Debug for TlsMitmClientAuthPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsMitmClientAuthPlan")
            .field("configures_ingress", &self.configure.is_some())
            .finish_non_exhaustive()
    }
}

impl TlsMitmClientAuthPlan {
    /// By default, ingress does not request a certificate.
    pub fn new<S>(resolver: S) -> Self
    where
        S: Service<TlsMitmClientIdentity, Output = Option<SslCredential>, Error: Into<BoxError>>,
    {
        Self {
            configure: None,
            resolve: MapErr::new(resolver, Into::into).boxed(),
        }
    }

    /// Fixed egress identity, without requiring ingress authentication.
    pub fn fixed(credential: Option<SslCredential>) -> Self {
        Self::new(service_fn(move |_: TlsMitmClientIdentity| {
            let credential = credential.clone();
            async move { Ok::<_, Infallible>(credential) }
        }))
    }

    /// Require a client certificate trusted by this prebuilt store. The store is
    /// reference-counted by BoringSSL, so callers can cheaply clone and reuse it.
    #[must_use]
    pub fn with_ingress_trust(self, store: rama_boring::x509::store::X509Store) -> Self {
        self.with_ingress(move |ssl| {
            ssl.set_verify_cert_store(store)?;
            ssl.set_verify(
                rama_boring::ssl::SslVerifyMode::PEER
                    | rama_boring::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            );
            Ok(())
        })
    }

    /// Configure native ingress authentication on this connection, after routing
    /// and before its handshake. Set verification mode, trust, CA hints and any
    /// custom verifier here. Calls compose in order. Never mutate a shared cached
    /// acceptor for flow policy.
    #[must_use]
    pub fn with_ingress<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(&mut SslRef) -> Result<(), BoxError> + Send + 'static,
    {
        let previous = self.configure;
        self.configure = Some(Box::new(move |ssl| {
            if let Some(previous) = previous {
                previous(ssl)?;
            }
            configure(ssl)
        }));
        self
    }
}

/// An opt-in policy. A flow extension overrides the relay's default policy.
/// Absent a policy, upstream client-certificate requests are rejected.
/// Policies use existing Rama services, including their usual layers/combinators.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsMitmClientAuthPolicy(
    pub(super) BoxService<TlsMitmClientAuthInput, TlsMitmClientAuthPlan, BoxError>,
);

impl TlsMitmClientAuthPolicy {
    pub fn new<S>(service: S) -> Self
    where
        S: Service<TlsMitmClientAuthInput, Output = TlsMitmClientAuthPlan, Error: Into<BoxError>>,
    {
        Self(MapErr::new(service, Into::into).boxed())
    }

    /// Use a prebuilt credential whenever upstream requests one. No ingress mTLS.
    pub fn fixed(credential: SslCredential) -> Self {
        Self::new(service_fn(move |input: TlsMitmClientAuthInput| {
            let credential = input.request.is_some().then(|| credential.clone());
            async move { Ok::<_, Infallible>(TlsMitmClientAuthPlan::fixed(credential)) }
        }))
    }
}

impl TryFrom<rama_tls::client::ClientAuth> for TlsMitmClientAuthPolicy {
    type Error = BoxError;

    fn try_from(auth: rama_tls::client::ClientAuth) -> Result<Self, Self::Error> {
        let credential = crate::client::ConnectorConfigClientAuth::try_from(auth)?.try_into()?;
        Ok(Self::fixed(credential))
    }
}

#[cfg(test)]
mod tests;
