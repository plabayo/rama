//! Admission for opt-in QUIC inspection and fixed-path association routing.
//!
//! A route is keyed by trusted ingress and peer addresses, never by a CID or
//! ClientHello field. CIDs cannot authorize a change of peer on an opaque path.

mod admission;
pub use admission::{
    Admission, AdmissionError, AdmissionLimits, AssociationKey, AssociationPermit,
};

mod router;
pub use router::{Decision, Inspection, QuicPeekRouter, RouteContext, Routed, RouterConfig};
mod socket;
pub use socket::{AssociationSender, AssociationSocket};

#[cfg(test)]
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
mod tests;
