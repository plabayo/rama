//! QUIC interception: inspect an association's Initial flight, then forward it untouched or
//! terminate it and relay the established connections.

mod admission;
pub use admission::{
    AdmissionError, AdmissionStats, AssociationKey, AssociationLimits, AssociationPermit,
    QuicAdmissionLayer, QuicAdmissionService, QuicAssociationAdmission,
};

mod peek;
pub use peek::{
    DEFAULT_QUIC_PEEK_LIMITS, DEFAULT_QUIC_PEEK_TIMEOUT, InputWithQuicClientHello,
    NoQuicPeekRouting, NoQuicRejectError, PeekQuicClientHelloService, QuicPeekFallbackPolicy,
    QuicPeekRejectedError, QuicPeekRejection, QuicPeekRoute, QuicPeekRouter,
};

mod relay;
pub use relay::QuicRelay;

#[cfg(feature = "boring")]
mod mitm;
#[cfg(feature = "boring")]
pub use mitm::{
    DEFAULT_QUIC_MITM_HANDSHAKE_TIMEOUT, QuicMirrorCeiling, QuicMitmIngress,
    QuicMitmIngressByIdentity, QuicMitmIngressByIdentityConfig, QuicMitmIngressConfig,
    QuicMitmRelay, QuicMitmRelayService, QuicMitmRoute,
};

mod migration;
pub use migration::{
    QuicEgressMigration, QuicMigrationConfig, QuicMigrationDecision, QuicMigrationFailureAction,
    QuicMigrationInput, QuicMigrationLayer, QuicMigrationService, QuicMigrationSide,
    QuicMigrationTrigger, QuicNetworkAvailability, QuicNetworkChanges, QuicNetworkPath,
    QuicNetworkSnapshot, QuicPathAction, QuicTransportReplacement,
};
