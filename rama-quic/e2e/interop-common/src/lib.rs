//! The interoperability scenarios each peer project runs, and the whole Rama side of them.
//!
//! A peer project depends on this by path, brings its own third-party QUIC implementation, and
//! writes an adapter that runs that implementation against the same parameters. What a scenario
//! asserts lives here, so every peer is held to the same expectations; what the peer read comes
//! back through its adapter.

pub mod datagram;
pub mod identity;
pub mod registry;
pub mod scenario;
pub mod support;
pub mod trust;

pub use datagram::{DatagramObservation, DatagramScenario, datagram_cases};
pub use identity::{ALPN, Identity, alpn, rama_client_config, rama_server_config, server_identity};
pub use registry::{Case, CaseRun, Role, Unsupported, for_each_case, stream_cases};
pub use scenario::{Chunk, PeerObservation, Received, SERVER_NAME, StreamScenario};
pub use support::{Deadline, Peer, digest, localhost, payload};
pub use trust::{TrustObservation, TrustScenario, trust_cases};
