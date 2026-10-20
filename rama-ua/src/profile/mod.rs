//! Client observations, retained evidence and user-agent emulation profiles.
//!
//! The lifecycle is: capture traffic, retain counted evidence, analyze it, select
//! correlated variants, then prepare them for replay. Each stage has a different
//! contract; observed protocol support does not guarantee exact replay support.
//!
//! - [`ProfileCapture`](crate::profile::capture::observation::ProfileCapture) binds typed protocol observations to a client and flow.
//! - [`ProfileEvidenceCollector`](crate::profile::evidence::collector::ProfileEvidenceCollector) retains bounded counts and samples.
//! - [`ProfileEvidence`](crate::profile::evidence::ProfileEvidence) is the input to [`analyze_profile_evidence`](crate::profile::analysis::profile::analyze_profile_evidence).
//! - [`AnalyzedProfile`](crate::profile::analysis::profile::AnalyzedProfile) describes retained variants and inferred distributions.
//! - [`UserAgentDatabase`](crate::profile::selection::database::UserAgentDatabase) indexes profiles for selection.
//! - [`EmulationContext`](crate::profile::selection::variants::EmulationContext) carries deterministic connection and request draws.
//! - [`ProfilePreservationReport`](crate::profile::replay::request::ProfilePreservationReport) records where replay deviated from its capture.
//!
//! [`CanonicalValue`](crate::profile::format::canonical::CanonicalValue) provides versioned bytes and stable identities for storage.
//! Archive loaders validate retained evidence and recompute analysis; diagnostic
//! JSON is a presentation of that data, not its canonical identity.
//!
//! Legacy profile rows are converted into the same captured form when loaded.
//! [`ProfileEmulateLayer`](crate::layer::emulate::ProfileEmulateLayer) applies
//! selected profiles to traffic.

pub mod model;

pub mod capture;

pub mod evidence;

pub mod analysis;

pub mod selection;

pub mod replay;

pub mod format;

pub mod compare;
