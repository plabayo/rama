//! User Agent (UA) Profiles, mostly used for emulation.
//!
//! See [`UserAgentProfile`] for the main profile type and
//! [`UserAgentEmulateService`] for the service that triggers the emulation.
//!
//! This module contains the profiles for the User Agent (UA) that are used for emulation.
//!
//! Learn more about User Agents (UA) and why Rama supports it
//! at <https://ramaproxy.org/book/intro/user_agent.html>.
//!
//! [`UserAgentProfile`]: crate::profile::UserAgentProfile
//! [`UserAgentEmulateService`]: crate::layer::emulate::UserAgentEmulateService

mod http;
pub use http::*;

#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub use tls::*;

mod js;
pub use js::*;

mod ua;
pub use ua::*;

mod db;
pub use db::*;

mod runtime_hints;
pub use runtime_hints::*;

mod input;
pub use input::*;

mod canonical;
pub use canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId};

mod header_structure;

mod completeness;
pub use completeness::ProfileCaptureCompleteness;

mod capture;
pub use capture::*;

mod identity;
pub use identity::*;

mod time;
pub use time::*;

mod ingestion;
pub use ingestion::*;

mod reservoir;
pub use reservoir::*;

mod distinct;
pub use distinct::{UntrackedDistinctCount, UntrackedDistinctSnapshot};

mod counts;
pub use counts::*;

mod bucket;
pub use bucket::*;

mod window;
pub use window::*;

mod order_capture;
pub use order_capture::*;

mod joint;
pub use joint::*;

mod transaction;
pub use transaction::*;

mod scope;
pub use scope::*;

mod record;
pub use record::*;

#[cfg(feature = "tls")]
mod tls_capture;
#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub use tls_capture::*;

mod runtime_capture;
pub use runtime_capture::*;

mod pseudo_capture;
pub use pseudo_capture::*;

mod h2_capture;
pub use h2_capture::*;

mod quic_flight_capture;
pub use quic_flight_capture::*;

mod h3_sequence_capture;
pub use h3_sequence_capture::*;

mod analysis;
pub use analysis::*;

mod archive;
pub use archive::*;

mod evidence;
pub use evidence::ProfileEvidenceCollector;

mod selection;
pub use selection::*;

mod legacy;
pub use legacy::{
    LegacyField, LegacyFieldCapture, LegacyFieldValue, LegacyHeaderCapture, LegacyHttpProtocol,
};

mod compare;
pub use compare::*;
