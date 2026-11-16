//! Typed observations of client traffic, before counting or inference.
//!
//! Protocol captures retain ordered fields and capture completeness. Request-owned
//! values are represented by bindings rather than reusable literals. A
//! [`JointCapture`](crate::profile::capture::joint::JointCapture) preserves components observed together; [`ProfileCapture`](crate::profile::capture::observation::ProfileCapture)
//! attaches client, flow and connection identity before ingestion.
//!
//! Capturing a component does not imply that a replay provider can reproduce it.

pub mod completeness;

pub mod headers;

pub mod pseudo_headers;

pub mod http2;

pub mod http3;

pub mod quic;
#[cfg(feature = "tls")]
pub mod tls;

pub mod order;

pub(in crate::profile) mod reserved;

pub mod runtime;

pub mod joint;

pub mod observation;

/// Revision of what captures retain. Bump it when a capture keeps data that
/// earlier captures dropped, so exports never mix the two within a profile.
/// Revision 1 keeps TLS trust anchor identifiers.
/// Matched ECH pairs also use revision 1: they add a distinct joint slot without
/// changing baseline fields, so exports retain existing request-flow evidence.
/// Absence of a matched pair means real ECH was not observed, not that the
/// client lacks ECH support. Neither the revision nor a GREASE ECH extension
/// establishes acceptance or supplies a denominator for ECH success rates.
pub const CAPTURE_REVISION: u16 = 1;
