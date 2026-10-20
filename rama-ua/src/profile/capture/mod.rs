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

pub mod runtime;

pub mod joint;

pub mod observation;
