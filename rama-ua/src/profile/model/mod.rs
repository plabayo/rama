//! Client identity, flow context and configuration-based profile models.
//!
//! [`ProfileKey`](crate::profile::model::identity::ProfileKey) identifies a client; [`FlowKey`](crate::profile::model::identity::FlowKey) and [`ConnectionContext`](crate::profile::model::identity::ConnectionContext)
//! describe where an observation applies. [`UserAgentProfile`](crate::profile::model::ua::UserAgentProfile) is the catalogue
//! entry shared by configuration-based profiles and analyzed captures.

pub mod identity;

pub mod time;

pub mod scope;

pub mod ua;

pub mod http;

pub mod js;
#[cfg(feature = "tls")]
pub mod tls;

pub mod runtime_hints;
