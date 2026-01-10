//! A `rama-grpc` based gRPC healthcheck implementation.

use std::fmt::{Display, Formatter};

/// Generated protobuf types from the `grpc.health.v1` package.
pub mod pb {
    #![allow(rustdoc::bare_urls)]

    crate::include_proto!("grpc.health.v1");
}

pub mod server;

/// An enumeration of values representing gRPC service health.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ServingStatus {
    /// Unknown status
    Unknown,
    /// The service is currently up and serving requests.
    Serving,
    /// The service is currently down and not serving requests.
    NotServing,
}

impl Display for ServingStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("Unknown"),
            Self::Serving => f.write_str("Serving"),
            Self::NotServing => f.write_str("NotServing"),
        }
    }
}

impl From<ServingStatus> for self::pb::health_check_response::ServingStatus {
    fn from(s: ServingStatus) -> Self {
        match s {
            ServingStatus::Unknown => Self::Unknown,
            ServingStatus::Serving => Self::Serving,
            ServingStatus::NotServing => Self::NotServing,
        }
    }
}
