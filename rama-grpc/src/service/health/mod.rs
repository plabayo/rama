//! A `rama-grpc` based gRPC healthcheck implementation.

use std::fmt::{Display, Formatter};

mod generated {
    #![allow(unreachable_pub)]
    #![allow(missing_docs)]

    // #[rustfmt::skip]
    // pub mod grpc_health_v1; // TODO: no clinet for now in rama_grpc

    #[rustfmt::skip]
    mod grpc_health_v1_fds;

    pub use grpc_health_v1_fds::FILE_DESCRIPTOR_SET;

    #[cfg(test)]
    mod tests {
        use super::FILE_DESCRIPTOR_SET;
        use crate::protobuf::prost::Message as _;

        #[test]
        fn file_descriptor_set_is_valid() {
            crate::protobuf::prost::types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
        }
    }
}

/// Generated protobuf types from the `grpc.health.v1` package.
pub mod pb {
    pub use super::generated::{FILE_DESCRIPTOR_SET /* TODO, grpc_health_v1::* */};
}

// TOOD [fix impl async traits (codegen) + what to do with client...]
// pub mod server;

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

// TODO

// impl From<ServingStatus> for pb::health_check_response::ServingStatus {
//     fn from(s: ServingStatus) -> Self {
//         match s {
//             ServingStatus::Unknown => pb::health_check_response::ServingStatus::Unknown,
//             ServingStatus::Serving => pb::health_check_response::ServingStatus::Serving,
//             ServingStatus::NotServing => pb::health_check_response::ServingStatus::NotServing,
//         }
//     }
// }
