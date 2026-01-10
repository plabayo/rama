//! A collection of useful protobuf types that can be used with `rama-grpc`.
//!
//! This crate also introduces the [`StatusExt`] trait and implements it in
//! [`crate::Status`], allowing the implementation of the
//! [gRPC Richer Error Model] with `rama-grpc` in a convenient way.
//!
//! # Usage
//!
//! Useful protobuf types are available through the [`pb`] module. They can be
//! imported and worked with directly.
//!
//! The [`StatusExt`] trait adds associated functions to [`crate::Status`] that
//! can be used on the server side to create a status with error details, which
//! can then be returned to gRPC clients. Moreover, the trait also adds methods
//! to [`crate::Status`] that can be used by a rama-grpc client to extract error
//! details, and handle them with ease.
//!
//! # Working with different error message types
//!
//! Multiple examples are provided at the [`ErrorDetails`] doc. Instructions
//! about how to use the fields of the standard error message types correctly
//! are provided at [error_details.proto].
//!
//! # Alternative [`crate::Status`] associated functions and methods
//!
//! In the [`StatusExt`] doc, an alternative way of interacting with
//! [`crate::Status`] is presented, using vectors of error details structs
//! wrapped with the [`ErrorDetail`] enum. This approach can provide more
//! control over the vector of standard error messages that will be generated or
//! that was received, if necessary. To see how to adopt this approach, please
//! check the [`StatusExt::try_with_error_details_vec`] and
//! [`StatusExt::get_error_details_vec`] docs.
//!
//! Besides that, multiple examples with alternative error details extraction
//! methods are provided in the [`StatusExt`] doc, which can be specially
//! useful if only one type of standard error message is being handled by the
//! client. For example, using [`StatusExt::get_details_bad_request`] is a
//! more direct way of extracting a [`BadRequest`] error message from
//! [`crate::Status`].
//!
//! [gRPC Richer Error Model]: https://www.grpc.io/docs/guides/error/
//! [error_details.proto]: https://github.com/googleapis/googleapis/blob/master/google/rpc/error_details.proto

mod generated {
    #![allow(unreachable_pub)]
    #![allow(rustdoc::invalid_html_tags)]
    #[rustfmt::skip]
    pub mod google_rpc;
    #[rustfmt::skip]
    pub mod types_fds;

    pub use types_fds::FILE_DESCRIPTOR_SET;

    #[cfg(test)]
    mod tests {
        use super::FILE_DESCRIPTOR_SET;
        use prost::Message as _;

        #[test]
        fn file_descriptor_set_is_valid() {
            prost_types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
        }
    }
}

/// Useful protobuf types
pub mod pb {
    pub use super::generated::{FILE_DESCRIPTOR_SET, google_rpc::*};
}

pub use pb::Status;

mod richer_error;

pub use richer_error::{
    BadRequest, DebugInfo, ErrorDetail, ErrorDetails, ErrorInfo, FieldViolation, Help, HelpLink,
    LocalizedMessage, PreconditionFailure, PreconditionViolation, QuotaFailure, QuotaViolation,
    RequestInfo, ResourceInfo, RetryInfo, RpcStatusExt, StatusExt,
};

mod sealed {
    pub trait Sealed {}
}
