//! Utilities for using rama services with rama-grpc.

pub(crate) mod layered;

#[doc(inline)]
pub use self::layered::{LayerExt, Layered};

mod recover_error;
pub use self::recover_error::{RecoverError, RecoverErrorLayer};

mod grpc_timeout;
pub use self::grpc_timeout::{GrpcTimeout, GrpcTimeoutLayer};

#[cfg(feature = "protobuf")]
pub mod health;

mod router;
pub use router::GrpcRouter;

pub mod interceptor;
