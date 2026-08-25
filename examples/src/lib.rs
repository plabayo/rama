//! Shared support for runnable Rama examples.

#[cfg(all(feature = "grpc", feature = "http-full"))]
pub mod http_grpc_job {
    pub mod common;
    pub mod jobs;
}
