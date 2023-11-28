#![feature(return_type_notation)]
#![allow(incomplete_features)]

pub mod rt;

pub mod service;
pub mod state;

pub mod stream;

pub mod tcp;

pub mod http;
pub mod tls;

#[allow(unreachable_pub)]
mod sealed {
    pub trait Sealed<T> {}
}

/// Alias for a type-erased error type.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
