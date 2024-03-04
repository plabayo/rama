//! [`Stream`] trait and related utilities.

use tokio::io::{AsyncRead, AsyncWrite};

pub mod matcher;

pub mod layer;
pub mod service;

/// A stream is a type that implements `AsyncRead`, `AsyncWrite` and `Send`.
/// This is specific to Rama and is directly linked to the supertraits of `Tokio`.
pub trait Stream: AsyncRead + AsyncWrite + Send + Sync + 'static {}

impl<T> Stream for T where T: AsyncRead + AsyncWrite + Send + Sync + 'static {}

mod socket;
pub use socket::Socket;
