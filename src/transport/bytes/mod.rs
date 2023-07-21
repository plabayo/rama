//! Functions and types for byte oriented transports (e.g. TCP).

use tokio::io::{AsyncRead, AsyncWrite};

pub mod service;

/// A byte oriented stream.
pub trait ByteStream: AsyncRead + AsyncWrite {}
impl<T> ByteStream for T where T: AsyncRead + AsyncWrite {}
