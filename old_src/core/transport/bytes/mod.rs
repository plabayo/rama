use tokio::io::{AsyncRead, AsyncWrite};

pub mod service;

pub trait ByteStream: AsyncRead + AsyncWrite + Send {}
impl<T> ByteStream for T where T: AsyncRead + AsyncWrite + Send {}
