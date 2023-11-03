use tokio::io::{AsyncRead, AsyncWrite};

pub trait Stream: AsyncRead + AsyncWrite {}

impl<T> Stream for T where T: AsyncRead + AsyncWrite {}
