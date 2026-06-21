use pin_project_lite::pin_project;
use rama_core::{extensions::Extensions, extensions::ExtensionsRef};
pub use tokio::net::UnixStream as TokioUnixStream;

pin_project! {
    #[derive(Debug)]
    /// A stream which can be either a secure or a plain stream.
    pub struct UnixStream {
        #[pin]
        pub stream: TokioUnixStream,
        pub extensions: Extensions
    }
}

impl UnixStream {
    pub fn new(stream: TokioUnixStream) -> Self {
        Self {
            stream,
            extensions: Extensions::new(),
        }
    }
}

impl From<TokioUnixStream> for UnixStream {
    fn from(value: TokioUnixStream) -> Self {
        Self::new(value)
    }
}

impl From<UnixStream> for TokioUnixStream {
    fn from(value: UnixStream) -> Self {
        value.stream
    }
}

impl ExtensionsRef for UnixStream {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

rama_net::stream::rama_delegate_async_read_write!(UnixStream => stream);
