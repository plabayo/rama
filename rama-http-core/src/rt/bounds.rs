//! Trait aliases
//!
//! Traits in this module ease setting bounds and usually automatically
//! implemented by implementing another trait.

pub use self::h2::Http2ServerConnExec;
pub use self::h2_client::Http2ClientConnExec;

mod h2_client {
    use rama_core::rt::Executor;
    use rama_http_types::dep::http_body;
    use std::{error::Error, future::Future};

    use crate::proto::h2::client::H2ClientFuture;
    use crate::rt::{Read, Write};

    /// An executor to spawn http2 futures for the client.
    ///
    /// This trait is implemented for any type that implements [`Executor`]
    /// trait for any future.
    ///
    /// This trait is sealed and cannot be implemented for types outside this crate.
    ///
    /// [`Executor`]: crate::rt::Executor
    pub trait Http2ClientConnExec<B, T>: sealed_client::Sealed<(B, T)>
    where
        B: http_body::Body,
        B::Error: Into<BoxError>,
        T: Read + Write + Unpin,
    {
        #[doc(hidden)]
        fn execute_h2_future(&mut self, future: H2ClientFuture<B, T>);
    }

    impl<B, T> Http2ClientConnExec<B, T> for Executor
    where
        B: http_body::Body + 'static,
        B::Error: Into<BoxError>,
        H2ClientFuture<B, T>: Future<Output = ()>,
        T: Read + Write + Unpin,
    {
        fn execute_h2_future(&mut self, future: H2ClientFuture<B, T>) {
            self.spawn_task(future)
        }
    }

    impl<B, T> sealed_client::Sealed<(B, T)> for Executor
    where
        B: http_body::Body + 'static,
        B::Error: Into<BoxError>,
        H2ClientFuture<B, T>: Future<Output = ()>,
        T: Read + Write + Unpin,
    {
    }

    mod sealed_client {
        pub trait Sealed<X> {}
    }
}

mod h2 {
    use crate::proto::h2::server::H2Stream;
    use rama_core::rt::Executor;
    use rama_http_types::dep::http_body::Body;
    use std::future::Future;

    /// An executor to spawn http2 connections.
    ///
    /// This trait is implemented for any type that implements [`Executor`]
    /// trait for any future.
    ///
    /// This trait is sealed and cannot be implemented for types outside this crate.
    ///
    /// [`Executor`]: crate::rt::Executor
    pub trait Http2ServerConnExec<F, B: Body>: sealed::Sealed<(F, B)> + Clone {
        #[doc(hidden)]
        fn execute_h2stream(&mut self, fut: H2Stream<F, B>);
    }

    #[doc(hidden)]
    impl<F, B> Http2ServerConnExec<F, B> for Executor
    where
        H2Stream<F, B>: Future<Output = ()>,
        B: Body + Send + Sync + 'static,
    {
        fn execute_h2stream(&mut self, fut: H2Stream<F, B>) {
            let _ = self.spawn_task(fut);
        }
    }

    impl<F, B> sealed::Sealed<(F, B)> for Executor
    where
        H2Stream<F, B>: Future<Output = ()>,
        B: Body,
    {
    }

    mod sealed {
        pub trait Sealed<T> {}
    }
}
