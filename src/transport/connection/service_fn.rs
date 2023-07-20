use std::future::Future;

use tower_async::Service;

use super::Connection;

/// Returns a new [`ServiceFn`] with the given closure,
///
/// This allows you to serve a [`Connection`] with the ease of writing a function or closure,
/// or put differently it builds a [`tower_async::Service`] from an async function that
/// that serves a [`Connection`] and returns the `Result` of the function.
///
/// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
///
/// # Examples
///
/// An example for a service function which only consumes the stream of the connection:
///
/// ```
/// use rama::transport::connection::service_fn;
/// # use rama::transport::connection::Connection;
/// # use rama::transport::graceful::Token;
/// use tower_async::Service;
/// use std::convert::Infallible;
///
/// # struct Stream(String);
/// #
/// # impl Stream {
/// #    fn read_all(self) -> String {
/// #       self.0
/// #    }
/// # }
/// # #[tokio::main]
/// # async fn main() -> Result<(), Infallible> {
/// async fn echo(input: Stream) -> Result<String, Infallible> {
///     Ok(input.read_all())
/// }
///
/// let mut service = service_fn(echo);
///
/// # let conn = Connection::new(Stream("Hello, World!".to_string()), Token::pending(), ());
/// let response = service
///     .call(conn)
///     .await?;
///
/// assert_eq!("Hello, World!", response);
/// #
/// # Ok(())
/// # }
/// ```
///
/// An example for a service function which consumes the both
/// the stream and the state of the connection:
///
/// ```
/// use rama::transport::connection::service_fn;
/// # use rama::transport::connection::Connection;
/// # use rama::transport::graceful::Token;
/// use tower_async::Service;
/// use std::convert::Infallible;
///
/// pub struct State {
///     lower: bool,
/// }
///
/// # struct Stream(String);
/// #
/// # impl Stream {
/// #    fn read_all(self) -> String {
/// #       self.0
/// #    }
/// # }
/// # #[tokio::main]
/// # async fn main() -> Result<(), Infallible> {
/// async fn echo(input: Stream, state: State) -> Result<String, Infallible> {
///     let s = input.read_all();
///     if state.lower {
///          Ok(s.to_lowercase())
///      } else {
///         Ok(s)
///     }
/// }
///
/// let mut service = service_fn(echo);
///
/// # let conn = Connection::new(Stream("Hello, World!".to_string()), Token::pending(), State { lower: true });
/// let response = service
///     .call(conn)
///     .await?;
///
/// assert_eq!("hello, world!", response);
/// #
/// # Ok(())
/// # }
/// ```
///
/// The input parameters of the function from the above example
/// can be swapped from `(Stream, State)` to `(State, Stream)`:
///
/// ```
/// use rama::transport::connection::service_fn;
/// # use rama::transport::connection::Connection;
/// # use rama::transport::graceful::Token;
/// use tower_async::Service;
/// use std::convert::Infallible;
///
/// pub struct State {
///     lower: bool,
/// }
///
/// # struct Stream(String);
/// #
/// # impl Stream {
/// #    fn read_all(self) -> String {
/// #       self.0
/// #    }
/// # }
/// # #[tokio::main]
/// # async fn main() -> Result<(), Infallible> {
/// async fn echo(state: State, input: Stream) -> Result<String, Infallible> {
///     let s = input.read_all();
///     if state.lower {
///          Ok(s.to_lowercase())
///      } else {
///         Ok(s)
///     }
/// }
///
/// let mut service = service_fn(echo);
///
/// # let conn = Connection::new(Stream("Hello, World!".to_string()), Token::pending(), State { lower: true });
/// let response = service
///     .call(conn)
///     .await?;
///
/// assert_eq!("hello, world!", response);
/// #
/// # Ok(())
/// # }
/// ```
///
/// An example for a service function which consumes the entire connection:
///
/// ```
/// use rama::transport::connection::service_fn;
/// # use rama::transport::connection::Connection;
/// # use rama::transport::graceful::Token;
/// use tower_async::Service;
/// use std::convert::Infallible;
///
/// pub struct State {
///     lower: bool,
/// }
///
/// # struct Stream(String);
/// #
/// # impl Stream {
/// #    fn read_all(&mut self) -> String {
/// #       self.0.clone()
/// #    }
/// # }
/// # #[tokio::main]
/// # async fn main() -> Result<(), Infallible> {
/// async fn echo(mut conn: Connection<Stream, State>) -> Result<String, Infallible> {
///     let s = conn.stream_mut().read_all();
///     if conn.state().lower {
///          Ok(s.to_lowercase())
///      } else {
///         Ok(s)
///     }
/// }
///
/// let mut service = service_fn(echo);
///
/// # let conn = Connection::new(Stream("Hello, World!".to_string()), Token::pending(), State { lower: true });
/// let response = service
///     .call(conn)
///     .await?;
///
/// assert_eq!("hello, world!", response);
/// #
/// # Ok(())
/// # }
/// ```
pub fn service_fn<H, T, S, I>(f: H) -> ServiceFn<H, (T, S, I)>
where
    H: Handler<T, S, I>,
{
    f.into_service_fn()
}

/// A [`tower_async::Service`] that serves a [`Connection`] from a wrapped function or closure.
///
/// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
#[derive(Debug)]
pub struct ServiceFn<H, K> {
    handler: H,
    _kind: std::marker::PhantomData<K>,
}

impl<H, T, S, I> Service<Connection<T, S>> for ServiceFn<H, (T, S, I)>
where
    H: Handler<T, S, I>,
{
    type Response = H::Response;
    type Error = H::Error;

    async fn call(&mut self, req: Connection<T, S>) -> Result<Self::Response, Self::Error> {
        self.handler.call(req).await
    }
}

/// A utility trait which is implemented by this module
/// for all functions and closures that can serve a [`Connection`]
/// and that can therefore be used as the input of [`service_fn`].
pub trait Handler<T, S, I>: Sized + sealed::Sealed<I> {
    /// The response type of the [`tower_async::Service`] that is built
    /// from this function or closure.
    ///
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    type Response;
    /// The error type of the [`tower_async::Service`] that is built
    /// from this function or closure.
    ///
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    type Error;

    /// Serves the given [`Connection`] by calling the wrapped function of closure
    /// and returns its `Result`.
    async fn call(&mut self, req: Connection<T, S>) -> Result<Self::Response, Self::Error>;

    /// Wraps this function or closure in a [`tower_async::Service`]
    /// that serves a [`Connection`].
    ///
    /// This is a convenience method used by [`service_fn`],
    /// as to allow us to return a single adapter type that
    /// implements [`tower_async::Service`].
    ///
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    fn into_service_fn(self) -> ServiceFn<Self, (T, S, I)> {
        ServiceFn {
            handler: self,
            _kind: std::marker::PhantomData,
        }
    }
}

impl<F, Fut, T, R, E> sealed::Sealed<((), T)> for F
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
}

impl<T, S, F, Fut, R, E> Handler<T, S, ((), T)> for F
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
    type Response = R;
    type Error = E;

    async fn call(&mut self, req: Connection<T, S>) -> Result<Self::Response, Self::Error> {
        let (stream, _, _) = req.into_parts();
        (self)(stream).await
    }
}

impl<F, Fut, T, S, R, E> sealed::Sealed<((), (), (T, S))> for F
where
    F: FnMut(T, S) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
}

impl<T, S, F, Fut, R, E> Handler<T, S, ((), (), (T, S))> for F
where
    F: FnMut(T, S) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
    type Response = R;
    type Error = E;

    async fn call(&mut self, req: Connection<T, S>) -> Result<Self::Response, Self::Error> {
        let (stream, _, state) = req.into_parts();
        (self)(stream, state).await
    }
}

impl<F, Fut, T, S, R, E> sealed::Sealed<((), (), ((), T, S))> for F
where
    F: FnMut(S, T) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
}

impl<T, S, F, Fut, R, E> Handler<T, S, ((), (), ((), T, S))> for F
where
    F: FnMut(S, T) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
    type Response = R;
    type Error = E;

    async fn call(&mut self, req: Connection<T, S>) -> Result<Self::Response, Self::Error> {
        let (stream, _, state) = req.into_parts();
        (self)(state, stream).await
    }
}

impl<F, Fut, T, S, R, E> sealed::Sealed<Connection<T, S>> for F
where
    F: FnMut(Connection<T, S>) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
}

impl<T, S, F, Fut, R, E> Handler<T, S, Connection<T, S>> for F
where
    F: FnMut(Connection<T, S>) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
    type Response = R;
    type Error = E;

    async fn call(&mut self, req: Connection<T, S>) -> Result<Self::Response, Self::Error> {
        (self)(req).await
    }
}

mod sealed {
    #[allow(unreachable_pub)]
    pub trait Sealed<T> {}
}
