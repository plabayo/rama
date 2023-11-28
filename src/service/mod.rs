//! `async fn(&self, Request) -> Result<Response, Error>`

pub use tower_async::{service_fn, util::ServiceFn, Layer, Service, ServiceBuilder};

pub mod util {
    //! Various utility types and functions that are generally used with a `Service`.

    pub use tower_async::layer::util::{Identity, Stack};
    pub use tower_async::util::{
        option_layer, AndThen, AndThenLayer, Either, MapErr, MapErrLayer, MapRequest,
        MapRequestLayer, MapResponse, MapResponseLayer, MapResult, MapResultLayer,
    };
}

pub mod timeout {
    //! Middleware that applies a timeout to requests.
    //!
    //! If the response does not complete within the specified timeout, the response
    //! will be aborted.

    pub use tower_async::timeout::{Timeout, TimeoutLayer};
}

pub mod filter {
    //! Conditionally dispatch requests to the inner service based on the result of
    //! a predicate.
    //!
    //! A predicate takes some request type and returns a `Result<Request, Error>`.
    //! If the predicate returns [`Ok`], the inner service is called with the request
    //! returned by the predicate &mdash; which may be the original request or a
    //! modified one. If the predicate returns [`Err`], the request is rejected and
    //! the inner service is not called.
    //!
    //! Predicates may either be synchronous (simple functions from a `Request` to
    //! a [`Result`]) or asynchronous (functions returning [`Future`]s). Separate
    //! traits, [`Predicate`] and [`AsyncPredicate`], represent these two types of
    //! predicate. Note that when it is not necessary to await some other
    //! asynchronous operation in the predicate, the synchronous predicate should be
    //! preferred, as it introduces less overhead.
    //!
    //! The predicate traits are implemented for closures and function pointers.
    //! However, users may also implement them for other types, such as when the
    //! predicate requires some state carried between requests. For example,
    //! [`Predicate`] could be implemented for a type that rejects a fixed set of
    //! requests by checking if they are contained by a a [`HashSet`] or other
    //! collection.
    //!
    //! [`Future`]: std::future::Future
    //! [`HashSet`]: std::collections::HashSet

    pub use tower_async::filter::{
        AsyncFilter, AsyncFilterLayer, AsyncPredicate, Filter, FilterLayer, Predicate,
    };
}

pub mod limit {
    //! A middleware that limits the number of in-flight requests.
    //!
    //! See [`Limit`].

    pub use tower_async::limit::{
        policy::{ConcurrentPolicy, LimitReached, Policy, PolicyOutput},
        Limit, LimitLayer,
    };
}

pub mod http;
pub mod hyper;
pub mod spawn;
