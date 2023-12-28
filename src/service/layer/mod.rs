//! Layer type and utilities.
//!
//! Layers are the abstraction of middleware in Rama.
//!
//! Direct copy of [tower-layer](https://docs.rs/tower-layer/0.3.0/tower_layer/trait.Layer.html).

mod either;
pub use either::Either;

mod identity;
pub use identity::Identity;

mod stack;
pub use stack::Stack;

mod then;
pub use then::{Then, ThenLayer};

mod and_then;
pub use and_then::{AndThen, AndThenLayer};

mod layer_fn;
pub use layer_fn::{layer_fn, LayerFn};

mod map_request;
pub use map_request::{MapRequest, MapRequestLayer};

mod map_response;
pub use map_response::{MapResponse, MapResponseLayer};

mod map_err;
pub use map_err::{MapErr, MapErrLayer};

mod map_result;
pub use map_result::{MapResult, MapResultLayer};

/// A layer that produces a Layered service (middleware(inner service)).
pub trait Layer<S> {
    /// The service produced by the layer.
    type Service;

    /// Wrap the given service with the middleware, returning a new service.
    fn layer(&self, inner: S) -> Self::Service;
}