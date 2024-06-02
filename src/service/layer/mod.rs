//! Layer type and utilities.
//!
//! Layers are the abstraction of middleware in Rama.
//!
//! Direct copy of [tower-layer](https://docs.rs/tower-layer/0.3.0/tower_layer/trait.Layer.html).

/// A layer that produces a Layered service (middleware(inner service)).
pub trait Layer<S> {
    /// The service produced by the layer.
    type Service;

    /// Wrap the given service with the middleware, returning a new service.
    fn layer(&self, inner: S) -> Self::Service;
}

impl<L, S> Layer<S> for Option<L>
where
    L: Layer<S>,
{
    type Service = Either<L::Service, S>;

    fn layer(&self, inner: S) -> Self::Service {
        match self {
            Some(layer) => Either::A(layer.layer(inner)),
            None => Either::B(inner),
        }
    }
}

mod into_error;
#[doc(inline)]
pub use into_error::{LayerErrorFn, LayerErrorStatic, MakeLayerError};

mod hijack;
#[doc(inline)]
pub use hijack::{HijackLayer, HijackService};

mod identity;
#[doc(inline)]
pub use identity::Identity;

mod stack;
#[doc(inline)]
pub use stack::Stack;

mod map_state;
#[doc(inline)]
pub use map_state::{MapState, MapStateLayer};

mod then;
#[doc(inline)]
pub use then::{Then, ThenLayer};

mod and_then;
#[doc(inline)]
pub use and_then::{AndThen, AndThenLayer};

mod layer_fn;
#[doc(inline)]
pub use layer_fn::{layer_fn, LayerFn};

mod map_request;
#[doc(inline)]
pub use map_request::{MapRequest, MapRequestLayer};

mod map_response;
#[doc(inline)]
pub use map_response::{MapResponse, MapResponseLayer};

mod map_err;
#[doc(inline)]
pub use map_err::{MapErr, MapErrLayer};

mod consume_err;
#[doc(inline)]
pub use consume_err::{ConsumeErr, ConsumeErrLayer};

mod trace_err;
#[doc(inline)]
pub use trace_err::{TraceErr, TraceErrLayer};

mod map_result;
#[doc(inline)]
pub use map_result::{MapResult, MapResultLayer};

pub mod timeout;
pub use timeout::{Timeout, TimeoutLayer};

pub mod limit;
pub use limit::{Limit, LimitLayer};

pub mod add_extension;
pub use add_extension::{AddExtension, AddExtensionLayer};

use super::util::combinators::Either;

pub mod http;
