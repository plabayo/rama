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

impl<'a, T, S> Layer<S> for &'a T
where
    T: ?Sized + Layer<S>,
{
    type Service = T::Service;

    fn layer(&self, inner: S) -> Self::Service {
        (**self).layer(inner)
    }
}

impl<L, S> Layer<S> for Option<L>
where
    L: Layer<S>,
{
    type Service = crate::combinators::Either<L::Service, S>;

    fn layer(&self, inner: S) -> Self::Service {
        match self {
            Some(layer) => crate::combinators::Either::A(layer.layer(inner)),
            None => crate::combinators::Either::B(inner),
        }
    }
}

impl<S> Layer<S> for () {
    type Service = S;

    fn layer(&self, service: S) -> Self::Service {
        service
    }
}

impl<S, L1> Layer<S> for (L1,)
where
    L1: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1,) = self;
        l1.layer(service)
    }
}

impl<S, L1, L2> Layer<S> for (L1, L2)
where
    L1: Layer<L2::Service>,
    L2: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2) = self;
        l1.layer(l2.layer(service))
    }
}

impl<S, L1, L2, L3> Layer<S> for (L1, L2, L3)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3) = self;
        l1.layer((l2, l3).layer(service))
    }
}

impl<S, L1, L2, L3, L4> Layer<S> for (L1, L2, L3, L4)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4) = self;
        l1.layer((l2, l3, l4).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5> Layer<S> for (L1, L2, L3, L4, L5)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5) = self;
        l1.layer((l2, l3, l4, l5).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5, L6> Layer<S> for (L1, L2, L3, L4, L5, L6)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6) = self;
        l1.layer((l2, l3, l4, l5, l6).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5, L6, L7> Layer<S> for (L1, L2, L3, L4, L5, L6, L7)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7) = self;
        l1.layer((l2, l3, l4, l5, l6, l7).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5, L6, L7, L8> Layer<S> for (L1, L2, L3, L4, L5, L6, L7, L8)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9> Layer<S> for (L1, L2, L3, L4, L5, L6, L7, L8, L9)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<L12::Service>,
    L12: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<L12::Service>,
    L12: Layer<L13::Service>,
    L13: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13).layer(service))
    }
}

impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<L12::Service>,
    L12: Layer<L13::Service>,
    L13: Layer<L14::Service>,
    L14: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14).layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<L12::Service>,
    L12: Layer<L13::Service>,
    L13: Layer<L14::Service>,
    L14: Layer<L15::Service>,
    L15: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15).layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<L12::Service>,
    L12: Layer<L13::Service>,
    L13: Layer<L14::Service>,
    L14: Layer<L15::Service>,
    L15: Layer<L16::Service>,
    L16: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16).layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<L12::Service>,
    L12: Layer<L13::Service>,
    L13: Layer<L14::Service>,
    L14: Layer<L15::Service>,
    L15: Layer<L16::Service>,
    L16: Layer<L17::Service>,
    L17: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17).layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<L12::Service>,
    L12: Layer<L13::Service>,
    L13: Layer<L14::Service>,
    L14: Layer<L15::Service>,
    L15: Layer<L16::Service>,
    L16: Layer<L17::Service>,
    L17: Layer<L18::Service>,
    L18: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18).layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<L12::Service>,
    L12: Layer<L13::Service>,
    L13: Layer<L14::Service>,
    L14: Layer<L15::Service>,
    L15: Layer<L16::Service>,
    L16: Layer<L17::Service>,
    L17: Layer<L18::Service>,
    L18: Layer<L19::Service>,
    L19: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19).layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20)
where
    L1: Layer<L2::Service>,
    L2: Layer<L3::Service>,
    L3: Layer<L4::Service>,
    L4: Layer<L5::Service>,
    L5: Layer<L6::Service>,
    L6: Layer<L7::Service>,
    L7: Layer<L8::Service>,
    L8: Layer<L9::Service>,
    L9: Layer<L10::Service>,
    L10: Layer<L11::Service>,
    L11: Layer<L12::Service>,
    L12: Layer<L13::Service>,
    L13: Layer<L14::Service>,
    L14: Layer<L15::Service>,
    L15: Layer<L16::Service>,
    L16: Layer<L17::Service>,
    L17: Layer<L18::Service>,
    L18: Layer<L19::Service>,
    L19: Layer<L20::Service>,
    L20: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20).layer(service))
    }
}

mod into_error;
#[doc(inline)]
pub use into_error::{LayerErrorFn, LayerErrorStatic, MakeLayerError};

mod hijack;
#[doc(inline)]
pub use hijack::{HijackLayer, HijackService};

mod map_state;
#[doc(inline)]
pub use map_state::{MapState, MapStateLayer};

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

pub mod get_extension;
pub use get_extension::{GetExtension, GetExtensionLayer};

macro_rules! impl_layer_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, S> Layer<S> for crate::combinators::$id<$($param),+>
        where
            $($param: Layer<S>),+,
        {
            type Service = crate::combinators::$id<$($param::Service),+>;

            fn layer(&self, inner: S) -> Self::Service {
                match self {
                    $(
                        crate::combinators::$id::$param(layer) => crate::combinators::$id::$param(layer.layer(inner)),
                    )+
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_layer_either);
