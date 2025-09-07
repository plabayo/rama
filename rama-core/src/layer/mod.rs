//! Layer type and utilities.
//!
//! Layers are the abstraction of middleware in Rama.
//!
//! Direct copy of [tower-layer](https://docs.rs/tower-layer/0.3.0/tower_layer/trait.Layer.html).

use rama_error::BoxError;
use std::fmt::Debug;

/// A layer that produces a Layered service (middleware(inner service)).
pub trait Layer<S>: Sized {
    /// The service produced by the layer.
    type Service;

    /// Wrap the given service with the middleware, returning a new service.
    fn layer(&self, inner: S) -> Self::Service;

    /// Same as `layer` but consuming self after the service was created.
    ///
    /// This is useful in case you no longer need the Layer after the service
    /// is created. By default this calls `layer` but if your `Layer` impl
    /// requires cloning you can impl this method as well to avoid the cloning
    /// for the cases where you no longer need the data in the `Layer` after
    /// service ceation.
    fn into_layer(self, inner: S) -> Self::Service {
        self.layer(inner)
    }
}

impl<T, S> Layer<S> for &T
where
    T: Layer<S>,
{
    type Service = T::Service;

    fn layer(&self, inner: S) -> Self::Service {
        (**self).layer(inner)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        (*self).layer(inner)
    }
}

impl<L, S> Layer<S> for Option<L>
where
    L: Layer<S>,
{
    type Service = MaybeLayeredService<S, L>;

    fn layer(&self, inner: S) -> Self::Service {
        match self {
            Some(layer) => MaybeLayeredService(MaybeLayeredSvc::Enabled(layer.layer(inner))),
            None => MaybeLayeredService(MaybeLayeredSvc::Disabled(inner)),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        match self {
            Some(layer) => MaybeLayeredService(MaybeLayeredSvc::Enabled(layer.into_layer(inner))),
            None => MaybeLayeredService(MaybeLayeredSvc::Disabled(inner)),
        }
    }
}

/// [`MaybeLayeredService`] is [`Service`] which is created by using an [`Option<Layer>`]
pub struct MaybeLayeredService<S, L: Layer<S>>(MaybeLayeredSvc<S, L>);

impl<S, L> Debug for MaybeLayeredService<S, L>
where
    S: Debug,
    L: Layer<S>,
    L::Service: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MaybeLayeredService").field(&self.0).finish()
    }
}

impl<S, L> Clone for MaybeLayeredService<S, L>
where
    S: Clone,
    L: Layer<S>,
    L::Service: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

enum MaybeLayeredSvc<S, L>
where
    L: Layer<S>,
{
    Enabled(L::Service),
    Disabled(S),
}

impl<S, L> Debug for MaybeLayeredSvc<S, L>
where
    S: Debug,
    L: Layer<S>,
    L::Service: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enabled(service) => f.debug_tuple("Enabled").field(service).finish(),
            Self::Disabled(service) => f.debug_tuple("Disabled").field(service).finish(),
        }
    }
}

impl<S, L> Clone for MaybeLayeredSvc<S, L>
where
    S: Clone,
    L: Layer<S>,
    L::Service: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Enabled(svc) => Self::Enabled(svc.clone()),
            Self::Disabled(inner) => Self::Disabled(inner.clone()),
        }
    }
}

impl<S, L, Request> Service<Request> for MaybeLayeredService<S, L>
where
    S: Service<Request, Error: Into<BoxError>>,
    L: Layer<S> + 'static,
    L::Service: Service<Request, Response = S::Response, Error: Into<BoxError>>,
    Request: Send + 'static,
{
    type Error = BoxError;
    type Response = S::Response;

    async fn serve(&self, ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
        match &self.0 {
            MaybeLayeredSvc::Enabled(svc) => svc.serve(ctx, req).await.map_err(Into::into),
            MaybeLayeredSvc::Disabled(inner) => inner.serve(ctx, req).await.map_err(Into::into),
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1,) = self;
        l1.into_layer(service)
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2) = self;
        l1.into_layer(l2.into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3) = self;
        l1.into_layer((l2, l3).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4) = self;
        l1.into_layer((l2, l3, l4).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5) = self;
        l1.into_layer((l2, l3, l4, l5).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6) = self;
        l1.into_layer((l2, l3, l4, l5, l6).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19).into_layer(service))
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

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20).into_layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21)
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
    L20: Layer<L21::Service>,
    L21: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21).layer(service))
    }

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21).into_layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21, L22> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21, L22)
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
    L20: Layer<L21::Service>,
    L21: Layer<L22::Service>,
    L22: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22).layer(service))
    }

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22).into_layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21, L22, L23> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21, L22, L23)
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
    L20: Layer<L21::Service>,
    L21: Layer<L22::Service>,
    L22: Layer<L23::Service>,
    L23: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23).layer(service))
    }

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23).into_layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21, L22, L23, L24> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21, L22, L23, L24)
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
    L20: Layer<L21::Service>,
    L21: Layer<L22::Service>,
    L22: Layer<L23::Service>,
    L23: Layer<L24::Service>,
    L24: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23, l24) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23, l24).layer(service))
    }

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23, l24) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23, l24).into_layer(service))
    }
}

#[rustfmt::skip]
impl<S, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21, L22, L23, L24, L25> Layer<S>
    for (L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18, L19, L20, L21, L22, L23, L24, L25)
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
    L20: Layer<L21::Service>,
    L21: Layer<L22::Service>,
    L22: Layer<L23::Service>,
    L23: Layer<L24::Service>,
    L24: Layer<L25::Service>,
    L25: Layer<S>,
{
    type Service = L1::Service;

    fn layer(&self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23, l24, l25) = self;
        l1.layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23, l24, l25).layer(service))
    }

    fn into_layer(self, service: S) -> Self::Service {
        let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23, l24, l25) = self;
        l1.into_layer((l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23, l24, l25).into_layer(service))
    }
}

mod into_error;
#[doc(inline)]
pub use into_error::{LayerErrorFn, LayerErrorStatic, MakeLayerError};

mod hijack;
#[doc(inline)]
pub use hijack::{HijackLayer, HijackService};

mod layer_fn;
#[doc(inline)]
pub use layer_fn::{LayerFn, layer_fn};

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

use crate::{Context, Service};

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

            fn into_layer(self, inner: S) -> Self::Service {
                match self {
                    $(
                        crate::combinators::$id::$param(layer) => crate::combinators::$id::$param(layer.into_layer(inner)),
                    )+
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_layer_either);

#[cfg(test)]
mod tests {
    use rama_error::OpaqueError;

    use crate::{Context, service::service_fn};

    use super::*;

    #[tokio::test]
    async fn simple_layer() {
        let svc = (GetExtensionLayer::new(async |_: String| {})).into_layer(service_fn(
            async |_: Context, _: ()| Ok::<_, OpaqueError>(()),
        ));

        svc.serve(Context::default(), ()).await.unwrap();
    }

    #[tokio::test]
    async fn simple_optional_layer() {
        let maybe_layer = Some(GetExtensionLayer::new(async |_: String| {}));

        let svc = (maybe_layer).into_layer(service_fn(async |_: Context, _: ()| {
            Ok::<_, OpaqueError>(())
        }));

        svc.serve(Context::default(), ()).await.unwrap();
    }
}
