use crate::http::headers::{HeaderMapExt, Via, XForwardedFor, XForwardedHost, XForwardedProto};
use crate::net::forwarded::ForwardedElement;
use crate::{
    http::Request,
    net::forwarded::Forwarded,
    service::{Context, Service},
};
use std::future::Future;
use std::marker::PhantomData;

use private::{ModeLegacy, ModeRFC7239};

#[derive(Debug, Clone)]
/// TODO
pub struct GetForwardedLayer<M = ModeRFC7239> {
    _mode: PhantomData<fn() -> M>,
}

#[derive(Debug, Clone)]
/// TODO
pub struct GetForwardedService<S, M = ModeRFC7239> {
    inner: S,
    _mode: PhantomData<fn() -> M>,
}

impl<S, State, Body> Service<State, Request<Body>> for GetForwardedService<S, ModeRFC7239>
where
    S: Service<State, Request<Body>>,
    Body: Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        if let Some(forwarded) = req.headers().typed_get::<Forwarded>() {
            match ctx.get_mut::<Forwarded>() {
                Some(ref mut f) => {
                    f.extend(forwarded);
                }
                None => {
                    ctx.insert(forwarded);
                }
            }
        }

        self.inner.serve(ctx, req)
    }
}

impl<S, State, Body> Service<State, Request<Body>> for GetForwardedService<S, ModeLegacy>
where
    S: Service<State, Request<Body>>,
    Body: Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let mut forwarded_elements = Vec::with_capacity(1);

        if let Some(x_forwarded_for) = req.headers().typed_get::<XForwardedFor>() {
            forwarded_elements.extend(
                x_forwarded_for
                    .iter()
                    .map(|ip| ForwardedElement::forwarded_for(*ip)),
            );
        }

        if let Some(via) = req.headers().typed_get::<Via>() {
            let mut via_iter = via.into_iter_nodes();
            for element in forwarded_elements.iter_mut() {
                match via_iter.next() {
                    Some(node) => {
                        element.set_forwarded_by(node);
                    }
                    None => break,
                }
            }
            // TODO: set also proto / version
            for node in via_iter {
                forwarded_elements.push(ForwardedElement::forwarded_by(node));
            }
        }

        if let Some(x_forwarded_host) = req.headers().typed_get::<XForwardedHost>() {
            let authority = x_forwarded_host.into_inner();
            match forwarded_elements.get_mut(0) {
                Some(el) => {
                    el.set_forwarded_host(authority);
                }
                None => {
                    forwarded_elements.push(ForwardedElement::forwarded_host(authority));
                }
            }
        }

        if let Some(x_forwarded_proto) = req.headers().typed_get::<XForwardedProto>() {
            let proto = x_forwarded_proto.into_protocol();
            match forwarded_elements.get_mut(0) {
                Some(el) => {
                    el.set_forwarded_proto(proto);
                }
                None => {
                    forwarded_elements.push(ForwardedElement::forwarded_proto(proto));
                }
            }
        }

        if !forwarded_elements.is_empty() {
            match ctx.get_mut::<Forwarded>() {
                Some(ref mut f) => {
                    f.extend(forwarded_elements);
                }
                None => {
                    let mut it = forwarded_elements.into_iter();
                    let mut forwarded = Forwarded::new(it.next().unwrap());
                    forwarded.extend(it);
                    ctx.insert(forwarded);
                }
            }
        }

        self.inner.serve(ctx, req)
    }
}

mod private {
    #[derive(Debug, Clone)]
    pub struct ModeRFC7239;

    #[derive(Debug, Clone)]
    pub struct ModeLegacy;
}
