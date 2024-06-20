use crate::http::headers::HeaderMapExt;
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
                    f.merge(forwarded);
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
        ctx: Context<State>,
        req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        // let mut forwarded_elements = Vec::with_capacity(1);

        // // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
        // if let Some() {
        //     forwarded_element = Some(ForwardedElement::forwarded_for(peer_addr));
        // }

        // if let Some(node_id) = self.by_node.clone() {
        //     forwarded_element = match forwarded_element.take() {
        //         Some(mut forwarded_element) => {
        //             forwarded_element.set_forwarded_by(node_id);
        //             Some(forwarded_element)
        //         }
        //         None => Some(ForwardedElement::forwarded_by(node_id)),
        //     };
        // }

        // if self.authority {
        //     if let Some(authority) = request_ctx.authority.clone() {
        //         forwarded_element = match forwarded_element.take() {
        //             Some(mut forwarded_element) => {
        //                 forwarded_element.set_forwarded_host(authority);
        //                 Some(forwarded_element)
        //             }
        //             None => Some(ForwardedElement::forwarded_host(authority)),
        //         };
        //     }
        // }

        // if self.proto {
        //     forwarded_element = match forwarded_element.take() {
        //         Some(mut forwarded_element) => {
        //             forwarded_element.set_forwarded_proto(request_ctx.protocol.clone());
        //             Some(forwarded_element)
        //         }
        //         None => Some(ForwardedElement::forwarded_proto(
        //             request_ctx.protocol.clone(),
        //         )),
        //     };
        // }

        // let forwarded = match (forwarded, forwarded_element) {
        //     (None, None) => None,
        //     (Some(forwarded), None) => Some(forwarded),
        //     (None, Some(forwarded_element)) => Some(Forwarded::new(forwarded_element)),
        //     (Some(mut forwarded), Some(forwarded_element)) => {
        //         forwarded.append(forwarded_element);
        //         Some(forwarded)
        //     }
        // };

        // if let Some(forwarded) = forwarded {
        //     req.headers_mut().typed_insert(forwarded);
        // }

        self.inner.serve(ctx, req)
    }
}

mod private {
    #[derive(Debug, Clone)]
    pub struct ModeRFC7239;

    #[derive(Debug, Clone)]
    pub struct ModeLegacy;
}
