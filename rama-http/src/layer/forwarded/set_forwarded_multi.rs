use crate::Request;
use crate::headers::HeaderMapExt;
use crate::headers::forwarded::ForwardHeader;
use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::{Layer, Service, extensions::ExtensionsRef};
use rama_net::address::Domain;
use rama_net::forwarded::{Forwarded, ForwardedElement, NodeId};
use rama_net::http::RequestContext;
use rama_net::stream::SocketInfo;
use rama_utils::macros::all_the_tuples_no_last_special_case;
use std::fmt;
use std::marker::PhantomData;

/// Layer to write [`Forwarded`] information for this proxy,
/// added to the end of the chain of forwarded information already known.
///
/// Use [`super::SetForwardedHeaderLayer`] if you only need a single a header.
///
/// This layer can set any headers as long as you have a [`ForwardHeader`] implementation
/// for the headers you want to set. You can pass it as the type to the layer when creating
/// the layer using [`SetForwardedHeadersLayer::new`], with the headers in a single tuple.
pub struct SetForwardedHeadersLayer<T = Forwarded> {
    by_node: NodeId,
    _headers: PhantomData<fn() -> T>,
}

impl<T: fmt::Debug> fmt::Debug for SetForwardedHeadersLayer<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SetForwardedHeadersLayer")
            .field("by_node", &self.by_node)
            .field(
                "_headers",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T: Clone> Clone for SetForwardedHeadersLayer<T> {
    fn clone(&self) -> Self {
        Self {
            by_node: self.by_node.clone(),
            _headers: PhantomData,
        }
    }
}

impl<T> Default for SetForwardedHeadersLayer<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SetForwardedHeadersLayer<T> {
    /// Create a new `SetForwardedHeadersLayer` for the specified headers `T`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_node: Domain::from_static("rama").into(),
            _headers: PhantomData,
        }
    }
}

impl<H, S> Layer<S> for SetForwardedHeadersLayer<H> {
    type Service = SetForwardedHeadersService<S, H>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            by_node: self.by_node.clone(),
            _headers: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            by_node: self.by_node,
            _headers: PhantomData,
        }
    }
}

/// Middleware [`Service`] to write [`Forwarded`] information for this proxy,
/// added to the end of the chain of forwarded information already known.
///
/// See [`SetForwardedHeadersLayer`] for more information.
pub struct SetForwardedHeadersService<S, T = Forwarded> {
    inner: S,
    by_node: NodeId,
    _headers: PhantomData<fn() -> T>,
}

impl<S: fmt::Debug, T> fmt::Debug for SetForwardedHeadersService<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetForwardedHeadersService")
            .field("inner", &self.inner)
            .field("by_node", &self.by_node)
            .field(
                "_headers",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<S: Clone, T> Clone for SetForwardedHeadersService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            by_node: self.by_node.clone(),
            _headers: PhantomData,
        }
    }
}

impl<S, T> SetForwardedHeadersService<S, T> {
    /// Create a new `SetForwardedHeadersService` for the specified headers `T`.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            by_node: Domain::from_static("rama").into(),
            _headers: PhantomData,
        }
    }
}

macro_rules! set_forwarded_service_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<S, $($ty),* , Body> Service<Request<Body>> for SetForwardedHeadersService<S, ($($ty,)*)>
        where
            $( $ty: ForwardHeader + Send + Sync + 'static, )*
            S: Service<Request<Body>, Error: Into<BoxError>>,
            Body: Send + 'static,
        {
            type Output = S::Output;
            type Error = BoxError;

            async fn serve(
                &self,
                mut req: Request<Body>,
            ) -> Result<Self::Output, Self::Error> {
                let forwarded: Option<Forwarded> = req.extensions().get().cloned();

                let mut forwarded_element = ForwardedElement::new_forwarded_by(self.by_node.clone());

                if let Some(peer_addr) = req.extensions().get::<SocketInfo>().map(|socket| socket.peer_addr()) {
                    forwarded_element.set_forwarded_for(peer_addr);
                }

                let request_ctx = RequestContext::try_from(&req)?;

                forwarded_element.set_forwarded_host(request_ctx.authority.clone());

                if let Ok(forwarded_proto) = (&request_ctx.protocol).try_into() {
                    forwarded_element.set_forwarded_proto(forwarded_proto);
                }

                let forwarded = match forwarded {
                    None => Some(Forwarded::new(forwarded_element)),
                    Some(mut forwarded) => {
                        forwarded.append(forwarded_element);
                        Some(forwarded)
                    }
                };

                if let Some(forwarded) = forwarded {
                    $(
                        if let Some(header) = $ty::try_from_forwarded(forwarded.iter()) {
                            req.headers_mut().typed_insert(header);
                        }
                    )*
                }

                self.inner.serve(req).await.into_box_error()
            }
        }
    };
}
all_the_tuples_no_last_special_case!(set_forwarded_service_for_tuple);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Response, StatusCode,
        headers::forwarded::{TrueClientIp, XClientIp, XRealIp},
        service::web::response::IntoResponse,
    };
    use rama_core::{Layer, error::BoxError, service::service_fn};
    use rama_http_headers::forwarded::XForwardedProto;
    use std::convert::Infallible;

    fn assert_is_service<T: Service<Request<()>>>(_: T) {}

    async fn dummy_service_fn() -> Result<Response, BoxError> {
        Ok(StatusCode::OK.into_response())
    }

    #[test]
    fn test_set_forwarded_service_is_service() {
        assert_is_service(SetForwardedHeadersService::<_, (TrueClientIp,)>::new(
            service_fn(dummy_service_fn),
        ));
        assert_is_service(
            SetForwardedHeadersService::<_, (TrueClientIp, XClientIp)>::new(service_fn(
                dummy_service_fn,
            )),
        );
        assert_is_service(
            SetForwardedHeadersLayer::<(XRealIp, XForwardedProto)>::new()
                .into_layer(service_fn(dummy_service_fn)),
        );
    }

    #[tokio::test]
    async fn test_set_forwarded_service_forwarded() {
        async fn svc(request: Request<()>) -> Result<(), Infallible> {
            assert_eq!(
                request.headers().get("Forwarded").unwrap(),
                "by=rama;host=\"example.com:80\";proto=http"
            );
            Ok(())
        }

        let service =
            SetForwardedHeadersService::<_, (rama_http_headers::forwarded::Forwarded,)>::new(
                service_fn(svc),
            );
        let req = Request::builder().uri("example.com").body(()).unwrap();
        service.serve(req).await.unwrap();
    }
}
