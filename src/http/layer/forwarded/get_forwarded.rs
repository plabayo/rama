use crate::http::headers::{
    ForwardHeader, HeaderMapExt, Via, XForwardedFor, XForwardedHost, XForwardedProto,
};
use crate::net::forwarded::ForwardedElement;
use crate::{
    http::Request,
    net::forwarded::Forwarded,
    service::{Context, Layer, Service},
};
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
/// Layer to extract [`Forwarded`] information from the specified `T` headers.
pub struct GetForwardedHeadersLayer<T = Forwarded> {
    _headers: PhantomData<fn() -> T>,
}

impl Default for GetForwardedHeadersLayer {
    fn default() -> Self {
        Self::forwarded()
    }
}

impl<T> GetForwardedHeadersLayer<T> {
    /// Create a new `GetForwardedHeadersLayer` for the specified headers `T`.
    pub fn new() -> Self {
        Self {
            _headers: PhantomData,
        }
    }
}

impl GetForwardedHeadersLayer {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the standard [`Forwarded`] header.
    pub fn forwarded() -> Self {
        Self::new()
    }
}

impl GetForwardedHeadersLayer<Via> {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the canonical [`Via`] header.
    pub fn via() -> Self {
        Self::new()
    }
}

impl GetForwardedHeadersLayer<XForwardedFor> {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the canonical [`X-Forwarded-For`] header.
    pub fn x_forwarded_for() -> Self {
        Self::new()
    }
}

impl GetForwardedHeadersLayer<XForwardedHost> {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the canonical [`X-Forwarded-Host`] header.
    pub fn x_forwarded_host() -> Self {
        Self::new()
    }
}

impl GetForwardedHeadersLayer<XForwardedProto> {
    #[inline]
    /// Create a new `GetForwardedHeadersLayer` for the canonical [`X-Forwarded-Proto`] header.
    pub fn x_forwarded_proto() -> Self {
        Self::new()
    }
}

macro_rules! get_forwarded_layer_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* S> Layer<S> for GetForwardedHeadersLayer<($($ty,)*)> {
            type Service = GetForwardedHeadersService<S, ($($ty,)*)>;

            fn layer(&self, inner: S) -> Self::Service {
                Self::Service {
                    inner,
                    _headers: PhantomData,
                }
            }
        }
    }
}

all_the_tuples_no_last_special_case!(get_forwarded_layer_for_tuple);

/// Middleware service to extract [`Forwarded`] information from the specified `T` headers.
pub struct GetForwardedHeadersService<S, T = Forwarded> {
    inner: S,
    _headers: PhantomData<fn() -> T>,
}

impl<S: fmt::Debug, T> fmt::Debug for GetForwardedHeadersService<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetForwardedHeadersService")
            .field("inner", &self.inner)
            .field("_headers", &format_args!("{}", std::any::type_name::<T>()))
            .finish()
    }
}

impl<S: Clone, T> Clone for GetForwardedHeadersService<S, T> {
    fn clone(&self) -> Self {
        GetForwardedHeadersService {
            inner: self.inner.clone(),
            _headers: PhantomData,
        }
    }
}

impl<S, T> GetForwardedHeadersService<S, T> {
    /// Create a new `GetForwardedHeadersService` for the specified headers `T`.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            _headers: PhantomData,
        }
    }
}

impl<S> GetForwardedHeadersService<S> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the standard [`Forwarded`] header.
    pub fn forwarded(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeadersService<S, Via> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the canonical [`Via`] header.
    pub fn via(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeadersService<S, XForwardedFor> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the canonical [`X-Forwarded-For`] header.
    pub fn x_forwarded_for(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeadersService<S, XForwardedHost> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the canonical [`X-Forwarded-Host`] header.
    pub fn x_forwarded_host(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedHeadersService<S, XForwardedProto> {
    #[inline]
    /// Create a new `GetForwardedHeadersService` for the canonical [`X-Forwarded-Proto`] header.
    pub fn x_forwarded_proto(inner: S) -> Self {
        Self::new(inner)
    }
}

macro_rules! get_forwarded_service_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* S, State, Body> Service<State, Request<Body>> for GetForwardedHeadersService<S, ($($ty,)*)>
        where
            $( $ty: ForwardHeader + Send + Sync + 'static, )*
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
                let mut forwarded_elements: Vec<ForwardedElement> = Vec::with_capacity(1);

                $(
                    if let Some($ty) = req.headers().typed_get::<$ty>() {
                        let mut iter = $ty.into_iter();
                        for element in forwarded_elements.iter_mut() {
                            let other = iter.next();
                            match other {
                                Some(other) => {
                                    element.merge(other);
                                }
                                None => break,
                            }
                        }
                        for other in iter {
                            forwarded_elements.push(other);
                        }
                    }
                )*

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
    }
}

impl<H, S, State, Body> Service<State, Request<Body>> for GetForwardedHeadersService<S, H>
where
    H: ForwardHeader + Send + Sync + 'static,
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
        let mut forwarded_elements: Vec<ForwardedElement> = Vec::with_capacity(1);

        if let Some(header) = req.headers().typed_get::<H>() {
            forwarded_elements.extend(header);
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

all_the_tuples_no_last_special_case!(get_forwarded_service_for_tuple);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::OpaqueError,
        http::{
            headers::{TrueClientIp, XClientIp},
            IntoResponse, Response, StatusCode,
        },
        service::service_fn,
    };

    fn assert_is_service<T: Service<(), Request<()>>>(_: T) {}

    async fn dummy_service_fn() -> Result<Response, OpaqueError> {
        Ok(StatusCode::OK.into_response())
    }

    #[test]
    fn test_get_forwarded_service_is_service() {
        assert_is_service(GetForwardedHeadersService::forwarded(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::via(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::x_forwarded_for(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::x_forwarded_proto(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::x_forwarded_host(service_fn(
            dummy_service_fn,
        )));
        assert_is_service(GetForwardedHeadersService::<_, TrueClientIp>::new(
            service_fn(dummy_service_fn),
        ));
        assert_is_service(GetForwardedHeadersService::<_, (TrueClientIp,)>::new(
            service_fn(dummy_service_fn),
        ));
        assert_is_service(
            GetForwardedHeadersService::<_, (TrueClientIp, XClientIp)>::new(service_fn(
                dummy_service_fn,
            )),
        );
    }
}
