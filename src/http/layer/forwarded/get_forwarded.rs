use crate::http::headers::{
    ForwardHeader, HeaderMapExt, Via, XForwardedFor, XForwardedHost, XForwardedProto,
};
use crate::net::forwarded::ForwardedElement;
use crate::{
    http::Request,
    net::forwarded::Forwarded,
    service::{Context, Layer, Service},
};
use std::future::Future;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
/// Layer to extract [`Forwarded`] information from the specified `T` headers.
pub struct GetForwardedLayer<T = (Forwarded,)> {
    _headers: PhantomData<fn() -> T>,
}

impl Default for GetForwardedLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> GetForwardedLayer<T> {
    /// Create a new `GetForwardedLayer` for the forward header `T`.
    pub fn new() -> Self {
        Self {
            _headers: PhantomData,
        }
    }
}

macro_rules! get_forwarded_combine_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty),*> GetForwardedLayer<($($ty,)*)> {
            /// Combine the header `T` with the current headers for this [`GetForwardedLayer`].
            pub fn combine<T>(self) -> GetForwardedLayer<($($ty,)* T)> {
                GetForwardedLayer {
                    _headers: PhantomData,
                }
            }
        }
    }
}

all_the_tuples_minus_one_no_last_special_case!(get_forwarded_combine_tuple);

impl GetForwardedLayer {
    #[inline]
    /// Create a new `GetForwardedLayer` for the standard [`Forwarded`] header.
    pub fn std() -> Self {
        Self::new()
    }
}

impl GetForwardedLayer<(Via, XForwardedFor, XForwardedHost, XForwardedProto)> {
    #[inline]
    /// Create a new `GetForwardedLayer` for the legacy [`Via`],
    /// [`X-Forwarded-For`], [`X-Forwarded-Host`], and [`X-Forwarded-Proto`] headers.
    ///
    /// [`Via`]: crate::http::headers::Via
    /// [`X-Forwarded-For`]: crate::http::headers::XForwardedFor
    /// [`X-Forwarded-Host`]: crate::http::headers::XForwardedHost
    /// [`X-Forwarded-Proto`]: crate::http::headers::XForwardedProto
    pub fn legacy() -> Self {
        Self::new()
    }
}

macro_rules! get_forwarded_layer_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* S> Layer<S> for GetForwardedLayer<($($ty,)*)> {
            type Service = GetForwardedService<S, ($($ty,)*)>;

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

#[derive(Debug, Clone)]
/// Middleware service to extract [`Forwarded`] information from the specified `T` headers.
pub struct GetForwardedService<S, T = (Forwarded,)> {
    inner: S,
    _headers: PhantomData<fn() -> T>,
}

impl<S, T> GetForwardedService<S, T> {
    /// Create a new `GetForwardedService` for the forward header `T`.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            _headers: PhantomData,
        }
    }
}

macro_rules! get_forwarded_service_combine_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<S, $($ty),*> GetForwardedService<S, ($($ty,)*)> {
            /// Combine the header `T` with the current headers for this [`GetForwardedService`].
            pub fn combine<T>(self) -> GetForwardedService<S, ($($ty,)* T)> {
                GetForwardedService {
                    inner: self.inner,
                    _headers: PhantomData,
                }
            }
        }
    }
}

all_the_tuples_minus_one_no_last_special_case!(get_forwarded_service_combine_tuple);

impl<S> GetForwardedService<S> {
    #[inline]
    /// Create a new `GetForwardedService` for the standard [`Forwarded`] header.
    pub fn std(inner: S) -> Self {
        Self::new(inner)
    }
}

impl<S> GetForwardedService<S, (Via, XForwardedFor, XForwardedHost, XForwardedProto)> {
    #[inline]
    /// Create a new `GetForwardedService` for the legacy [`Via`],
    /// [`X-Forwarded-For`], [`X-Forwarded-Host`], and [`X-Forwarded-Proto`] headers.
    ///
    /// [`Via`]: crate::http::headers::Via
    /// [`X-Forwarded-For`]: crate::http::headers::XForwardedFor
    /// [`X-Forwarded-Host`]: crate::http::headers::XForwardedHost
    /// [`X-Forwarded-Proto`]: crate::http::headers::XForwardedProto
    pub fn legacy(inner: S) -> Self {
        Self::new(inner)
    }
}

macro_rules! get_forwarded_service_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* S, State, Body> Service<State, Request<Body>> for GetForwardedService<S, ($($ty,)*)>
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

all_the_tuples_no_last_special_case!(get_forwarded_service_for_tuple);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::OpaqueError,
        http::{headers::TrueClientIp, IntoResponse, Response, StatusCode},
        service::service_fn,
    };

    fn assert_is_service<T: Service<(), Request<()>>>(_: T) {}

    async fn dummy_service_fn() -> Result<Response, OpaqueError> {
        Ok(StatusCode::OK.into_response())
    }

    #[test]
    fn test_get_forwarded_service_is_service() {
        assert_is_service(GetForwardedService::std(service_fn(dummy_service_fn)));
        assert_is_service(GetForwardedService::legacy(service_fn(dummy_service_fn)));
        assert_is_service(
            GetForwardedService::legacy(service_fn(dummy_service_fn)).combine::<TrueClientIp>(),
        );
        assert_is_service(GetForwardedService::<_, (TrueClientIp,)>::new(service_fn(
            dummy_service_fn,
        )));
    }
}
