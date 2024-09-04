use super::extract::{FromRequest, FromRequestParts};
use crate::{IntoResponse, Request, Response};
use rama_core::Context;
use rama_utils::macros::all_the_tuples_no_last_special_case;
use std::future::Future;

/// [`crate::Service`] implemented for functions taking extractors.
pub trait EndpointServiceFn<S, T>: private::Sealed<S, T> + Clone + Send + Sync + 'static {
    /// Serve a response for the given request.
    ///
    /// It is expected to do so by extracting the desired data from the context and/or request,
    /// and then calling the function with the extracted data.
    fn call(&self, ctx: Context<S>, req: Request) -> impl Future<Output = Response> + Send + '_;
}

impl<F, R, O, S> EndpointServiceFn<S, (F, R, O)> for F
where
    F: Fn() -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    S: Send + Sync + 'static,
{
    async fn call(&self, _ctx: Context<S>, _req: Request) -> Response {
        self().await.into_response()
    }
}

impl<F, R, O, S, I, M> EndpointServiceFn<S, (F, R, O, I, M)> for F
where
    F: Fn(I) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    S: Send + Sync + 'static,
    I: FromRequest<S, M>,
    M: Send + Sync + 'static,
{
    async fn call(&self, ctx: Context<S>, req: Request) -> Response {
        let param: I = match I::from_request(ctx, req).await {
            Ok(v) => v,
            Err(r) => return r.into_response(),
        };
        self(param).await.into_response()
    }
}

macro_rules! impl_endpoint_service_fn_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, S, $($ty),+, I, M> EndpointServiceFn<S, (F, R, O, $($ty),+, I, M)> for F
            where
                F: Fn($($ty),+, I) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                S: Send + Sync + 'static,
                $($ty: FromRequestParts<S>),+,
                I: FromRequest<S, M>,
                M: Send + Sync + 'static,
        {
            async fn call(&self, ctx: Context<S>, req: Request) -> Response {
                let (parts, body) = req.into_parts();
                $(let $ty = match $ty::from_request_parts(&ctx, &parts).await {
                    Ok(v) => v,
                    Err(r) => return r.into_response(),
                });+;
                let req = Request::from_parts(parts, body);
                let last = match I::from_request(ctx, req).await {
                    Ok(v) => v,
                    Err(r) => return r.into_response(),
                };
                self($($ty),+, last).await.into_response()
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple);

macro_rules! impl_endpoint_service_fn_tuple_with_context_and_request {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, S, $($ty),+> EndpointServiceFn<S, (F, R, O, (), (), (), (), (), (), (), (), (), (), (), (), $($ty),+, Context<S>, Request)> for F
            where
                F: Fn($($ty),+, Context<S>, Request) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                S: Send + Sync + 'static,
                $($ty: FromRequestParts<S>),+,
        {
            async fn call(&self, ctx: Context<S>, req: Request) -> Response {
                let (parts, body) = req.into_parts();
                $(let $ty = match $ty::from_request_parts(&ctx, &parts).await {
                    Ok(v) => v,
                    Err(r) => return r.into_response(),
                });+;
                let req = Request::from_parts(parts, body);
                self($($ty),+, ctx, req).await.into_response()
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_context_and_request);

mod private {
    use super::*;

    pub trait Sealed<S, T> {}

    impl<F, R, O, S> Sealed<S, (F, R, O)> for F
    where
        F: Fn() -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
    }

    impl<F, R, O, S, I, M> Sealed<S, (F, R, O, I, M)> for F
    where
        F: Fn(I) -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        S: Send + Sync + 'static,
        I: FromRequest<S, M>,
        M: Send + Sync + 'static,
    {
    }

    macro_rules! impl_endpoint_service_fn_sealed_tuple {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, S, $($ty),+, I, M> Sealed<S, (F, R, O, $($ty),+, I, M)> for F
                where
                    F: Fn($($ty),+, I) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    S: Send + Sync + 'static,
                    $($ty: FromRequestParts<S>),+,
                    I: FromRequest<S, M>,
                    M: Send + Sync + 'static,
            {}
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple);

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_context_and_request {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, S, $($ty),+> Sealed<S, (F, R, O, (), (), (), (), (), (), (), (), (), (), (), (), $($ty),+, Context<S>, Request)> for F
                where
                    F: Fn($($ty),+, Context<S>, Request) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    S: Send + Sync + 'static,
                    $($ty: FromRequestParts<S>),+,
            {}
        };
    }

    all_the_tuples_no_last_special_case!(
        impl_endpoint_service_fn_sealed_tuple_with_context_and_request
    );
}
