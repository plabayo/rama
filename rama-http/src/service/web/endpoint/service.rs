use super::IntoResponse;
use super::extract::{FromRequest, FromRequestContextRefPair};
use crate::{Request, Response};
use rama_core::Context;
use rama_utils::macros::all_the_tuples_no_last_special_case;

/// [`rama_core::Service`] implemented for functions taking extractors.
pub trait EndpointServiceFn<S, T>: private::Sealed<S, T> + Clone + Send + Sync + 'static {}

impl<F, R, O, S> EndpointServiceFn<S, (F, R, O)> for F
where
    F: Fn() -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
}

impl<F, R, O, S, I> EndpointServiceFn<S, (F, R, O, (), (), I)> for F
where
    F: Fn(I) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
    I: FromRequest,
{
}

impl<F, R, O, S> EndpointServiceFn<S, (F, R, O, (), Context<S>)> for F
where
    F: Fn(Context<S>) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
}

impl<F, R, O, S, I> EndpointServiceFn<S, (F, R, O, (), Context<S>, I)> for F
where
    F: Fn(Context<S>, I) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
    I: FromRequest,
{
}

macro_rules! impl_endpoint_service_fn_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, S, $($ty),+> EndpointServiceFn<S, (F, R, O, ($($ty),+,))> for F
            where
                F: Fn($($ty),+) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                S: Clone + Send + Sync + 'static,
                $($ty: FromRequestContextRefPair<S>),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple);

macro_rules! impl_endpoint_service_fn_tuple_with_from_request {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, S, $($ty),+, I> EndpointServiceFn<S, (F, R, O, ($($ty),+,), (), I)> for F
            where
                F: Fn($($ty),+, I) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                S: Clone + Send + Sync + 'static,
                $($ty: FromRequestContextRefPair<S>),+,
                I: FromRequest,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_from_request);

macro_rules! impl_endpoint_service_fn_tuple_with_context {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, S, $($ty),+> EndpointServiceFn<S, (F, R, O, ($($ty),+,), Context<S>)> for F
            where
                F: Fn($($ty),+, Context<S>) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                S: Clone + Send + Sync + 'static,
                $($ty: FromRequestContextRefPair<S>),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_context);

macro_rules! impl_endpoint_service_fn_tuple_with_context_and_from_request {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, S, $($ty),+, I> EndpointServiceFn<S, (F, R, O, ($($ty),+,), Context<S>, I)> for F
            where
                F: Fn($($ty),+, Context<S>, I) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                S: Clone + Send + Sync + 'static,
                $($ty: FromRequestContextRefPair<S>),+,
                I: FromRequest,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_context_and_from_request);

mod private {
    use super::*;

    pub trait Sealed<S, T> {
        /// Serve a response for the given request.
        ///
        /// It is expected to do so by extracting the desired data from the context and/or request,
        /// and then calling the function with the extracted data.
        fn call(&self, ctx: Context<S>, req: Request)
        -> impl Future<Output = Response> + Send + '_;
    }

    impl<F, R, O, S> Sealed<S, (F, R, O)> for F
    where
        F: Fn() -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        S: Clone + Send + Sync + 'static,
    {
        async fn call(&self, _ctx: Context<S>, _req: Request) -> Response {
            self().await.into_response()
        }
    }

    impl<F, R, O, S, I> Sealed<S, (F, R, O, (), (), I)> for F
    where
        F: Fn(I) -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        S: Clone + Send + Sync + 'static,
        I: FromRequest,
    {
        async fn call(&self, _ctx: Context<S>, req: Request) -> Response {
            let param: I = match I::from_request(req).await {
                Ok(v) => v,
                Err(r) => return r.into_response(),
            };
            self(param).await.into_response()
        }
    }

    impl<F, R, O, S> Sealed<S, (F, R, O, (), Context<S>)> for F
    where
        F: Fn(Context<S>) -> R + Clone + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        S: Clone + Send + Sync + 'static,
    {
        async fn call(&self, ctx: Context<S>, _req: Request) -> Response {
            self(ctx).await.into_response()
        }
    }

    impl<F, R, O, S, I> Sealed<S, (F, R, O, (), Context<S>, I)> for F
    where
        F: Fn(Context<S>, I) -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        S: Clone + Send + Sync + 'static,
        I: FromRequest,
    {
        async fn call(&self, ctx: Context<S>, req: Request) -> Response {
            let param: I = match I::from_request(req).await {
                Ok(v) => v,
                Err(r) => return r.into_response(),
            };
            self(ctx, param).await.into_response()
        }
    }

    macro_rules! impl_endpoint_service_fn_sealed_tuple {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, S, $($ty),+> Sealed<S, (F, R, O, ($($ty),+,))> for F
                where
                    F: Fn($($ty),+) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    S: Clone + Send + Sync + 'static,
                    $($ty: FromRequestContextRefPair<S>),+,
            {

                async fn call(&self, ctx: Context<S>, req: Request) -> Response {
                        let (parts, _body) = req.into_parts();
                        $(let $ty = match $ty::from_request_context_ref_pair(&ctx, &parts).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        });+;
                        self($($ty),+).await.into_response()
                    }
            }
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple);

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_from_request {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, S, $($ty),+, I> Sealed<S, (F, R, O, ($($ty),+,), (), I)> for F
                where
                    F: Fn($($ty),+, I) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    S: Clone + Send + Sync + 'static,
                    I: FromRequest,
                    $($ty: FromRequestContextRefPair<S>),+,
            {

                async fn call(&self, ctx: Context<S>, req: Request) -> Response {
                        let (parts, body) = req.into_parts();
                        $(let $ty = match $ty::from_request_context_ref_pair(&ctx, &parts).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        });+;
                        let req = Request::from_parts(parts, body);
                        let last: I = match I::from_request(req).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        };
                        self($($ty),+, last).await.into_response()
                    }
            }
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple_with_from_request);

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_context {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, S, $($ty),+> Sealed<S, (F, R, O, ($($ty),+,), Context<S>)> for F
                where
                    F: Fn($($ty),+, Context<S>) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    S: Clone + Send + Sync + 'static,
                    $($ty: FromRequestContextRefPair<S>),+,
            {

                async fn call(&self, ctx: Context<S>, req: Request) -> Response {
                        let (parts, _body) = req.into_parts();
                        $(let $ty = match $ty::from_request_context_ref_pair(&ctx, &parts).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        });+;
                        self($($ty),+, ctx).await.into_response()
                    }
            }
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple_with_context);

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_context_and_from_request {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, S, $($ty),+, I> Sealed<S, (F, R, O, ($($ty),+,), Context<S>, I)> for F
                where
                    F: Fn($($ty),+, Context<S>, I) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    S: Clone + Send + Sync + 'static,
                    I: FromRequest,
                    $($ty: FromRequestContextRefPair<S>),+,
            {

                async fn call(&self, ctx: Context<S>, req: Request) -> Response {
                        let (parts, body) = req.into_parts();
                        $(let $ty = match $ty::from_request_context_ref_pair(&ctx, &parts).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        });+;
                        let req = Request::from_parts(parts, body);
                        let last: I = match I::from_request(req).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        };
                        self($($ty),+, ctx, last).await.into_response()
                    }
            }
        };
    }

    all_the_tuples_no_last_special_case!(
        impl_endpoint_service_fn_sealed_tuple_with_context_and_from_request
    );
}
