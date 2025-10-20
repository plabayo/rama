use super::IntoResponse;
use super::extract::{FromRequest, FromRequestContextRefPair};
use crate::{Request, Response};
use rama_utils::macros::all_the_tuples_no_last_special_case;

#[derive(Clone, Debug)]
pub struct State<S>(pub S);

// Generic T = (Function, Input, Output)
// Input = ((State), (FromRequestContextRefPair), (FromRequest))

/// [`rama_core::Service`] implemented for functions taking extractors.
pub trait EndpointServiceFn<T, State>:
    private::Sealed<T, State> + Clone + Send + Sync + 'static
{
}

impl<F, R, O, S> EndpointServiceFn<(F, ((), (), ()), (R, O)), S> for F
where
    F: Fn() -> R + Send + Sync + Clone + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    S: Send + Sync + 'static,
{
}

impl<F, R, O, S> EndpointServiceFn<(F, ((S,), (), ()), (R, O)), S> for F
where
    F: Fn(State<S>) -> R + Send + Sync + Clone + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    S: Send + Sync + 'static,
{
}

impl<F, R, O, I, S> EndpointServiceFn<(F, ((), (), (I,)), (R, O)), S> for F
where
    F: Fn(I) -> R + Send + Sync + Clone + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    I: FromRequest,
    S: Send + Sync + 'static,
{
}

impl<F, R, O, I, S> EndpointServiceFn<(F, ((S,), (), (I,)), (R, O)), S> for F
where
    F: Fn(State<S>, I) -> R + Send + Sync + Clone + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    I: FromRequest,
    S: Send + Sync + 'static,
{
}

macro_rules! impl_endpoint_service_fn_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, State, $($ty),+> EndpointServiceFn<(F, ((), ($($ty),+,), ()), (R, O)), State> for F
            where
                F: Fn($($ty),+) -> R + Send + Sync + Clone + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                State: Send + Sync + 'static,
                $($ty: FromRequestContextRefPair),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple);

macro_rules! impl_endpoint_service_fn_tuple_with_state {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, S, $($ty),+> EndpointServiceFn<(F, ((S,), ($($ty),+,), ()), (R, O)), S> for F
            where
                F: Fn(State<S>, $($ty),+) -> R + Send + Sync + Clone + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                S: Send + Sync + 'static,
                $($ty: FromRequestContextRefPair),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_state);

macro_rules! impl_endpoint_service_fn_tuple_with_from_request {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, S, $($ty),+, I> EndpointServiceFn<(F, ((), ($($ty),+,), I), (R, O)), S> for F
            where
                F: Fn($($ty),+, I) -> R + Send + Sync + Clone + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                I: FromRequest,
                S: Send + Sync + 'static,
                $($ty: FromRequestContextRefPair),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_from_request);

macro_rules! impl_endpoint_service_fn_tuple_with_from_request_with_state {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, S, $($ty),+, I> EndpointServiceFn<(F, ((S,), ($($ty),+,), I), (R, O)), S> for F
            where
                F: Fn(State<S>, $($ty),+, I) -> R + Send + Sync + Clone + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                I: FromRequest,
                S: Send + Sync + 'static,
                $($ty: FromRequestContextRefPair),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_from_request_with_state);

mod private {
    use super::*;

    pub trait Sealed<T, State> {
        /// Serve a response for the given request.
        ///
        /// It is expected to do so by extracting the desired data from the context and/or request,
        /// and then calling the function with the extracted data.
        fn call(&self, state: State, req: Request) -> impl Future<Output = Response> + Send + '_;
    }

    impl<F, R, O, S> Sealed<(F, ((), (), ()), (R, O)), S> for F
    where
        F: Fn() -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
        async fn call(&self, _state: S, _req: Request) -> Response {
            self().await.into_response()
        }
    }

    impl<F, R, O, S> Sealed<(F, ((S,), (), ()), (R, O)), S> for F
    where
        F: Fn(State<S>) -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
        async fn call(&self, state: S, _req: Request) -> Response {
            self(State(state)).await.into_response()
        }
    }

    impl<F, R, O, I, S> Sealed<(F, ((), (), (I,)), (R, O)), S> for F
    where
        F: Fn(I) -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        I: FromRequest,
        S: Send + Sync + 'static,
    {
        async fn call(&self, _state: S, req: Request) -> Response {
            let param: I = match I::from_request(req).await {
                Ok(v) => v,
                Err(r) => return r.into_response(),
            };
            self(param).await.into_response()
        }
    }

    impl<F, R, O, I, S> Sealed<(F, ((S,), (), (I,)), (R, O)), S> for F
    where
        F: Fn(State<S>, I) -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        I: FromRequest,
        S: Send + Sync + 'static,
    {
        async fn call(&self, state: S, req: Request) -> Response {
            let param: I = match I::from_request(req).await {
                Ok(v) => v,
                Err(r) => return r.into_response(),
            };
            self(State(state), param).await.into_response()
        }
    }

    macro_rules! impl_endpoint_service_fn_sealed_tuple {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, State, $($ty),+> Sealed<(F, ((), ($($ty),+,), ()), (R, O)), State> for F
                where
                    F: Fn($($ty),+) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    State: Send + Sync + 'static,
                    $($ty: FromRequestContextRefPair),+,
            {

                async fn call(&self, _state: State, req: Request) -> Response {
                        let (parts, _body) = req.into_parts();
                        $(let $ty = match $ty::from_request_context_ref_pair(&parts).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        });+;
                        self($($ty),+).await.into_response()
                    }
            }
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple);

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_state {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, S, $($ty),+> Sealed<(F, ((S,), ($($ty),+,), ()), (R, O)), S> for F
                where
                    F: Fn(State<S>, $($ty),+) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    S: Send + Sync + 'static,
                    $($ty: FromRequestContextRefPair),+,
            {

                async fn call(&self, state: S, req: Request) -> Response {
                        let (parts, _body) = req.into_parts();
                        $(let $ty = match $ty::from_request_context_ref_pair(&parts).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        });+;
                        self(State(state), $($ty),+).await.into_response()
                    }
            }
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple_with_state);

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_from_request {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, S, $($ty),+, I> Sealed<(F, ((), ($($ty),+,), I), (R, O)), S> for F
                where
                    F: Fn($($ty),+, I) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    I: FromRequest,
                    S: Send + Sync + 'static,
                    $($ty: FromRequestContextRefPair),+,
            {

                async fn call(&self, _state: S, req: Request) -> Response {
                        let (parts, body) = req.into_parts();
                        $(let $ty = match $ty::from_request_context_ref_pair(&parts).await {
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

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_from_request_with_state {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, S, $($ty),+, I> Sealed<(F, ((S,), ($($ty),+,), I), (R, O)), S> for F
                where
                    F: Fn(State<S>, $($ty),+, I) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    I: FromRequest,
                    S: Send + Sync + 'static,
                    $($ty: FromRequestContextRefPair),+,
            {

                async fn call(&self, state: S, req: Request) -> Response {
                        let (parts, body) = req.into_parts();
                        $(let $ty = match $ty::from_request_context_ref_pair(&parts).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        });+;
                        let req = Request::from_parts(parts, body);
                        let last: I = match I::from_request(req).await {
                            Ok(v) => v,
                            Err(r) => return r.into_response(),
                        };
                        self(State(state), $($ty),+, last).await.into_response()
                    }
            }
        };
    }

    all_the_tuples_no_last_special_case!(
        impl_endpoint_service_fn_sealed_tuple_with_from_request_with_state
    );
}
