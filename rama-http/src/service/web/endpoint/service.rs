use super::IntoResponse;
use super::extract::{FromPartsStateRefPair, FromRequest};
use crate::{Request, Response};
use rama_utils::macros::all_the_tuples_no_last_special_case;

// Generic T = (Function, Input, Output)
// Input = ((FromPartsStateRefPair), (FromRequest))

/// [`rama_core::Service`] implemented for functions taking extractors.
pub trait EndpointServiceFn<T, State>:
    private::Sealed<T, State> + Clone + Send + Sync + 'static
{
}

impl<F, R, O, State> EndpointServiceFn<(F, ((), ()), (R, O)), State> for F
where
    F: Fn() -> R + Send + Sync + Clone + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, I, State> EndpointServiceFn<(F, ((), (I,)), (R, O)), State> for F
where
    F: Fn(I) -> R + Send + Sync + Clone + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + Sync + 'static,
    I: FromRequest,
    State: Send + Sync + 'static,
{
}

macro_rules! impl_endpoint_service_fn_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, State, $($ty),+> EndpointServiceFn<(F, (($($ty),+,), ()), (R, O)), State> for F
            where
                F: Fn($($ty),+) -> R + Send + Sync + Clone + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                State: Send + Sync + 'static,
                $($ty: FromPartsStateRefPair<State>),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple);

macro_rules! impl_endpoint_service_fn_tuple_with_from_request {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, State, $($ty),+, I> EndpointServiceFn<(F, (($($ty),+,), I), (R, O)), State> for F
            where
                F: Fn($($ty),+, I) -> R + Send + Sync + Clone + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + Sync + 'static,
                I: FromRequest,
                State: Send + Sync + 'static,
                $($ty: FromPartsStateRefPair<State>),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_from_request);

mod private {
    use super::*;

    pub trait Sealed<T, State> {
        /// Serve a response for the given request.
        ///
        /// It is expected to do so by extracting the desired data from the context and/or request,
        /// and then calling the function with the extracted data.
        fn call(&self, req: Request, state: &State) -> impl Future<Output = Response> + Send;
    }

    impl<F, R, O, State> Sealed<(F, ((), ()), (R, O)), State> for F
    where
        F: Fn() -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        State: Send + Sync,
    {
        async fn call(&self, _req: Request, _state: &State) -> Response {
            self().await.into_response()
        }
    }

    impl<F, R, O, I, State> Sealed<(F, ((), (I,)), (R, O)), State> for F
    where
        F: Fn(I) -> R + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + Sync + 'static,
        I: FromRequest,
        State: Send + Sync,
    {
        async fn call(&self, req: Request, _state: &State) -> Response {
            let param: I = match I::from_request(req).await {
                Ok(v) => v,
                Err(r) => return r.into_response(),
            };
            self(param).await.into_response()
        }
    }

    macro_rules! impl_endpoint_service_fn_sealed_tuple {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, State, $($ty),+> Sealed<(F, (($($ty),+,), ()), (R, O)), State> for F
                where
                    F: Fn($($ty),+) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    State: Send + Sync,
                    $($ty: FromPartsStateRefPair<State>),+,
            {

                async fn call(&self, req: Request, state: &State) -> Response {
                        let (parts, _body) = req.into_parts();
                        $(let $ty = match $ty::from_parts_state_ref_pair(&parts, &state).await {
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
            impl<F, R, O, State, $($ty),+, I> Sealed<(F, (($($ty),+,), I), (R, O)), State> for F
                where
                    F: Fn($($ty),+, I) -> R + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + Sync + 'static,
                    I: FromRequest,
                    State: Send + Sync,
                    $($ty: FromPartsStateRefPair<State>),+,
            {

                async fn call(&self, req: Request, state: &State) -> Response {
                        let (parts, body) = req.into_parts();
                        $(let $ty = match $ty::from_parts_state_ref_pair(&parts, &state).await {
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
}
