use rama_utils::macros::all_the_tuples_no_last_special_case;

use super::extract::{FromPartsStateRefPair, FromRequest};
use crate::Request;

// Generic T = (Function, Input, Output)
// Input = ((FromPartsStateRefPair), (FromRequest))

/// [`rama_core::Service`] implemented for functions taking extractors.
pub trait EndpointServiceFn<T, O, E, State>:
    private::Sealed<T, O, E, State> + Clone + Send + Sync + 'static
{
}

impl<F, R, O, E, State> EndpointServiceFn<(F, ((), ()), (R, O)), O, E, State> for F
where
    F: Fn() -> R + Send + Sync + Clone + 'static,
    R: Future<Output = Result<O, E>> + Send + 'static,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, E, I, State> EndpointServiceFn<(F, ((), (I,)), (R, O)), O, E, State> for F
where
    F: Fn(I) -> R + Send + Sync + Clone + 'static,
    R: Future<Output = Result<O, E>> + Send + 'static,
    E: From<I::Rejection>,
    I: FromRequest,
    State: Send + Sync + 'static,
{
}

macro_rules! impl_endpoint_service_fn_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, E, State, $($ty),+> EndpointServiceFn<(F, (($($ty),+,), ()), (R, O)), O, E, State> for F
            where
                F: Fn($($ty),+) -> R + Send + Sync + Clone + 'static,
                R: Future<Output = Result<O, E>> + Send + 'static,
                State: Send + Sync + 'static,
                $($ty: FromPartsStateRefPair<State>),+,
                $(E: From<$ty::Rejection>),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple);

macro_rules! impl_endpoint_service_fn_tuple_with_from_request {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, E, State, $($ty),+, I> EndpointServiceFn<(F, (($($ty),+,), I), (R, O)), O, E, State> for F
            where
                F: Fn($($ty),+, I) -> R + Send + Sync + Clone + 'static,
                R: Future<Output = Result<O, E>> + Send + 'static,
                State: Send + Sync + 'static,
                I: FromRequest,
                E: From<I::Rejection>,
                $($ty: FromPartsStateRefPair<State>),+,
                $(E: From<$ty::Rejection>),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_from_request);

mod private {
    use super::*;

    pub trait Sealed<T, O, E, State> {
        /// Serve a response for the given request.
        ///
        /// It is expected to do so by extracting the desired data from the context and/or request,
        /// and then calling the function with the extracted data.
        fn call(&self, req: Request, state: &State) -> impl Future<Output = Result<O, E>> + Send;
    }

    impl<F, R, O, E, State> Sealed<(F, ((), ()), (R, O)), O, E, State> for F
    where
        F: Fn() -> R + Send + Sync + 'static,
        R: Future<Output = Result<O, E>> + Send + 'static,
        State: Send + Sync,
    {
        async fn call(&self, _req: Request, _state: &State) -> Result<O, E> {
            self().await
        }
    }

    impl<F, R, O, E, I, State> Sealed<(F, ((), (I,)), (R, O)), O, E, State> for F
    where
        F: Fn(I) -> R + Send + Sync + 'static,
        R: Future<Output = Result<O, E>> + Send + 'static,
        I: FromRequest,
        E: From<I::Rejection>,
        State: Send + Sync,
    {
        async fn call(&self, req: Request, _state: &State) -> Result<O, E> {
            let param = I::from_request(req).await?;
            self(param).await
        }
    }

    macro_rules! impl_endpoint_service_fn_sealed_tuple {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, E, State, $($ty),+> Sealed<(F, (($($ty),+,), ()), (R, O)), O, E, State> for F
                where
                    F: Fn($($ty),+) -> R + Send + Sync + 'static,
                    R: Future<Output = Result<O, E>> + Send + 'static,
                    State: Send + Sync,
                    $($ty: FromPartsStateRefPair<State>),+,
                    $(E: From<$ty::Rejection>),+,
            {
                async fn call(&self, req: Request, state: &State) -> Result<O, E> {
                    let (parts, _body) = req.into_parts();
                    $(let $ty = $ty::from_parts_state_ref_pair(&parts, &state).await?);+;
                    self($($ty),+).await
                }
            }
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple);

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_from_request {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, E, State, $($ty),+, I> Sealed<(F, (($($ty),+,), I), (R, O)), O, E, State> for F
                where
                    F: Fn($($ty),+, I) -> R + Send + Sync + 'static,
                    R: Future<Output = Result<O, E>> + Send + 'static,
                    State: Send + Sync,
                    I: FromRequest,
                    E: From<I::Rejection>,
                    $($ty: FromPartsStateRefPair<State>),+,
                    $(E: From<$ty::Rejection>),+,
            {
                async fn call(&self, req: Request, state: &State) -> Result<O, E> {
                        let (parts, body) = req.into_parts();
                        $(let $ty = $ty::from_parts_state_ref_pair(&parts, &state).await?);+;
                        let req = Request::from_parts(parts, body);
                        let last = I::from_request(req).await?;
                        self($($ty),+, last).await
                    }
            }
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple_with_from_request);
}
