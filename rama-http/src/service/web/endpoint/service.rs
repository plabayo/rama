use std::convert::Infallible;

use rama_utils::macros::all_the_tuples_no_last_special_case;

use crate::{
    Request,
    service::web::{
        endpoint::response::ErrorResponse,
        extract::{FromPartsStateRefPair, FromRequest},
        response::IntoResponse,
    },
};

// Generic T = (Function, Input, Output)
// Input = ((FromPartsStateRefPair), (FromRequest))

/// [`rama_core::Service`] implemented for functions taking extractors.
pub trait EndpointServiceFn<T, State>:
    private::Sealed<T, State> + Clone + Send + Sync + 'static
{
}

impl<F, R, O, E, State> EndpointServiceFn<(F, ((), ()), (R, O)), State> for F
where
    F: Fn() -> R + Clone + Send + Sync + 'static,
    R: Future<Output = Result<O, E>> + Send + 'static,
    O: Send + 'static,
    E: Send + 'static,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, State> EndpointServiceFn<(F, ((), ()), (R, O), Infallible), State> for F
where
    F: Fn() -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + 'static,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, E, I, State> EndpointServiceFn<(F, ((), (I,)), (R, O)), State> for F
where
    F: Fn(I) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = Result<O, E>> + Send + 'static,
    O: Send + 'static,
    E: Send + From<I::Rejection> + 'static,
    I: FromRequest,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, I, State> EndpointServiceFn<(F, ((), (I,)), (R, O), Infallible), State> for F
where
    F: Fn(I) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + 'static,
    I: FromRequest,
    ErrorResponse: From<I::Rejection>,
    State: Send + Sync + 'static,
{
}

macro_rules! impl_endpoint_service_fn_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, E, State, $($ty),+> EndpointServiceFn<(F, (($($ty),+,), ()), (R, O)), State> for F
            where
                F: Fn($($ty),+) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = Result<O, E>> + Send + 'static,
                O: Send + 'static,
                E: Send + 'static,
                State: Send + Sync + 'static,
                $($ty: FromPartsStateRefPair<State>),+,
                $(E: From<$ty::Rejection>),+,
        {
        }

        #[allow(non_snake_case)]
        impl<F, R, O, State, $($ty),+> EndpointServiceFn<(F, (($($ty),+,), ()), (R, O), Infallible), State> for F
            where
                F: Fn($($ty),+) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + 'static,
                State: Send + Sync + 'static,
                $($ty: FromPartsStateRefPair<State>),+,
                $(ErrorResponse: From<$ty::Rejection>),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple);

macro_rules! impl_endpoint_service_fn_tuple_with_from_request {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, E, State, $($ty),+, I> EndpointServiceFn<(F, (($($ty),+,), I), (R, O)), State> for F
            where
                F: Fn($($ty),+, I) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = Result<O, E>> + Send + 'static,
                O: Send + 'static,
                E: Send + 'static,
                State: Send + Sync + 'static,
                I: FromRequest,
                E: From<I::Rejection>,
                $($ty: FromPartsStateRefPair<State>),+,
                $(E: From<$ty::Rejection>),+,
        {
        }

        #[allow(non_snake_case)]
        impl<F, R, O, State, $($ty),+, I> EndpointServiceFn<(F, (($($ty),+,), I), (R, O), Infallible), State> for F
            where
                F: Fn($($ty),+, I) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + 'static,
                State: Send + Sync + 'static,
                I: FromRequest,
                ErrorResponse: From<I::Rejection>,
                $($ty: FromPartsStateRefPair<State>),+,
                $(ErrorResponse: From<$ty::Rejection>),+,
        {
        }
    };
}

all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_tuple_with_from_request);

mod private {
    use super::*;

    pub trait Sealed<T, State> {
        type Output: Send + 'static;
        type Error: Send + 'static;

        /// Serve a response for the given request.
        ///
        /// It is expected to do so by extracting the desired data from the context and/or request,
        /// and then calling the function with the extracted data.
        fn call(
            &self,
            req: Request,
            state: &State,
        ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;
    }

    impl<F, R, O, E, State> Sealed<(F, ((), ()), (R, O)), State> for F
    where
        F: Fn() -> R + Clone + Send + Sync + 'static,
        R: Future<Output = Result<O, E>> + Send + 'static,
        O: Send + 'static,
        E: Send + 'static,
        State: Send + Sync + 'static,
    {
        type Output = O;
        type Error = E;

        fn call(
            &self,
            _req: Request,
            _state: &State,
        ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send {
            self()
        }
    }

    impl<F, R, O, State> Sealed<(F, ((), ()), (R, O), Infallible), State> for F
    where
        F: Fn() -> R + Clone + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + 'static,
        State: Send + Sync + 'static,
    {
        type Output = O;
        type Error = ErrorResponse;

        async fn call(&self, _req: Request, _state: &State) -> Result<Self::Output, Self::Error> {
            Ok(self().await)
        }
    }

    impl<F, R, O, E, I, State> Sealed<(F, ((), (I,)), (R, O)), State> for F
    where
        F: Fn(I) -> R + Clone + Send + Sync + 'static,
        R: Future<Output = Result<O, E>> + Send + 'static,
        O: Send + 'static,
        E: Send + From<I::Rejection> + 'static,
        I: FromRequest,
        State: Send + Sync + 'static,
    {
        type Output = O;
        type Error = E;

        async fn call(&self, req: Request, _state: &State) -> Result<Self::Output, Self::Error> {
            let param = I::from_request(req).await?;
            self(param).await
        }
    }

    impl<F, R, O, I, State> Sealed<(F, ((), (I,)), (R, O), Infallible), State> for F
    where
        F: Fn(I) -> R + Clone + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + 'static,
        I: FromRequest,
        ErrorResponse: From<I::Rejection>,
        State: Send + Sync + 'static,
    {
        type Output = O;
        type Error = ErrorResponse;

        async fn call(&self, req: Request, _state: &State) -> Result<Self::Output, Self::Error> {
            let param = I::from_request(req).await?;
            Ok(self(param).await)
        }
    }

    macro_rules! impl_endpoint_service_fn_sealed_tuple {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, E, State, $($ty),+> Sealed<(F, (($($ty),+,), ()), (R, O)), State> for F
                where
                    F: Fn($($ty),+) -> R + Clone + Send + Sync + 'static,
                    R: Future<Output = Result<O, E>> + Send + 'static,
                    O: Send + 'static,
                    E: Send + 'static,
                    State: Send + Sync + 'static,
                    $($ty: FromPartsStateRefPair<State>),+,
                    $(E: From<$ty::Rejection>),+,
            {
                type Output = O;
                type Error = E;

                async fn call(&self, req: Request, state: &State) -> Result<O, E> {
                    let (parts, _body) = req.into_parts();
                    $(let $ty = $ty::from_parts_state_ref_pair(&parts, &state).await?);+;
                    self($($ty),+).await
                }
            }

            #[allow(non_snake_case)]
            impl<F, R, O, State, $($ty),+> Sealed<(F, (($($ty),+,), ()), (R, O), Infallible), State> for F
                where
                    F: Fn($($ty),+) -> R + Clone + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + 'static,
                    State: Send + Sync + 'static,
                    $($ty: FromPartsStateRefPair<State>),+,
                    $(ErrorResponse: From<$ty::Rejection>),+,
            {
                type Output = O;
                type Error = ErrorResponse;

                async fn call(&self, req: Request, state: &State) -> Result<Self::Output, Self::Error> {
                    let (parts, _body) = req.into_parts();
                    $(let $ty = $ty::from_parts_state_ref_pair(&parts, &state).await?);+;
                    Ok(self($($ty),+).await)
                }
            }
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple);

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_from_request {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, E, State, $($ty),+, I> Sealed<(F, (($($ty),+,), I), (R, O)), State> for F
                where
                    F: Fn($($ty),+, I) -> R + Clone + Send + Sync + 'static,
                    R: Future<Output = Result<O, E>> + Send + 'static,
                    O: Send + 'static,
                    E: Send + 'static,
                    State: Send + Sync + 'static,
                    I: FromRequest,
                    E: From<I::Rejection>,
                    $($ty: FromPartsStateRefPair<State>),+,
                    $(E: From<$ty::Rejection>),+,
            {
                type Output = O;
                type Error = E;

                async fn call(&self, req: Request, state: &State) -> Result<O, E> {
                    let (parts, body) = req.into_parts();
                    $(let $ty = $ty::from_parts_state_ref_pair(&parts, &state).await?);+;
                    let req = Request::from_parts(parts, body);
                    let last = I::from_request(req).await?;
                    self($($ty),+, last).await
                }
            }

            #[allow(non_snake_case)]
            impl<F, R, O, State, $($ty),+, I> Sealed<(F, (($($ty),+,), I), (R, O), Infallible), State> for F
                where
                    F: Fn($($ty),+, I) -> R + Clone + Send + Sync + 'static,
                    R: Future<Output = O> + Send + 'static,
                    O: IntoResponse + Send + 'static,
                    State: Send + Sync + 'static,
                    I: FromRequest,
                    ErrorResponse: From<I::Rejection>,
                    $($ty: FromPartsStateRefPair<State>),+,
                    $(ErrorResponse: From<$ty::Rejection>),+,
            {
                type Output = O;
                type Error = ErrorResponse;

                async fn call(&self, req: Request, state: &State) -> Result<Self::Output, Self::Error> {
                    let (parts, body) = req.into_parts();
                    $(let $ty = $ty::from_parts_state_ref_pair(&parts, &state).await?);+;
                    let req = Request::from_parts(parts, body);
                    let last = I::from_request(req).await?;
                    Ok(self($($ty),+, last).await)
                }
            }
        };
    }

    all_the_tuples_no_last_special_case!(impl_endpoint_service_fn_sealed_tuple_with_from_request);
}
