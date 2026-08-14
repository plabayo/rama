#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use std::convert::Infallible;

use rama_utils::macros::{
    all_the_tuples_minus_one_no_last_special_case, all_the_tuples_no_last_special_case,
};

use crate::{
    Request,
    service::web::{
        endpoint::response::ErrorResponse,
        extract::{FromOwnedRequestParts, FromPartsStateRefPair, FromRequest, FromRequestBody},
        response::IntoResponse,
    },
};

// Generic T = (Input, () as Result<O, E> / Infallible as IntoResponse)
// Input = ((FromPartsStateRefPair), FromRequest)
//      or ((FromPartsStateRefPair), FromOwnedRequestParts, FromRequestBody)

/// [`rama_core::Service`] implemented for functions taking extractors.
pub trait EndpointServiceFn<T, State>:
    private::Sealed<T, State> + Clone + Send + Sync + 'static
{
}

impl<F, R, O, E, State> EndpointServiceFn<(((), ()), ()), State> for F
where
    F: Fn() -> R + Clone + Send + Sync + 'static,
    R: Future<Output = Result<O, E>> + Send + 'static,
    O: Send + 'static,
    E: Send + 'static,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, State> EndpointServiceFn<(((), ()), Infallible), State> for F
where
    F: Fn() -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + 'static,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, E, I, State> EndpointServiceFn<(((), I), ()), State> for F
where
    F: Fn(I) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = Result<O, E>> + Send + 'static,
    O: Send + 'static,
    E: Send + From<I::Rejection> + 'static,
    I: FromRequest,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, I, State> EndpointServiceFn<(((), I), Infallible), State> for F
where
    F: Fn(I) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + 'static,
    I: FromRequest,
    ErrorResponse: From<I::Rejection>,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, E, P, I, State> EndpointServiceFn<(((), P, I), ()), State> for F
where
    F: Fn(P, I) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = Result<O, E>> + Send + 'static,
    O: Send + 'static,
    E: Send + From<P::Rejection> + From<I::Rejection> + 'static,
    P: FromOwnedRequestParts,
    I: FromRequestBody,
    State: Send + Sync + 'static,
{
}

impl<F, R, O, P, I, State> EndpointServiceFn<(((), P, I), Infallible), State> for F
where
    F: Fn(P, I) -> R + Clone + Send + Sync + 'static,
    R: Future<Output = O> + Send + 'static,
    O: IntoResponse + Send + 'static,
    P: FromOwnedRequestParts,
    I: FromRequestBody,
    ErrorResponse: From<P::Rejection>,
    ErrorResponse: From<I::Rejection>,
    State: Send + Sync + 'static,
{
}

macro_rules! impl_endpoint_service_fn_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, E, State, $($ty),+> EndpointServiceFn<((($($ty),+,), ()), ()), State> for F
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
        impl<F, R, O, State, $($ty),+> EndpointServiceFn<((($($ty),+,), ()), Infallible), State> for F
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
        impl<F, R, O, E, State, $($ty),+, I> EndpointServiceFn<((($($ty),+,), I), ()), State> for F
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
        impl<F, R, O, State, $($ty),+, I> EndpointServiceFn<((($($ty),+,), I), Infallible), State> for F
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

macro_rules! impl_endpoint_service_fn_tuple_with_owned_parts_and_body {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<F, R, O, E, State, P, I, $($ty),+>
            EndpointServiceFn<((($($ty),+,), P, I), ()), State> for F
        where
            F: Fn($($ty),+, P, I) -> R + Clone + Send + Sync + 'static,
            R: Future<Output = Result<O, E>> + Send + 'static,
            O: Send + 'static,
            E: Send + From<P::Rejection> + From<I::Rejection> + 'static,
            State: Send + Sync + 'static,
            P: FromOwnedRequestParts,
            I: FromRequestBody,
            $($ty: FromPartsStateRefPair<State>),+,
            $(E: From<$ty::Rejection>),+,
        {
        }

        #[allow(non_snake_case)]
        impl<F, R, O, State, P, I, $($ty),+>
            EndpointServiceFn<((($($ty),+,), P, I), Infallible), State> for F
        where
            F: Fn($($ty),+, P, I) -> R + Clone + Send + Sync + 'static,
            R: Future<Output = O> + Send + 'static,
            O: IntoResponse + Send + 'static,
            State: Send + Sync + 'static,
            P: FromOwnedRequestParts,
            I: FromRequestBody,
            ErrorResponse: From<P::Rejection>,
            ErrorResponse: From<I::Rejection>,
            $($ty: FromPartsStateRefPair<State>),+,
            $(ErrorResponse: From<$ty::Rejection>),+,
        {
        }
    };
}

all_the_tuples_minus_one_no_last_special_case!(
    impl_endpoint_service_fn_tuple_with_owned_parts_and_body
);

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

    impl<F, R, O, E, State> Sealed<(((), ()), ()), State> for F
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

    impl<F, R, O, State> Sealed<(((), ()), Infallible), State> for F
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

    impl<F, R, O, E, I, State> Sealed<(((), I), ()), State> for F
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

    impl<F, R, O, I, State> Sealed<(((), I), Infallible), State> for F
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

    impl<F, R, O, E, P, I, State> Sealed<(((), P, I), ()), State> for F
    where
        F: Fn(P, I) -> R + Clone + Send + Sync + 'static,
        R: Future<Output = Result<O, E>> + Send + 'static,
        O: Send + 'static,
        E: Send + From<P::Rejection> + From<I::Rejection> + 'static,
        P: FromOwnedRequestParts,
        I: FromRequestBody,
        State: Send + Sync + 'static,
    {
        type Output = O;
        type Error = E;

        async fn call(&self, req: Request, _state: &State) -> Result<Self::Output, Self::Error> {
            let (parts, body) = req.into_parts();
            let last = I::from_request_body(&parts, body);
            let penultimate = P::from_owned_request_parts(parts).await?;
            let last = last.await?;
            self(penultimate, last).await
        }
    }

    impl<F, R, O, P, I, State> Sealed<(((), P, I), Infallible), State> for F
    where
        F: Fn(P, I) -> R + Clone + Send + Sync + 'static,
        R: Future<Output = O> + Send + 'static,
        O: IntoResponse + Send + 'static,
        P: FromOwnedRequestParts,
        I: FromRequestBody,
        ErrorResponse: From<P::Rejection>,
        ErrorResponse: From<I::Rejection>,
        State: Send + Sync + 'static,
    {
        type Output = O;
        type Error = ErrorResponse;

        async fn call(&self, req: Request, _state: &State) -> Result<Self::Output, Self::Error> {
            let (parts, body) = req.into_parts();
            let last = I::from_request_body(&parts, body);
            let penultimate = P::from_owned_request_parts(parts).await?;
            let last = last.await?;
            Ok(self(penultimate, last).await)
        }
    }

    macro_rules! impl_endpoint_service_fn_sealed_tuple {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, E, State, $($ty),+> Sealed<((($($ty),+,), ()), ()), State> for F
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
            impl<F, R, O, State, $($ty),+> Sealed<((($($ty),+,), ()), Infallible), State> for F
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
            impl<F, R, O, E, State, $($ty),+, I> Sealed<((($($ty),+,), I), ()), State> for F
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
            impl<F, R, O, State, $($ty),+, I> Sealed<((($($ty),+,), I), Infallible), State> for F
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

    macro_rules! impl_endpoint_service_fn_sealed_tuple_with_owned_parts_and_body {
        ($($ty:ident),+ $(,)?) => {
            #[allow(non_snake_case)]
            impl<F, R, O, E, State, P, I, $($ty),+>
                Sealed<((($($ty),+,), P, I), ()), State> for F
            where
                F: Fn($($ty),+, P, I) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = Result<O, E>> + Send + 'static,
                O: Send + 'static,
                E: Send + From<P::Rejection> + From<I::Rejection> + 'static,
                State: Send + Sync + 'static,
                P: FromOwnedRequestParts,
                I: FromRequestBody,
                $($ty: FromPartsStateRefPair<State>),+,
                $(E: From<$ty::Rejection>),+,
            {
                type Output = O;
                type Error = E;

                async fn call(&self, req: Request, state: &State) -> Result<O, E> {
                    let (parts, body) = req.into_parts();
                    $(let $ty = $ty::from_parts_state_ref_pair(&parts, &state).await?);+;
                    let last = I::from_request_body(&parts, body);
                    let penultimate = P::from_owned_request_parts(parts).await?;
                    let last = last.await?;
                    self($($ty),+, penultimate, last).await
                }
            }

            #[allow(non_snake_case)]
            impl<F, R, O, State, P, I, $($ty),+>
                Sealed<((($($ty),+,), P, I), Infallible), State> for F
            where
                F: Fn($($ty),+, P, I) -> R + Clone + Send + Sync + 'static,
                R: Future<Output = O> + Send + 'static,
                O: IntoResponse + Send + 'static,
                State: Send + Sync + 'static,
                P: FromOwnedRequestParts,
                I: FromRequestBody,
                ErrorResponse: From<P::Rejection>,
                ErrorResponse: From<I::Rejection>,
                $($ty: FromPartsStateRefPair<State>),+,
                $(ErrorResponse: From<$ty::Rejection>),+,
            {
                type Output = O;
                type Error = ErrorResponse;

                async fn call(&self, req: Request, state: &State) -> Result<Self::Output, Self::Error> {
                    let (parts, body) = req.into_parts();
                    $(let $ty = $ty::from_parts_state_ref_pair(&parts, &state).await?);+;
                    let last = I::from_request_body(&parts, body);
                    let penultimate = P::from_owned_request_parts(parts).await?;
                    let last = last.await?;
                    Ok(self($($ty),+, penultimate, last).await)
                }
            }
        };
    }

    all_the_tuples_minus_one_no_last_special_case!(
        impl_endpoint_service_fn_sealed_tuple_with_owned_parts_and_body
    );
}
