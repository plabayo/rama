use crate::service::{layer::limit, Context, Layer, Service};

macro_rules! create_either {
    ($id:ident, $guard_id:ident, $($param:ident),+ $(,)?) => {
        #[derive(Debug)]
        /// A type to allow you to use multiple types as a single type.
        ///
        /// Implements:
        ///
        /// - the [`Service`] trait;
        /// - the [`Layer`] trait;
        /// - the [`Policy`] trait;
        ///
        /// and will delegate the functionality to the type that is wrapped in the `Either` type.
        /// To keep it easy all wrapped types are expected to work with the same inputs and outputs.
        ///
        /// [`Policy`]: crate::service::layer::limit::policy::Policy
        /// [`Service`]: crate::service::Service
        /// [`Layer`]: crate::service::Layer
        pub enum $id<$($param),+> {
            $(
                /// option $param
                $param($param),
            )+
        }

        impl<$($param),+> Clone for $id<$($param),+>
        where
            $($param: Clone),+
        {
            fn clone(&self) -> Self {
                match self {
                    $(
                        $id::$param(s) => $id::$param(s.clone()),
                    )+
                }
            }
        }

        impl<$($param),+, State, Request, Response, Error> Service<State, Request> for $id<$($param),+>
        where
            $($param: Service<State, Request, Response = Response, Error = Error>),+,
            Request: Send + 'static,
            State: Send + Sync + 'static,
            Response: Send + 'static,
            Error: Send + Sync + 'static,
        {
            type Response = Response;
            type Error = Error;

            async fn serve(&self, ctx: Context<State>, req: Request) -> Result<Self::Response, Self::Error> {
                match self {
                    $(
                        $id::$param(s) => s.serve(ctx, req).await,
                    )+
                }
            }
        }

        impl<$($param),+, S> Layer<S> for $id<$($param),+>
        where
            $($param: Layer<S>),+,
        {
            type Service = $id<$($param::Service),+>;

            fn layer(&self, inner: S) -> Self::Service {
                match self {
                    $(
                        $id::$param(layer) => $id::$param(layer.layer(inner)),
                    )+
                }
            }
        }

        #[derive(Debug)]
        /// The [`Policy`] guard for the [`$id`] combinator.
        ///
        /// [`Policy`]: crate::service::layer::limit::policy::Policy
        pub enum $guard_id<$($param),+> {
            $(
                $param($param),
            )+
        }

        impl<$($param),+> Clone for $guard_id<$($param),+>
        where
            $($param: Clone),+
        {
            fn clone(&self) -> Self {
                match self {
                    $(
                        $guard_id::$param(s) => $guard_id::$param(s.clone()),
                    )+
                }
            }
        }

        impl<$($param),+, State, Request, Error> limit::Policy<State, Request> for $id<$($param),+>
        where
            $($param: limit::Policy<State, Request, Error = Error>),+,
            Request: Send + 'static,
            State: Send + Sync + 'static,
            Error: Send + Sync + 'static,
        {
            type Guard = $guard_id<$($param::Guard),+>;
            type Error = Error;

            async fn check(
                &self,
                ctx: Context<State>,
                req: Request,
            ) -> limit::policy::PolicyResult<State, Request, Self::Guard, Self::Error> {
                match self {
                    $(
                        $id::$param(policy) => {
                            let result = policy.check(ctx, req).await;
                            match result.output {
                                limit::policy::PolicyOutput::Ready(guard) => limit::policy::PolicyResult {
                                    ctx: result.ctx,
                                    request: result.request,
                                    output: limit::policy::PolicyOutput::Ready($guard_id::$param(guard)),
                                },
                                limit::policy::PolicyOutput::Abort(err) => limit::policy::PolicyResult {
                                    ctx: result.ctx,
                                    request: result.request,
                                    output: limit::policy::PolicyOutput::Abort(err),
                                },
                                limit::policy::PolicyOutput::Retry => limit::policy::PolicyResult {
                                    ctx: result.ctx,
                                    request: result.request,
                                    output: limit::policy::PolicyOutput::Retry,
                                },
                            }
                        }
                    )+
                }
            }
        }
    };
}

create_either!(Either, EitherGuard, A, B,);
create_either!(Either3, EitherGuard3, A, B, C,);
create_either!(Either4, EitherGuard4, A, B, C, D,);
create_either!(Either5, EitherGuard5, A, B, C, D, E,);
create_either!(Either6, EitherGuard6, A, B, C, D, E, F,);
create_either!(Either7, EitherGuard7, A, B, C, D, E, F, G,);
create_either!(Either8, EitherGuard8, A, B, C, D, E, F, G, H,);
create_either!(Either9, EitherGuard9, A, B, C, D, E, F, G, H, I,);
