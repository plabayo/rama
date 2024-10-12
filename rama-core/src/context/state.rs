use super::Context;
use std::convert::Infallible;

/// Transforms the `State` embedded in the input [`Context`]
/// into the [`StateTransformer::Output`] state.
///
/// The transformer can return [`StateTransformer::Error`]
/// in case the transformation could not succeed. A common example
/// could be when depending on the availability of state, or
/// validation of dynamic (extension) state.
pub trait StateTransformer<Input> {
    /// Transformed `State` object.
    type Output: Clone + Send + Sync + 'static;
    /// Error that is returned in case the transformation failed.
    type Error;

    /// Transforms the state from the input [`Context`] either in a new state object,
    /// or an error should it have failed.
    fn transform_state(&self, ctx: &Context<Input>) -> Result<Self::Output, Self::Error>;
}

impl<Input> StateTransformer<Input> for ()
where
    Input: Clone + Send + Sync + 'static,
{
    type Output = Input;
    type Error = Infallible;

    fn transform_state(&self, ctx: &Context<Input>) -> Result<Self::Output, Self::Error> {
        Ok(ctx.state().clone())
    }
}

impl<F, Input, Output, Error> StateTransformer<Input> for F
where
    F: Fn(&Context<Input>) -> Result<Output, Error>,
    Input: Clone + Send + Sync + 'static,
    Output: Clone + Send + Sync + 'static,
{
    type Output = Output;
    type Error = Error;

    fn transform_state(&self, ctx: &Context<Input>) -> Result<Self::Output, Self::Error> {
        (self)(ctx)
    }
}

#[cfg(test)]
mod test {
    use rama_error::OpaqueError;

    use crate::context::StateTransformer;
    use crate::rt::Executor;
    use crate::Context;

    #[test]
    fn test_state_transform_default() {
        #[derive(Debug, Clone)]
        struct State {
            answer: usize,
        }

        let state =
            ().transform_state(&Context::new(State { answer: 42 }, Executor::default()))
                .unwrap();
        assert_eq!(state.answer, 42);
    }

    #[test]
    fn test_state_transform_custom() {
        #[derive(Debug, Clone)]
        struct State {
            answer: usize,
        }

        #[derive(Debug, Clone)]
        struct OutputState {
            answer: usize,
            multiplier_used: Multiplier,
        }

        #[derive(Debug, Clone)]
        struct Multiplier(usize);

        fn transformer(ctx: &Context<State>) -> Result<OutputState, OpaqueError> {
            let multiplier = ctx
                .get::<Multiplier>()
                .ok_or_else(|| OpaqueError::from_display("missing multipier"))?;
            Ok(OutputState {
                answer: ctx.state().answer * multiplier.0,
                multiplier_used: multiplier.clone(),
            })
        }

        let mut ctx = Context::new(State { answer: 21 }, Executor::default());

        assert!(transformer.transform_state(&ctx).is_err());

        ctx.insert(Multiplier(2));

        let state = transformer.transform_state(&ctx).unwrap();
        assert_eq!(state.answer, 42);
        assert_eq!(state.multiplier_used.0, 2);
    }
}
