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
    type Output;
    /// Error that is returned in case the transformation failed.
    type Error;

    /// Transforms the state from the input [`Context`] either in a new state object,
    /// or an error should it have failed.
    fn transform_state(&self, ctx: &Context<Input>) -> Result<Self::Output, Self::Error>;
}

impl<Input> StateTransformer<Input> for ()
where
    Input: Clone,
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

    use crate::context::{AsRef, StateTransformer};
    use crate::rt::Executor;
    use crate::Context;
    use std::ops::Deref;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    struct Database;

    #[derive(AsRef)]
    struct State {
        db: Database,
    }

    #[derive(AsRef)]
    struct ConnectionState {
        inner: Arc<State>,
        counter: Arc<AtomicU64>,
    }

    impl<T> AsRef<T> for ConnectionState
    where
        State: AsRef<T>,
    {
        fn as_ref(&self) -> &T {
            self.inner.deref().as_ref()
        }
    }

    impl From<Arc<State>> for ConnectionState {
        fn from(inner: Arc<State>) -> Self {
            Self {
                inner,
                counter: Arc::new(AtomicU64::new(0)),
            }
        }
    }

    fn assert_database<T: AsRef<Database>>(_t: &T) {}
    fn assert_counter<T: AsRef<Arc<AtomicU64>>>(_t: &T) {}

    #[test]
    fn test_state_wrapper() {
        let state = Arc::new(State { db: Database });
        let connection_state = ConnectionState::from(state.clone());

        assert_database(state.deref());
        assert_database(&connection_state);
        assert_counter(&connection_state);
    }

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
