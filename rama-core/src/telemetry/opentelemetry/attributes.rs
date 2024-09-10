use crate::Context;
use opentelemetry::KeyValue;

/// Trait that can be used to implement your own attributes
/// creator. It is used by layers as a starting point for attributes,
/// and they will add their own attributes on top.
pub trait AttributesFactory<State>: Send + Sync + 'static {
    /// Create an attributes [`Vec`].
    ///
    /// The `size_hint` indicates how many attributes the _callee_
    /// may wish to add on top
    fn attributes(&self, size_hint: usize, ctx: &Context<State>) -> Vec<KeyValue>;
}

impl<State> AttributesFactory<State> for () {
    fn attributes(&self, size_hint: usize, _ctx: &Context<State>) -> Vec<KeyValue> {
        Vec::with_capacity(size_hint)
    }
}

impl<State> AttributesFactory<State> for Vec<KeyValue> {
    fn attributes(&self, size_hint: usize, _ctx: &Context<State>) -> Vec<KeyValue> {
        let mut attributes = self.clone();
        attributes.reserve(size_hint);
        attributes
    }
}

impl<State, F> AttributesFactory<State> for F
where
    F: Fn(usize, &Context<State>) -> Vec<KeyValue> + Send + Sync + 'static,
{
    fn attributes(&self, size_hint: usize, _ctx: &Context<State>) -> Vec<KeyValue> {
        Vec::with_capacity(size_hint)
    }
}
