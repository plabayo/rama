use crate::Context;
use opentelemetry::KeyValue;

/// Trait that can be used to implement your own attributes
/// creator. It is used by layers as a starting point for attributes,
/// and they will add their own attributes on top.
pub trait AttributesFactory: Send + Sync + 'static {
    /// Create an attributes [`Vec`].
    ///
    /// The `size_hint` indicates how many attributes the _callee_
    /// may wish to add on top
    fn attributes(&self, size_hint: usize, ctx: &Context) -> Vec<KeyValue>;
}

impl AttributesFactory for () {
    fn attributes(&self, size_hint: usize, _ctx: &Context) -> Vec<KeyValue> {
        Vec::with_capacity(size_hint)
    }
}

impl AttributesFactory for Vec<KeyValue> {
    fn attributes(&self, size_hint: usize, _ctx: &Context) -> Vec<KeyValue> {
        let mut attributes = self.clone();
        attributes.reserve(size_hint);
        attributes
    }
}

impl<F> AttributesFactory for F
where
    F: Fn(usize, &Context) -> Vec<KeyValue> + Send + Sync + 'static,
{
    fn attributes(&self, size_hint: usize, ctx: &Context) -> Vec<KeyValue> {
        (self)(size_hint, ctx)
    }
}
