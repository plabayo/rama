use crate::{
    matcher::{Extensions, Matcher},
    Context,
};
use std::any::Any;

pub struct ExtensionMatcher<T: Send + Sync> {
    marker: T,
}

struct Const<T: Send + Sync>(T);
struct FnBox(Box<dyn Fn(&dyn Any) -> bool + Send + Sync>);

impl ExtensionMatcher<FnBox> {
    pub fn with<T: Send + Sync + 'static, F: Fn(&T) -> bool + Send + Sync + 'static>(f: F) -> Self {
        let wrapped_fn = move |v: &dyn Any| {
            if let Some(concrete) = v.downcast_ref::<T>() {
                f(concrete)
            } else {
                false
            }
        };
        Self {
            marker: FnBox(Box::new(wrapped_fn)),
        }
    }
}

impl<T: Send + Sync + Sync + std::cmp::PartialEq> ExtensionMatcher<Const<T>> {
    pub fn constant(value: T) -> Self {
        Self {
            marker: Const(value),
        }
    }
}

impl<T: Send + Sync + std::cmp::PartialEq + 'static, State, Request> Matcher<State, Request>
    for ExtensionMatcher<Const<T>>
{
    fn matches(&self, _ext: Option<&mut Extensions>, ctx: &Context<State>, _req: &Request) -> bool {
        ctx.get::<T>()
            .map(|v| v == &self.marker.0)
            .unwrap_or_default()
    }
}

impl<State, Request> Matcher<State, Request> for ExtensionMatcher<FnBox> {
    fn matches(&self, _ext: Option<&mut Extensions>, ctx: &Context<State>, _req: &Request) -> bool {
        ctx.get::<FnBox>()
            .map(|v| (self.marker.0)(v))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::context::Extensions;

    #[derive(Clone, PartialEq)]
    struct MyMarker(i32);

    #[test]
    fn test_extension_matcher() {
        let mut ext = Extensions::new();
        ext.insert(MyMarker(10));
        let matcher = ExtensionMatcher::constant(MyMarker(10));
        assert!(matcher.matches(Some(&mut ext), &Context::default(), &10));
    }

    #[test]
    fn test_fn_extension_matcher() {
        let mut ext = Extensions::new();
        ext.insert(MyMarker(10));
        let matcher = ExtensionMatcher::with(|v: &MyMarker| v.0.eq(&10));
        assert!(matcher.matches(Some(&mut ext), &Context::default(), &10));
    }
}
