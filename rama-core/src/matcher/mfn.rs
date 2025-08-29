use crate::context::Extensions;
use crate::{Context, matcher::Matcher};
use std::marker::PhantomData;

/// Create a [`MatchFn`] from a function.
pub fn match_fn<F, A>(f: F) -> MatchFnBox<F, A> {
    MatchFnBox {
        f,
        _marker: PhantomData,
    }
}

/// A [`MatchFn`] is a [`Matcher`] implemented using a function.
///
/// You do not need to implement this trait yourself.
/// Instead, you need to use the [`match_fn`] function to create a [`MatchFn`].
pub trait MatchFn<Request, A>: private::Sealed<Request, A> + Send + Sync + 'static {}

impl<F, Request> MatchFn<Request, ()> for F where F: Fn() -> bool + Send + Sync + 'static {}

impl<F, Request> MatchFn<Request, (Request,)> for F where
    F: Fn(&Request) -> bool + Send + Sync + 'static
{
}

impl<F, Request> MatchFn<Request, (Context, Request)> for F where
    F: Fn(&Context, &Request) -> bool + Send + Sync + 'static
{
}

impl<F, Request> MatchFn<Request, (Option<&mut Extensions>, Context, Request)> for F where
    F: Fn(Option<&mut Extensions>, &Context, &Request) -> bool + Send + Sync + 'static
{
}

impl<F, Request> MatchFn<Request, ((), (), Option<&mut Extensions>, Request)> for F where
    F: Fn(Option<&mut Extensions>, &Request) -> bool + Send + Sync + 'static
{
}

impl<F, Request> MatchFn<Request, ((), (), (), (), Option<&mut Extensions>)> for F where
    F: Fn(Option<&mut Extensions>) -> bool + Send + Sync + 'static
{
}

impl<F, Request> MatchFn<Request, ((), (), (), (), (), Context)> for F where
    F: Fn(&Context) -> bool + Send + Sync + 'static
{
}

impl<F, Request> MatchFn<Request, ((), (), (), (), (), (), Option<&mut Extensions>, Context)> for F where
    F: Fn(Option<&mut Extensions>, &Context) -> bool + Send + Sync + 'static
{
}

/// The public wrapper type for [`MatchFn`].
pub struct MatchFnBox<F, A> {
    f: F,
    _marker: PhantomData<fn(A) -> ()>,
}

impl<F, A> Clone for MatchFnBox<F, A>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            _marker: PhantomData,
        }
    }
}

impl<F, A> std::fmt::Debug for MatchFnBox<F, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchFnBox").finish()
    }
}

impl<F, Request, A> Matcher<Request> for MatchFnBox<F, A>
where
    A: Send + 'static,
    F: MatchFn<Request, A>,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context, req: &Request) -> bool {
        self.f.call(ext, ctx, req)
    }
}

mod private {
    use super::*;

    pub trait Sealed<Request, A> {
        /// returns true on a match, false otherwise
        ///
        /// `ext` is None in case the callee is not interested in collecting potential
        /// match metadata gathered during the matching process. An example of this
        /// path parameters for an http Uri matcher.
        fn call(&self, ext: Option<&mut Extensions>, ctx: &Context, req: &Request) -> bool;
    }

    impl<F, Request> Sealed<Request, ()> for F
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        fn call(&self, _ext: Option<&mut Extensions>, _ctx: &Context, _req: &Request) -> bool {
            (self)()
        }
    }

    impl<F, Request> Sealed<Request, (Request,)> for F
    where
        F: Fn(&Request) -> bool + Send + Sync + 'static,
    {
        fn call(&self, _ext: Option<&mut Extensions>, _ctx: &Context, req: &Request) -> bool {
            (self)(req)
        }
    }

    impl<F, Request> Sealed<Request, (Context, Request)> for F
    where
        F: Fn(&Context, &Request) -> bool + Send + Sync + 'static,
    {
        fn call(&self, _ext: Option<&mut Extensions>, ctx: &Context, req: &Request) -> bool {
            (self)(ctx, req)
        }
    }

    impl<F, Request> Sealed<Request, (Option<&mut Extensions>, Context, Request)> for F
    where
        F: Fn(Option<&mut Extensions>, &Context, &Request) -> bool + Send + Sync + 'static,
    {
        fn call(&self, ext: Option<&mut Extensions>, ctx: &Context, req: &Request) -> bool {
            (self)(ext, ctx, req)
        }
    }

    impl<F, Request> Sealed<Request, ((), (), Option<&mut Extensions>, Request)> for F
    where
        F: Fn(Option<&mut Extensions>, &Request) -> bool + Send + Sync + 'static,
    {
        fn call(&self, ext: Option<&mut Extensions>, _ctx: &Context, req: &Request) -> bool {
            (self)(ext, req)
        }
    }

    impl<F, Request> Sealed<Request, ((), (), (), (), Option<&mut Extensions>)> for F
    where
        F: Fn(Option<&mut Extensions>) -> bool + Send + Sync + 'static,
    {
        fn call(&self, ext: Option<&mut Extensions>, _ctx: &Context, _req: &Request) -> bool {
            (self)(ext)
        }
    }

    impl<F, Request> Sealed<Request, ((), (), (), (), (), Context)> for F
    where
        F: Fn(&Context) -> bool + Send + Sync + 'static,
    {
        fn call(&self, _ext: Option<&mut Extensions>, ctx: &Context, _req: &Request) -> bool {
            (self)(ctx)
        }
    }

    impl<F, Request> Sealed<Request, ((), (), (), (), (), (), Option<&mut Extensions>, Context)> for F
    where
        F: Fn(Option<&mut Extensions>, &Context) -> bool + Send + Sync + 'static,
    {
        fn call(&self, ext: Option<&mut Extensions>, ctx: &Context, _req: &Request) -> bool {
            (self)(ext, ctx)
        }
    }
}
