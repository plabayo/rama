//! matchers to match a request to a web service

mod or_matcher;
pub use or_matcher::{or, Or};

mod method;
pub use method::MethodFilter;

mod domain;
pub use domain::DomainFilter;

pub mod uri;
pub use uri::UriFilter;

mod path;
pub use path::{PathFilter, UriParams, UriParamsDeserializeError};

use crate::{
    http::Request,
    service::{context::Extensions, Context},
};

/// condition to decide whether [`Request`] within the given [`Context`] matches to a defined (web) [`Service`]
///
/// [`Service`]: crate::service::Service
pub trait Matcher<State, Body>: Send + Sync + 'static {
    /// returns true on a match, false otherwise
    fn matches(&self, ext: &mut Extensions, ctx: &Context<State>, req: &Request<Body>) -> bool;
}

macro_rules! impl_matcher_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Body, $($ty),+> Matcher<State, Body> for ($($ty),+,)
            where $($ty: Matcher<State, Body>),+
        {
            fn matches(&self, ext: &mut Extensions, ctx: &Context<State>, req: &Request<Body>) -> bool {
                let ($($ty),+,) = self;
                $($ty.matches(ext, ctx, req))&&+
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_matcher_tuple);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_matcher_or() {
        let m = or!(MethodFilter::GET, MethodFilter::POST);

        // ok
        assert!(m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder().method("GET").body(()).unwrap()
        ));
        assert!(m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder().method("POST").body(()).unwrap()
        ));

        // not ok
        assert!(!m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder().method("PUT").body(()).unwrap()
        ));
    }

    #[test]
    fn test_matcher_and() {
        let m = (MethodFilter::GET, DomainFilter::new("www.example.com"));

        // ok
        assert!(m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder()
                .method("GET")
                .uri("http://www.example.com")
                .body(())
                .unwrap()
        ));

        // not ok
        assert!(!m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder()
                .method("GET")
                .uri("http://example.com")
                .body(())
                .unwrap()
        ));
        assert!(!m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder()
                .method("POST")
                .uri("http://www.example.com")
                .body(())
                .unwrap()
        ));
    }

    #[test]
    fn test_matcher_and_or() {
        let m = or!(
            (MethodFilter::GET, DomainFilter::new("www.example.com")),
            MethodFilter::POST
        );

        // ok
        assert!(m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder()
                .method("GET")
                .uri("http://www.example.com")
                .body(())
                .unwrap()
        ));
        assert!(m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder().method("POST").body(()).unwrap()
        ));

        // not ok
        assert!(!m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder()
                .method("GET")
                .uri("http://example.com")
                .body(())
                .unwrap()
        ));
        assert!(!m.matches(
            &mut Extensions::new(),
            &Context::default(),
            &Request::builder()
                .method("PUT")
                .uri("http://www.example.com")
                .body(())
                .unwrap()
        ));
    }

    #[test]
    fn test_ensure_or_keeps_only_matched_state() {
        let m = or!(
            (PathFilter::new("/foo/:bar"), MethodFilter::GET),
            MethodFilter::POST
        );

        let mut ext = Extensions::new();
        let ctx = Context::default();
        let req = Request::builder()
            .method("POST")
            .uri("http://www.example.com/foo/42")
            .body(())
            .unwrap();

        assert!(m.matches(&mut ext, &ctx, &req));
        assert!(ext.get::<UriParams>().is_none());
    }
}
