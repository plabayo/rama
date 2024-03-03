use super::*;

#[test]
fn test_always() {
    assert!(Always.matches(None, &Context::default(), &()));
    assert!(Always.matches(None, &Context::default(), &0));
    assert!(Always.matches(None, &Context::default(), &false));
    assert!(Always.matches(None, &Context::default(), &"foo"));
}

#[test]
fn test_not() {
    assert!(!Not::new(Always).matches(None, &Context::default(), &()));
}

#[test]
fn test_not_builder() {
    assert!(!Always::new().not().matches(None, &Context::default(), &()));
    assert!(!Always::new().not().matches(None, &Context::default(), &0));
    assert!(!Always::new()
        .not()
        .matches(None, &Context::default(), &false));
    assert!(!Always::new()
        .not()
        .matches(None, &Context::default(), &"foo"));
}

#[derive(Debug, Clone)]
struct OddMatcher;

impl<State> Matcher<State, u8> for OddMatcher {
    fn matches(&self, _ext: Option<&mut Extensions>, _ctx: &Context<State>, req: &u8) -> bool {
        *req % 2 != 0
    }
}

#[derive(Debug, Clone)]
struct EvenMatcher;

impl<State> Matcher<State, u8> for EvenMatcher {
    fn matches(&self, _ext: Option<&mut Extensions>, _ctx: &Context<State>, req: &u8) -> bool {
        *req % 2 == 0
    }
}

#[derive(Debug, Clone)]
struct ConstMatcher(u8);

impl<State> Matcher<State, u8> for ConstMatcher {
    fn matches(&self, _ext: Option<&mut Extensions>, _ctx: &Context<State>, req: &u8) -> bool {
        *req == self.0
    }
}

#[test]
fn test_option() {
    assert!(Option::<ConstMatcher>::None.matches(None, &Context::default(), &0));
    assert!(Some(ConstMatcher(0)).matches(None, &Context::default(), &0));
    assert!(!Some(ConstMatcher(1)).matches(None, &Context::default(), &0));
}

#[test]
fn test_and() {
    let matcher = and!(ConstMatcher(1), OddMatcher);
    assert!(!matcher.matches(None, &Context::default(), &0));
    assert!(matcher.matches(None, &Context::default(), &1));
    assert!(!matcher.matches(None, &Context::default(), &2));
    for i in 3..=255 {
        assert!(!matcher.matches(None, &Context::default(), &i), "i = {}", i);
    }
}

#[test]
fn test_and_builder() {
    let matcher = ConstMatcher(1).and(OddMatcher);
    assert!(!matcher.matches(None, &Context::default(), &0));
    assert!(matcher.matches(None, &Context::default(), &1));
    assert!(!matcher.matches(None, &Context::default(), &2));
    for i in 3..=255 {
        assert!(!matcher.matches(None, &Context::default(), &i), "i = {}", i);
    }
}

#[test]
fn test_or() {
    let matcher = or!(ConstMatcher(1), EvenMatcher);
    assert!(matcher.matches(None, &Context::default(), &0));
    assert!(matcher.matches(None, &Context::default(), &1));
    assert!(matcher.matches(None, &Context::default(), &2));
    for i in 3..=255 {
        if i % 2 == 0 {
            assert!(matcher.matches(None, &Context::default(), &i), "i = {}", i);
        } else {
            assert!(!matcher.matches(None, &Context::default(), &i), "i = {}", i);
        }
    }
}

#[test]
fn test_or_builder() {
    let matcher = ConstMatcher(1)
        .or(ConstMatcher(2))
        .or(ConstMatcher(3))
        .or(ConstMatcher(4))
        .or(ConstMatcher(5))
        .or(ConstMatcher(6))
        .or(ConstMatcher(7))
        .or(ConstMatcher(8))
        .or(ConstMatcher(9))
        .or(ConstMatcher(10))
        .or(ConstMatcher(11))
        .or(ConstMatcher(12));

    assert!(!matcher.matches(None, &Context::default(), &0));
    for i in 1..=12 {
        assert!(matcher.matches(None, &Context::default(), &i), "i = {}", i);
    }
    for i in 13..=255 {
        assert!(!matcher.matches(None, &Context::default(), &i), "i = {}", i);
    }
}

#[test]
fn test_and_never() {
    for i in 0..=255 {
        assert!(
            !and!(OddMatcher, EvenMatcher).matches(None, &Context::default(), &i),
            "i = {}",
            i
        );
    }
}

#[test]
fn test_or_never() {
    for i in 0..=255 {
        assert!(
            or!(OddMatcher, EvenMatcher).matches(None, &Context::default(), &i),
            "i = {}",
            i
        );
    }
}

#[test]
fn test_and_or() {
    let matcher = ConstMatcher(1)
        .or(ConstMatcher(2))
        .and(OddMatcher.or(EvenMatcher));
    assert!(matcher.matches(None, &Context::default(), &1));
    assert!(matcher.matches(None, &Context::default(), &2));
    for i in 3..=255 {
        assert!(!matcher.matches(None, &Context::default(), &i), "i = {}", i);
    }
}

#[test]
fn test_match_fn_always() {
    assert!(match_fn(|| true).matches(None, &Context::default(), &()));
    assert!(match_fn(|_: &Context<()>| true).matches(None, &Context::default(), &()));
    assert!(match_fn(|_: Option<&mut Extensions>| true).matches(None, &Context::default(), &()));
    assert!(
        match_fn(|_: Option<&mut Extensions>, _: &Context<()>| true).matches(
            None,
            &Context::default(),
            &()
        )
    );
    assert!(match_fn(|_: &Context<()>, _: &()| true).matches(None, &Context::default(), &()));
    assert!(match_fn(|_: &()| true).matches(None, &Context::default(), &()));
    assert!(match_fn(|_: &u8| true).matches(None, &Context::default(), &0));
    assert!(match_fn(|_: &bool| true).matches(None, &Context::default(), &false));
    assert!(match_fn(|_: &&str| true).matches(None, &Context::default(), &"foo"));
}

#[test]
fn test_match_fn() {
    let matcher = match_fn(|req: &u8| *req % 2 != 0);
    for i in 0..=255 {
        if i % 2 != 0 {
            assert!(matcher.matches(None, &Context::default(), &i), "i = {}", i);
        } else {
            assert!(!matcher.matches(None, &Context::default(), &i), "i = {}", i);
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
enum TestMatchers {
    Const(ConstMatcher),
    Even(EvenMatcher),
    Odd(OddMatcher),
}

impl<State> Matcher<State, u8> for TestMatchers {
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &u8) -> bool {
        match self {
            TestMatchers::Const(m) => m.matches(ext, ctx, req),
            TestMatchers::Even(m) => m.matches(ext, ctx, req),
            TestMatchers::Odd(m) => m.matches(ext, ctx, req),
        }
    }
}

#[test]
fn test_enum_matcher() {
    assert!(!TestMatchers::Const(ConstMatcher(1)).matches(None, &Context::default(), &0));
    assert!(TestMatchers::Const(ConstMatcher(1)).matches(None, &Context::default(), &1));
    assert!(!TestMatchers::Even(EvenMatcher).matches(None, &Context::default(), &1));
    assert!(TestMatchers::Even(EvenMatcher).matches(None, &Context::default(), &2));
    assert!(!TestMatchers::Odd(OddMatcher).matches(None, &Context::default(), &2));
    assert!(TestMatchers::Odd(OddMatcher).matches(None, &Context::default(), &3));
}

#[test]
fn test_iter_enum_and() {
    let matchers = vec![
        TestMatchers::Const(ConstMatcher(1)),
        TestMatchers::Odd(OddMatcher),
    ];

    assert!(matchers[0].matches(None, &Context::default(), &1));
    assert!(matchers[1].matches(None, &Context::default(), &1));

    for matcher in matchers.iter() {
        assert!(matcher.matches(None, &Context::default(), &1));
    }

    assert!(matchers.iter().matches_and(None, &Context::default(), &1));
    assert!(!matchers.iter().matches_and(None, &Context::default(), &3));
    assert!(!matchers.iter().matches_and(None, &Context::default(), &4));
}

#[test]
fn test_iter_enum_or() {
    let matchers = vec![
        TestMatchers::Const(ConstMatcher(0)),
        TestMatchers::Const(ConstMatcher(2)),
        TestMatchers::Odd(OddMatcher),
    ];

    assert!(matchers[0].matches(None, &Context::default(), &0));
    assert!(matchers[1].matches(None, &Context::default(), &2));
    assert!(matchers[2].matches(None, &Context::default(), &1));

    for i in 0..=2 {
        assert!(
            matchers.iter().matches_or(None, &Context::default(), &i),
            "i = {}",
            i
        );
    }
    for i in 3..=255 {
        if i % 2 == 1 {
            assert!(
                matchers.iter().matches_or(None, &Context::default(), &i),
                "i = {}",
                i
            );
        } else {
            assert!(
                !matchers.iter().matches_or(None, &Context::default(), &i),
                "i = {}",
                i
            );
        }
    }
}

#[test]
#[allow(unused_allocation)]
fn test_box() {
    assert!(Box::new(ConstMatcher(0)).matches(None, &Context::default(), &0));
    assert!(!Box::new(ConstMatcher(1)).matches(None, &Context::default(), &0));
}

#[test]
fn test_iter_box_and() {
    let matchers: Vec<Box<dyn Matcher<_, _>>> =
        vec![Box::new(ConstMatcher(1)), Box::new(OddMatcher)];

    assert!(matchers[0].matches(None, &Context::default(), &1));
    assert!(matchers[1].matches(None, &Context::default(), &1));

    for matcher in matchers.iter() {
        assert!(matcher.matches(None, &Context::default(), &1));
    }

    assert!(matchers.iter().matches_and(None, &Context::default(), &1));
    assert!(!matchers.iter().matches_and(None, &Context::default(), &3));
    assert!(!matchers.iter().matches_and(None, &Context::default(), &4));
}

#[test]
fn test_iter_box_or() {
    let matchers: Vec<Box<dyn Matcher<_, _>>> = vec![
        Box::new(ConstMatcher(0)),
        Box::new(ConstMatcher(2)),
        Box::new(OddMatcher),
    ];

    assert!(matchers[0].matches(None, &Context::default(), &0));
    assert!(matchers[1].matches(None, &Context::default(), &2));
    assert!(matchers[2].matches(None, &Context::default(), &1));

    for i in 0..=2 {
        assert!(
            matchers.iter().matches_or(None, &Context::default(), &i),
            "i = {}",
            i
        );
    }
    for i in 3..=255 {
        if i % 2 == 1 {
            assert!(
                matchers.iter().matches_or(None, &Context::default(), &i),
                "i = {}",
                i
            );
        } else {
            assert!(
                !matchers.iter().matches_or(None, &Context::default(), &i),
                "i = {}",
                i
            );
        }
    }
}

// TODO: add tests to ensure we do not store extension of unmatched branch
