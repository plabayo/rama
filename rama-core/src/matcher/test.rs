use super::*;

#[test]
fn test_not() {
    assert!(!Not::new(true).matches(None, &&()));
}

#[test]
fn test_not_builder() {
    assert!(!true.not().matches(None, &&()));
    assert!(!true.not().matches(None, &&0));
    assert!(!true.not().matches(None, &&false));
    assert!(!true.not().matches(None, &&"foo"));
}

mod marker {
    #[derive(Debug, Clone)]
    pub(super) struct Odd;

    #[derive(Debug, Clone)]
    pub(super) struct Even;

    #[derive(Debug, Clone)]
    pub(super) struct Const;
}

#[derive(Debug, Clone)]
struct OddMatcher;

impl Matcher<u8> for OddMatcher {
    fn matches(&self, ext: Option<&mut Extensions>, req: &u8) -> bool {
        if !(*req).is_multiple_of(2) {
            if let Some(ext) = ext {
                ext.insert(marker::Odd);
            }
            return true;
        }
        false
    }
}

#[derive(Debug, Clone)]
struct EvenMatcher;

impl Matcher<u8> for EvenMatcher {
    fn matches(&self, ext: Option<&mut Extensions>, req: &u8) -> bool {
        if (*req).is_multiple_of(2) {
            if let Some(ext) = ext {
                ext.insert(marker::Even);
            }
            return true;
        }
        false
    }
}

#[derive(Debug, Clone)]
struct ConstMatcher(u8);

impl Matcher<u8> for ConstMatcher {
    fn matches(&self, ext: Option<&mut Extensions>, req: &u8) -> bool {
        if *req == self.0 {
            if let Some(ext) = ext {
                ext.insert(marker::Const);
            }
            return true;
        }
        false
    }
}

#[test]
fn test_option() {
    assert!(!Option::<ConstMatcher>::None.matches(None, &0));
    assert!(Some(ConstMatcher(0)).matches(None, &0));
    assert!(!Some(ConstMatcher(1)).matches(None, &0));
}

#[test]
fn test_and() {
    let matcher = And::new((ConstMatcher(1), OddMatcher));
    assert!(!matcher.matches(None, &0));
    assert!(matcher.matches(None, &1));
    assert!(!matcher.matches(None, &2));
    for i in 3..=255 {
        assert!(!matcher.matches(None, &i), "i = {i}");
    }
}

#[test]
fn test_and_builder() {
    let matcher = ConstMatcher(1).and(OddMatcher);
    assert!(!matcher.matches(None, &0));
    assert!(matcher.matches(None, &1));
    assert!(!matcher.matches(None, &2));
    for i in 3..=255 {
        assert!(!matcher.matches(None, &i), "i = {i}");
    }
}

#[test]
fn test_or() {
    let matcher = Or::new((ConstMatcher(1), EvenMatcher));
    assert!(matcher.matches(None, &0));
    assert!(matcher.matches(None, &1));
    assert!(matcher.matches(None, &2));
    for i in 3..=255 {
        if i % 2 == 0 {
            assert!(matcher.matches(None, &i), "i = {i}");
        } else {
            assert!(!matcher.matches(None, &i), "i = {i}");
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

    assert!(!matcher.matches(None, &0));
    for i in 1..=12 {
        assert!(matcher.matches(None, &i), "i = {i}");
    }
    for i in 13..=255 {
        assert!(!matcher.matches(None, &i), "i = {i}");
    }
}

#[test]
fn test_and_never() {
    for i in 0..=255 {
        assert!(
            !And::new((OddMatcher, EvenMatcher)).matches(None, &i),
            "i = {i}"
        );
    }
}

#[test]
fn test_or_never() {
    for i in 0..=255 {
        assert!(
            Or::new((OddMatcher, EvenMatcher)).matches(None, &i),
            "i = {i}",
        );
    }
}

#[test]
fn test_and_or() {
    let matcher = ConstMatcher(1)
        .or(ConstMatcher(2))
        .and(OddMatcher.or(EvenMatcher));
    assert!(matcher.matches(None, &1));
    assert!(matcher.matches(None, &2));
    for i in 3..=255 {
        assert!(!matcher.matches(None, &i), "i = {i}");
    }
}

#[test]
fn test_match_fn_always() {
    assert!(match_fn(|| true).matches(None, &&()));
    assert!(match_fn(|| true).matches(None, &&()));
    assert!(match_fn(|_: Option<&mut Extensions>| true).matches(None, &&()));
    assert!(match_fn(|_: Option<&mut Extensions>| true).matches(None, &()));
    assert!(match_fn(|_: &()| true).matches(None, &()));
    assert!(match_fn(|_: &u8| true).matches(None, &0));
    assert!(match_fn(|_: &bool| true).matches(None, &false));
    assert!(match_fn(|_: &&str| true).matches(None, &"foo"));
}

#[test]
fn test_match_fn() {
    let matcher = match_fn(|req: &u8| !(*req).is_multiple_of(2));
    for i in 0..=255 {
        if i % 2 != 0 {
            assert!(matcher.matches(None, &i), "i = {i}");
        } else {
            assert!(!matcher.matches(None, &i), "i = {i}");
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

impl Matcher<u8> for TestMatchers {
    fn matches(&self, ext: Option<&mut Extensions>, req: &u8) -> bool {
        match self {
            Self::Const(m) => m.matches(ext, req),
            Self::Even(m) => m.matches(ext, req),
            Self::Odd(m) => m.matches(ext, req),
        }
    }
}

#[test]
fn test_enum_matcher() {
    assert!(!TestMatchers::Const(ConstMatcher(1)).matches(None, &0));
    assert!(TestMatchers::Const(ConstMatcher(1)).matches(None, &1));
    assert!(!TestMatchers::Even(EvenMatcher).matches(None, &1));
    assert!(TestMatchers::Even(EvenMatcher).matches(None, &2));
    assert!(!TestMatchers::Odd(OddMatcher).matches(None, &2));
    assert!(TestMatchers::Odd(OddMatcher).matches(None, &3));
}

#[test]
fn test_iter_enum_and() {
    let matchers = [
        TestMatchers::Const(ConstMatcher(1)),
        TestMatchers::Odd(OddMatcher),
    ];

    assert!(matchers[0].matches(None, &1));
    assert!(matchers[1].matches(None, &1));

    for matcher in matchers.iter() {
        assert!(matcher.matches(None, &1));
    }

    assert!(matchers.iter().matches_and(None, &1));
    assert!(!matchers.iter().matches_and(None, &3));
    assert!(!matchers.iter().matches_and(None, &4));
}

#[test]
fn test_iter_empty() {
    let matchers: Vec<ConstMatcher> = Vec::new();
    for i in 0..=255 {
        assert!(matchers.iter().matches_and(None, &i));
        assert!(matchers.iter().matches_or(None, &i));
    }
}

#[test]
fn test_iter_enum_or() {
    let matchers = [
        TestMatchers::Const(ConstMatcher(0)),
        TestMatchers::Const(ConstMatcher(2)),
        TestMatchers::Odd(OddMatcher),
    ];

    assert!(matchers[0].matches(None, &0));
    assert!(matchers[1].matches(None, &2));
    assert!(matchers[2].matches(None, &1));

    for i in 0..=2 {
        assert!(matchers.iter().matches_or(None, &i), "i = {i}",);
    }
    for i in 3..=255 {
        if i % 2 == 1 {
            assert!(matchers.iter().matches_or(None, &i), "i = {i}",);
        } else {
            assert!(!matchers.iter().matches_or(None, &i), "i = {i}",);
        }
    }
}

#[test]
#[allow(unused_allocation)]
fn test_box() {
    assert!(Box::new(ConstMatcher(0)).matches(None, &0));
    assert!(!Box::new(ConstMatcher(1)).matches(None, &0));
}

#[test]
fn test_iter_box_and() {
    let matchers: Vec<Box<dyn Matcher<_>>> = vec![Box::new(ConstMatcher(1)), Box::new(OddMatcher)];

    assert!(matchers[0].matches(None, &1));
    assert!(matchers[1].matches(None, &1));

    for matcher in matchers.iter() {
        assert!(matcher.matches(None, &1));
    }

    assert!(matchers.iter().matches_and(None, &1));
    assert!(!matchers.iter().matches_and(None, &3));
    assert!(!matchers.iter().matches_and(None, &4));
}

#[test]
fn test_iter_box_or() {
    let matchers: Vec<Box<dyn Matcher<_>>> = vec![
        Box::new(ConstMatcher(0)),
        Box::new(ConstMatcher(2)),
        Box::new(OddMatcher),
    ];

    assert!(matchers[0].matches(None, &0));
    assert!(matchers[1].matches(None, &2));
    assert!(matchers[2].matches(None, &1));

    for i in 0..=2 {
        assert!(matchers.iter().matches_or(None, &i), "i = {i}",);
    }
    for i in 3..=255 {
        if i % 2 == 1 {
            assert!(matchers.iter().matches_or(None, &i), "i = {i}",);
        } else {
            assert!(!matchers.iter().matches_or(None, &i), "i = {i}",);
        }
    }
}

#[test]
fn test_ext_insert_and_revert_op_or() {
    let matcher = EvenMatcher
        .and(ConstMatcher(2))
        .or(OddMatcher.and(ConstMatcher(3)));

    let mut ext = Extensions::new();

    // test #1: pass: match first part, should have extensions
    ext.clear();
    assert!(matcher.matches(Some(&mut ext), &2));
    assert!(ext.get::<marker::Even>().is_some());
    assert!(ext.get::<marker::Const>().is_some());
    assert!(ext.get::<marker::Odd>().is_none());

    // test #2: pass: match 2nd part, should have extensions
    ext.clear();
    assert!(matcher.matches(Some(&mut ext), &3));
    assert!(ext.get::<marker::Even>().is_none());
    assert!(ext.get::<marker::Const>().is_some());
    assert!(ext.get::<marker::Odd>().is_some());

    // test #3: pass: do not match any part
    ext.clear();
    assert!(!matcher.matches(Some(&mut ext), &4));
    assert!(ext.get::<marker::Even>().is_none());
    assert!(ext.get::<marker::Const>().is_none());
    assert!(ext.get::<marker::Odd>().is_none());
}

#[test]
fn test_ext_insert_and_revert_iter_or() {
    let matcher: Vec<Box<dyn Matcher<_>>> = vec![
        Box::new(EvenMatcher.and(ConstMatcher(2))),
        Box::new(OddMatcher.and(ConstMatcher(3))),
    ];

    let mut ext = Extensions::new();

    // test #1: pass: match first part, should have extensions
    ext.clear();
    assert!(matcher.iter().matches_or(Some(&mut ext), &2));
    assert!(ext.get::<marker::Even>().is_some());
    assert!(ext.get::<marker::Const>().is_some());
    assert!(ext.get::<marker::Odd>().is_none());

    // test #2: pass: match 2nd part, should have extensions
    ext.clear();
    assert!(matcher.iter().matches_or(Some(&mut ext), &3));
    assert!(ext.get::<marker::Even>().is_none());
    assert!(ext.get::<marker::Const>().is_some());
    assert!(ext.get::<marker::Odd>().is_some());

    // test #3: pass: do not match any part
    ext.clear();
    assert!(!matcher.iter().matches_or(Some(&mut ext), &4));
    assert!(ext.get::<marker::Even>().is_none());
    assert!(ext.get::<marker::Const>().is_none());
    assert!(ext.get::<marker::Odd>().is_none());
}

#[test]
fn test_ext_insert_and_revert_iter_and() {
    let matcher: Vec<Box<dyn Matcher<_>>> = vec![
        Box::new(ConstMatcher(2).or(ConstMatcher(3))),
        Box::new(OddMatcher.or(EvenMatcher)),
    ];

    let mut ext = Extensions::new();

    // test #1: pass: match both parts, with first member of 2nd part
    ext.clear();
    assert!(matcher.iter().matches_and(Some(&mut ext), &3));
    assert!(ext.get::<marker::Even>().is_none());
    assert!(ext.get::<marker::Const>().is_some());
    assert!(ext.get::<marker::Odd>().is_some());

    // test #2: pass: match both parts, with second member of 2nd part
    ext.clear();
    assert!(matcher.iter().matches_and(Some(&mut ext), &2));
    assert!(ext.get::<marker::Even>().is_some());
    assert!(ext.get::<marker::Const>().is_some());
    assert!(ext.get::<marker::Odd>().is_none());

    // test #3: pass: do not match any part
    ext.clear();
    assert!(!matcher.iter().matches_and(Some(&mut ext), &1));
    assert!(ext.get::<marker::Even>().is_none());
    assert!(ext.get::<marker::Const>().is_none());
    assert!(ext.get::<marker::Odd>().is_none());
}

#[test]
fn test_ext_insert_and_revert_op_and() {
    let matcher = ConstMatcher(2)
        .or(ConstMatcher(3))
        .and(OddMatcher.or(EvenMatcher));

    let mut ext = Extensions::new();

    // test #1: pass: match both parts, with first member of 2nd part
    ext.clear();
    assert!(matcher.matches(Some(&mut ext), &3));
    assert!(ext.get::<marker::Even>().is_none());
    assert!(ext.get::<marker::Const>().is_some());
    assert!(ext.get::<marker::Odd>().is_some());

    // test #2: pass: match both parts, with second member of 2nd part
    ext.clear();
    assert!(matcher.matches(Some(&mut ext), &2));
    assert!(ext.get::<marker::Even>().is_some());
    assert!(ext.get::<marker::Const>().is_some());
    assert!(ext.get::<marker::Odd>().is_none());

    // test #3: pass: do not match any part
    ext.clear();
    assert!(!matcher.matches(Some(&mut ext), &1));
    assert!(ext.get::<marker::Even>().is_none());
    assert!(ext.get::<marker::Const>().is_none());
    assert!(ext.get::<marker::Odd>().is_none());
}
