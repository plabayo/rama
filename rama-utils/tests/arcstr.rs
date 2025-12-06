use ahash::{HashMap, HashMapExt as _};
use rama_utils::str::arcstr::{ArcStr, arcstr};

#[test]
#[allow(clippy::cmp_owned)]
fn test_various_partial_eq() {
    macro_rules! check_partial_eq {
        (@eq1; $a:expr, $b:expr) => {{
            // Note: intentionally not assert_eq.
            assert!($a == $b);
            assert!(!($a != $b));
            assert!($b == $a);
            assert!(!($b != $a));
        }};
        (@ne1; $a:expr, $b:expr) => {
            assert!($a != $b);
            assert!(!($a == $b));
            assert!($b != $a);
            assert!(!($b == $a));
        };
        (@eq; $a:expr, $b:expr) => {{
            check_partial_eq!(@eq1; $a, $b);
            check_partial_eq!(@eq1; $a.clone(), $b);
            check_partial_eq!(@eq1; $a.clone(), $a);
        }};
        (@ne; $a:expr, $b:expr) => {{
            check_partial_eq!(@ne1; $a, $b);
            check_partial_eq!(@ne1; $a.clone(), $b);
        }};
    }

    check_partial_eq!(@eq; ArcStr::from("123"), "123");
    check_partial_eq!(@eq; ArcStr::from("foobar"), *"foobar");
    check_partial_eq!(@eq; ArcStr::from("🏳️‍🌈"), String::from("🏳️‍🌈"));
    check_partial_eq!(@eq; ArcStr::from("🏳️‍⚧️"), std::borrow::Cow::Borrowed("🏳️‍⚧️"));
    check_partial_eq!(@eq; ArcStr::from("🏴‍☠️"), std::borrow::Cow::Owned("🏴‍☠️".into()));
    check_partial_eq!(@eq; ArcStr::from(":o"), std::rc::Rc::<str>::from(":o"));
    check_partial_eq!(@eq; ArcStr::from("!!!"), std::sync::Arc::<str>::from("!!!"));

    check_partial_eq!(@eq; ArcStr::from(""), "");
    check_partial_eq!(@eq; ArcStr::from(""), ArcStr::from(""));

    check_partial_eq!(@ne; ArcStr::from("123"), "124");
    check_partial_eq!(@ne; ArcStr::from("Foobar"), *"FoobarFoobar");

    check_partial_eq!(@ne; ArcStr::from("①"), String::from("1"));
    check_partial_eq!(@ne; ArcStr::from(""), String::from("1"));
    check_partial_eq!(@ne; ArcStr::from("abc"), String::from(""));

    check_partial_eq!(@ne; ArcStr::from("butts"), std::borrow::Cow::Borrowed("boots"));
    check_partial_eq!(@ne; ArcStr::from("bots"), std::borrow::Cow::Owned("🤖".into()));
    check_partial_eq!(@ne; ArcStr::from("put"), std::rc::Rc::<str>::from("⛳️"));
    check_partial_eq!(@ne; ArcStr::from("pots"), std::sync::Arc::<str>::from("🍲"));
}

#[test]
fn test_indexing() {
    let a = ArcStr::from("12345");
    assert_eq!(&a[..], "12345");
    assert_eq!(&a[1..], "2345");
    assert_eq!(&a[..4], "1234");
    assert_eq!(&a[1..4], "234");
    assert_eq!(&a[1..=3], "234");
    assert_eq!(&a[..=3], "1234");
}

#[test]
fn test_ord() {
    let mut arr = [ArcStr::from("foo"), "bar".into(), "baz".into()];
    arr.sort();
    assert_eq!(&arr, &["bar", "baz", "foo"]);
}

#[test]
fn smoke_test_clone() {
    let count = if cfg!(miri) { 20 } else { 100 };
    for _ in 0..count {
        drop(vec![ArcStr::from("foobar"); count]);
        drop(vec![ArcStr::from("baz quux"); count]);
        let lit = { arcstr!("test 999") };
        drop(vec![lit; count]);
    }
    drop(vec![ArcStr::default(); count]);
}

#[test]
fn test_btreemap() {
    let mut m = std::collections::BTreeMap::new();

    for i in 0..100 {
        let prev = m.insert(ArcStr::from(format!("key {i}")), i);
        assert_eq!(prev, None);
    }

    for i in 0..100 {
        let s = format!("key {i}");
        assert_eq!(m.remove(s.as_str()), Some(i));
    }
}
#[test]
fn test_hashmap() {
    let mut m = HashMap::new();
    for i in 0..100 {
        let prev = m.insert(ArcStr::from(format!("key {i}")), i);
        assert_eq!(prev, None);
    }
    for i in 0..100 {
        let key = format!("key {i}");
        let search = key.as_str();
        assert_eq!(m[search], i);
        assert_eq!(m.remove(search), Some(i));
    }
}

#[test]
fn test_serde() {
    use serde_test::{Token, assert_de_tokens, assert_tokens};
    let teststr = ArcStr::from("test test 123 456");
    assert_tokens(&teststr, &[Token::BorrowedStr("test test 123 456")]);
    #[allow(clippy::redundant_clone)]
    assert_tokens(&teststr.clone(), &[Token::BorrowedStr("test test 123 456")]);
    assert_tokens(&ArcStr::default(), &[Token::BorrowedStr("")]);

    let checks = &[
        [Token::Str("123")],
        [Token::BorrowedStr("123")],
        [Token::String("123")],
        [Token::Bytes(b"123")],
        [Token::BorrowedBytes(b"123")],
        [Token::ByteBuf(b"123")],
    ];
    for check in checks {
        eprintln!("checking {check:?}");
        assert_de_tokens(&ArcStr::from("123"), check);
    }
}

#[test]
fn test_loose_ends() {
    assert_eq!(ArcStr::default(), "");
    assert_eq!("abc".parse::<ArcStr>().unwrap(), "abc");
    let abc_arc = ArcStr::from("abc");
    let abc_str: &str = abc_arc.as_ref();
    let abc_bytes: &[u8] = abc_arc.as_ref();
    assert_eq!(abc_str, "abc");
    assert_eq!(abc_bytes, b"abc");
}

#[test]
fn test_from_into_raw() {
    let a = vec![
        ArcStr::default(),
        ArcStr::from("1234"),
        ArcStr::from(format!("test {}", 1)),
    ];
    let v = a.into_iter().cycle().take(100).collect::<Vec<ArcStr>>();
    let v2 = v
        .iter()
        .map(|s| ArcStr::into_raw(s.clone()))
        .collect::<Vec<_>>();
    drop(v);
    let back = v2
        .iter()
        .map(|s| unsafe { ArcStr::from_raw(*s) })
        .collect::<Vec<_>>();

    let end = [
        ArcStr::default(),
        ArcStr::from("1234"),
        ArcStr::from(format!("test {}", 1)),
    ]
    .iter()
    .cloned()
    .cycle()
    .take(100)
    .collect::<Vec<_>>();
    assert_eq!(back, end);
    drop(back);
}

#[test]
fn test_strong_count() {
    let foobar = ArcStr::from("foobar");
    assert_eq!(Some(1), ArcStr::strong_count(&foobar));
    let also_foobar = ArcStr::clone(&foobar);
    assert_eq!(Some(2), ArcStr::strong_count(&foobar));
    assert_eq!(Some(2), ArcStr::strong_count(&also_foobar));

    let astr = arcstr!("baz");
    assert_eq!(None, ArcStr::strong_count(&astr));
    assert_eq!(None, ArcStr::strong_count(&ArcStr::default()));
}

#[test]
fn test_ptr_eq() {
    let foobar = ArcStr::from("foobar");
    let same_foobar = foobar.clone();
    let other_foobar = ArcStr::from("foobar");
    assert!(ArcStr::ptr_eq(&foobar, &same_foobar));
    assert!(!ArcStr::ptr_eq(&foobar, &other_foobar));

    const YET_AGAIN_A_DIFFERENT_FOOBAR: ArcStr = arcstr!("foobar");
    #[allow(clippy::redundant_clone)]
    let strange_new_foobar = YET_AGAIN_A_DIFFERENT_FOOBAR.clone();
    let wild_blue_foobar = strange_new_foobar.clone();
    assert!(ArcStr::ptr_eq(&strange_new_foobar, &wild_blue_foobar));
}

#[test]
fn test_statics() {
    const STATIC: ArcStr = arcstr!("Electricity!");
    assert!(ArcStr::is_static(&STATIC));
    assert_eq!(ArcStr::as_static(&STATIC), Some("Electricity!"));

    assert!(ArcStr::is_static(&ArcStr::new()));
    assert_eq!(ArcStr::as_static(&ArcStr::new()), Some(""));
    let st = {
        // Note that they don't have to be consts, just made using `arcstr!`:
        let still_static = { arcstr!("Shocking!") };
        assert!(ArcStr::is_static(&still_static));
        assert_eq!(ArcStr::as_static(&still_static), Some("Shocking!"));
        assert_eq!(ArcStr::as_static(&still_static.clone()), Some("Shocking!"));
        // clones are still static
        assert_eq!(ArcStr::as_static(&still_static.clone()), Some("Shocking!"));
        ArcStr::as_static(&still_static).unwrap()
    };
    assert_eq!(st, "Shocking!");

    // But it won't work for other strings.
    let nonstatic = ArcStr::from("Grounded...");
    assert_eq!(ArcStr::as_static(&nonstatic), None);
}

#[test]
fn test_static_arcstr_include_bytes() {
    const APACHE: ArcStr = arcstr!(include_str!("../../LICENSE-APACHE"));
    assert!(APACHE.len() > 9700);
    assert!(APACHE.trim_start().starts_with("Apache License"));
    assert!(APACHE.trim_end().ends_with("END OF TERMS AND CONDITIONS"));
}

#[test]
fn test_inherent_overrides() {
    let s = ArcStr::from("abc");
    assert_eq!(s.as_str(), "abc");
    let a = ArcStr::from("foo");
    assert_eq!(a.len(), 3);
    assert!(!ArcStr::from("foo").is_empty());
    assert!(ArcStr::new().is_empty());
}

#[test]
fn test_froms_more() {
    let mut s = "asdf".to_owned();
    {
        let s2: &mut str = &mut s;
        // Make sure we go through the right From
        let arc = <ArcStr as From<&mut str>>::from(s2);
        assert_eq!(arc, "asdf");
    }
    let arc = <ArcStr as From<&String>>::from(&s);
    assert_eq!(arc, "asdf");

    // This is a slightly more natural way to check, as it's when the "you a
    // weird From" situation comes up more often.

    let b: Option<Box<str>> = Some("abc".into());
    assert_eq!(b.map(ArcStr::from), Some(ArcStr::from("abc")));

    let b: Option<std::rc::Rc<str>> = Some("abc".into());
    assert_eq!(b.map(ArcStr::from), Some(ArcStr::from("abc")));

    let b: Option<std::sync::Arc<str>> = Some("abc".into());
    assert_eq!(b.map(ArcStr::from), Some(ArcStr::from("abc")));

    let bs: Box<str> = ArcStr::from("123").into();
    assert_eq!(&bs[..], "123");
    let rcs: std::rc::Rc<str> = ArcStr::from("123").into();
    assert_eq!(&rcs[..], "123");
    let arcs: std::sync::Arc<str> = ArcStr::from("123").into();
    assert_eq!(&arcs[..], "123");
    use std::borrow::Cow::{self, Borrowed, Owned};
    let cow: Cow<'_, str> = Borrowed("abcd");
    assert_eq!(ArcStr::from(cow), "abcd");

    let cow: Cow<'_, str> = Owned("abcd".into());
    assert_eq!(ArcStr::from(cow), "abcd");

    let cow: Option<Cow<'_, str>> = Some(Cow::from(&arc));
    assert_eq!(cow.as_deref(), Some("asdf"));

    let cow: Option<Cow<'_, str>> = Some(Cow::from(arc));
    assert!(matches!(cow, Some(Cow::Owned(_))));
    assert_eq!(cow.as_deref(), Some("asdf"));

    let st = { arcstr!("static should borrow") };
    {
        let cow: Option<Cow<'_, str>> = Some(Cow::from(st.clone()));
        assert!(matches!(cow, Some(Cow::Borrowed(_))));
        assert_eq!(cow.as_deref(), Some("static should borrow"));
    }
    // works with any lifetime
    {
        let cow: Option<Cow<'static, str>> = Some(Cow::from(st.clone()));
        assert!(matches!(cow, Some(Cow::Borrowed(_))));
        assert_eq!(cow.as_deref(), Some("static should borrow"));
    }

    let astr = ArcStr::from(&st);
    assert!(ArcStr::ptr_eq(&st, &astr));
    // Check non-statics
    let astr2 = ArcStr::from("foobar");
    assert!(ArcStr::ptr_eq(&astr2, &ArcStr::from(&astr2)))
}

#[test]
fn try_allocate() {
    assert_eq!(ArcStr::try_alloc("foo").as_deref(), Some("foo"));
    // TODO: how to test the error cases here?
}

#[test]
fn repeat_string() {
    assert_eq!(ArcStr::try_repeat("", 1000).unwrap(), "");
    assert_eq!(ArcStr::try_repeat("AAA", 0).unwrap(), "");
    assert_eq!(ArcStr::try_repeat("AAA", 1000).unwrap(), "AAA".repeat(1000));
    assert_eq!(ArcStr::try_repeat("AAA", usize::MAX), None);
}

#[test]
fn repeat_string_errors_overflow() {
    assert!(ArcStr::try_repeat("AAA", usize::MAX).is_none());
}

#[test]
#[allow(unknown_lints)]
fn test_leaking() {
    let s = ArcStr::from("foobar");
    assert!(!ArcStr::is_static(&s));
    assert!(ArcStr::as_static(&s).is_none());

    let leaked: &'static str = s.leak();
    assert_eq!(leaked, s);
    assert!(ArcStr::is_static(&s));
    assert_eq!(ArcStr::as_static(&s), Some("foobar"));
}
