use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use rama_js::JsScript;

fn hash(script: &JsScript) -> u64 {
    let mut hasher = DefaultHasher::new();
    script.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn script_conversions_preserve_source() {
    const STATIC_SOURCE: &str = "static source";
    let static_script = JsScript::from(STATIC_SOURCE);
    assert_eq!(static_script.as_str(), STATIC_SOURCE);
    assert_eq!(static_script.as_str().as_ptr(), STATIC_SOURCE.as_ptr());

    let string_script = JsScript::from("string source".to_owned());
    let boxed_script = JsScript::from(String::from("boxed source").into_boxed_str());
    let shared_source = Arc::<str>::from("shared source");
    let shared_script = JsScript::from(shared_source.clone());

    assert_eq!(string_script.as_ref(), "string source");
    assert_eq!(boxed_script.as_ref(), "boxed source");
    assert_eq!(shared_script.as_ref(), "shared source");
    assert_eq!(shared_script.as_str().as_ptr(), shared_source.as_ptr());
}

#[test]
fn script_equality_hash_and_debug_follow_source() {
    let left = JsScript::from("same source".to_owned());
    let right = JsScript::from(Arc::<str>::from("same source"));
    let different = JsScript::from("different source");

    assert_eq!(left, right);
    assert_ne!(left, different);
    assert_eq!(hash(&left), hash(&right));
    assert_ne!(hash(&left), hash(&different));

    let debug = format!("{left:?}");
    assert!(debug.contains("JsScript"));
    assert!(debug.contains("len: 11"));
    assert!(!debug.contains("same source"));
}

#[test]
fn default_script_is_empty() {
    assert_eq!(JsScript::default().as_str(), "");
}
