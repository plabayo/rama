use super::*;

#[test]
fn the_cache_keeps_the_newest_values_of_the_most_recent_keys() {
    let cache =
        TlsClientSessionCache::new(NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(2).unwrap());
    for value in 0..3 {
        cache.insert("a", value);
    }
    assert_eq!(cache.len(), 2);
    cache.insert("b", 10);
    cache.insert("a", 3);
    // Storing to "c" evicts "b", the key stored to least recently.
    cache.insert("c", 20);
    assert_eq!(cache.most_recent(&["a", "b", "c"]), Some(&"c"));
    assert_eq!(cache.most_recent(&["a", "b"]), Some(&"a"));
    assert_eq!(cache.pop(&"b"), None);
    assert_eq!(cache.pop(&"a"), Some(3));
    assert_eq!(cache.pop(&"a"), Some(2));
    assert_eq!(cache.pop(&"a"), None);
    assert_eq!(cache.most_recent(&["a"]), None);
    assert_eq!(cache.pop(&"c"), Some(20));
    assert!(cache.is_empty());
    // Emptied keys release their slot.
    for key in ["d", "e"] {
        cache.insert(key, 0);
    }
    assert_eq!(cache.len(), 2);
}
