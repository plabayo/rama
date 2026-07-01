#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::{HeaderMap, HeaderName, HeaderValue};

fuzz_target!(|data: &[u8]| {
    let mut map = HeaderMap::new();

    for chunk in data.chunks(17) {
        if chunk.len() < 3 {
            continue;
        }

        let name_len = usize::from(chunk[1] % 12) + 1;
        let name_end = 2 + name_len.min(chunk.len().saturating_sub(2));
        let value = &chunk[name_end..];
        let Ok(name) = HeaderName::from_bytes(&chunk[2..name_end]) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(value) else {
            continue;
        };

        match chunk[0] % 3 {
            0 => {
                map.insert(name, value);
            }
            1 => {
                map.append(name, value);
            }
            _ => {
                map.remove(name);
            }
        }

        assert_header_map_invariants(&map);
    }
});

fn assert_header_map_invariants(map: &HeaderMap) {
    let ordered: Vec<_> = map
        .ordered_iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();

    assert_eq!(ordered.len(), map.len());

    for (name, _) in map.ordered_iter() {
        assert!(map.contains_key(name));
    }

    let consumed: Vec<_> = map
        .clone()
        .into_ordered_iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    assert_eq!(ordered, consumed);

    if map.ordered_iter().all(|(_, value)| value.to_str().is_ok()) {
        let json = serde_json::to_vec(map);
        assert!(json.is_ok(), "serialize header map");
        let Ok(json) = json else {
            return;
        };
        let roundtrip = serde_json::from_slice::<HeaderMap>(&json);
        assert!(roundtrip.is_ok(), "deserialize header map");
        let Ok(roundtrip) = roundtrip else {
            return;
        };
        let roundtrip_ordered: Vec<_> = roundtrip
            .ordered_iter()
            .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
            .collect();
        assert_eq!(ordered, roundtrip_ordered);
    }
}
