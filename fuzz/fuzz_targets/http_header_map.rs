#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::header::Entry;
use rama::http::{HeaderMap, HeaderName, HeaderValue};

fuzz_target!(|data: &[u8]| {
    let mut map = HeaderMap::new();
    let mut model = HeaderMapModel::default();

    assert_header_map_matches_model(&map, &model);

    for chunk in data.chunks(3) {
        if chunk.len() < 3 {
            continue;
        }

        let (name, semantic_id) = header_name(chunk[1]);
        let value = header_value(chunk[2]);

        match chunk[0] % 6 {
            0 => {
                let Some(header_name) = make_header_name(name) else {
                    continue;
                };
                let Some(header_value) = make_header_value(&value) else {
                    continue;
                };
                let Some(original_name) = original_name(name) else {
                    continue;
                };
                map.insert(header_name, header_value);
                model.insert(semantic_id, original_name, value);
            }
            1 => {
                let Some(header_name) = make_header_name(name) else {
                    continue;
                };
                let Some(header_value) = make_header_value(&value) else {
                    continue;
                };
                let Some(original_name) = original_name(name) else {
                    continue;
                };
                map.append(header_name, header_value);
                model.append(semantic_id, original_name, value);
            }
            2 => {
                let Some(header_name) = make_header_name(name) else {
                    continue;
                };
                map.remove(header_name);
                model.remove(semantic_id);
            }
            3 => {
                let Some(header_name) = make_header_name(name) else {
                    continue;
                };
                if let Entry::Occupied(entry) = map.entry(header_name) {
                    let _ = entry.remove_entry_mult();
                }
                model.remove(semantic_id);
            }
            4 => {
                let Some(header_name) = make_header_name(name) else {
                    continue;
                };
                let Some(header_value) = make_header_value(&value) else {
                    continue;
                };
                let Some(original_name) = original_name(name) else {
                    continue;
                };
                match map.entry(header_name) {
                    Entry::Occupied(mut entry) => {
                        entry.append(header_value);
                    }
                    Entry::Vacant(entry) => {
                        entry.insert_entry(header_value);
                    }
                }
                model.entry_append(semantic_id, original_name, value);
            }
            _ => {
                let Some(header_name) = make_header_name(name) else {
                    continue;
                };
                let Some(header_value) = make_header_value(&value) else {
                    continue;
                };
                let Some(original_name) = original_name(name) else {
                    continue;
                };
                match map.entry(header_name) {
                    Entry::Occupied(mut entry) => {
                        let _ = entry.insert_mult(header_value);
                    }
                    Entry::Vacant(entry) => {
                        entry.insert_entry(header_value);
                    }
                }
                model.entry_insert_mult(semantic_id, original_name, value);
            }
        }

        assert_header_map_matches_model(&map, &model);
    }
});

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModelHeader {
    semantic_id: usize,
    name: String,
    value: Vec<u8>,
    head: bool,
}

#[derive(Default)]
struct HeaderMapModel {
    fields: Vec<Option<ModelHeader>>,
}

impl HeaderMapModel {
    fn len(&self) -> usize {
        self.fields.iter().filter(|field| field.is_some()).count()
    }

    fn ordered(&self) -> Vec<(String, Vec<u8>)> {
        self.fields
            .iter()
            .filter_map(|field| {
                field
                    .as_ref()
                    .map(|field| (field.name.clone(), field.value.clone()))
            })
            .collect()
    }

    fn values_for(&self, semantic_id: usize) -> Vec<Vec<u8>> {
        self.fields
            .iter()
            .filter_map(|field| {
                let field = field.as_ref()?;
                (field.semantic_id == semantic_id).then(|| field.value.clone())
            })
            .collect()
    }

    fn head_index(&self, semantic_id: usize) -> Option<usize> {
        self.fields.iter().position(|field| {
            field
                .as_ref()
                .is_some_and(|field| field.semantic_id == semantic_id && field.head)
        })
    }

    fn head_name(&self, semantic_id: usize) -> Option<String> {
        let head_idx = self.head_index(semantic_id)?;
        self.fields
            .get(head_idx)
            .and_then(Option::as_ref)
            .map(|field| field.name.clone())
    }

    fn remove(&mut self, semantic_id: usize) {
        for field in &mut self.fields {
            if field
                .as_ref()
                .is_some_and(|field| field.semantic_id == semantic_id)
            {
                *field = None;
            }
        }
    }

    fn append(&mut self, semantic_id: usize, name: String, value: Vec<u8>) {
        let head = self.head_index(semantic_id).is_none();
        self.fields.push(Some(ModelHeader {
            semantic_id,
            name,
            value,
            head,
        }));
    }

    fn insert(&mut self, semantic_id: usize, name: String, value: Vec<u8>) {
        if let Some(head_idx) = self.head_index(semantic_id) {
            for (idx, field) in self.fields.iter_mut().enumerate() {
                if idx != head_idx
                    && field
                        .as_ref()
                        .is_some_and(|field| field.semantic_id == semantic_id)
                {
                    *field = None;
                }
            }
            self.fields[head_idx] = Some(ModelHeader {
                semantic_id,
                name,
                value,
                head: true,
            });
        } else {
            self.append(semantic_id, name, value);
        }
    }

    fn entry_append(&mut self, semantic_id: usize, name: String, value: Vec<u8>) {
        if let Some(entry_name) = self.head_name(semantic_id) {
            self.append(semantic_id, entry_name, value);
        } else {
            self.append(semantic_id, name, value);
        }
    }

    fn entry_insert_mult(&mut self, semantic_id: usize, name: String, value: Vec<u8>) {
        if let Some(entry_name) = self.head_name(semantic_id) {
            self.insert(semantic_id, entry_name, value);
        } else {
            self.append(semantic_id, name, value);
        }
    }
}

fn header_name(selector: u8) -> (&'static str, usize) {
    match selector % 8 {
        0 => ("x-a", 0),
        1 => ("X-A", 0),
        2 => ("x-b", 1),
        3 => ("X-B", 1),
        4 => ("cookie", 2),
        5 => ("Cookie", 2),
        6 => ("x-c", 3),
        _ => ("X-C", 3),
    }
}

fn header_value(selector: u8) -> Vec<u8> {
    format!("v{selector}").into_bytes()
}

fn make_header_name(name: &str) -> Option<HeaderName> {
    HeaderName::from_bytes(name.as_bytes()).ok()
}

fn original_name(name: &str) -> Option<String> {
    make_header_name(name).map(|name| name.to_string())
}

fn make_header_value(value: &[u8]) -> Option<HeaderValue> {
    HeaderValue::from_bytes(value).ok()
}

fn assert_header_map_matches_model(map: &HeaderMap, model: &HeaderMapModel) {
    let ordered: Vec<_> = map
        .ordered_iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();

    assert_eq!(ordered.len(), map.len());
    assert_eq!(ordered.len(), model.len());
    assert_eq!(ordered, model.ordered());

    for (name, _) in map.ordered_iter() {
        assert!(map.contains_key(name));
    }

    let consumed: Vec<_> = map
        .clone()
        .into_ordered_iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    assert_eq!(ordered, consumed);

    for (name, semantic_id) in [
        ("x-a", 0),
        ("X-A", 0),
        ("x-b", 1),
        ("X-B", 1),
        ("cookie", 2),
        ("Cookie", 2),
        ("x-c", 3),
        ("X-C", 3),
    ] {
        let Some(header_name) = make_header_name(name) else {
            continue;
        };
        let actual = map
            .get_all(header_name)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(actual, model.values_for(semantic_id));
    }

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
