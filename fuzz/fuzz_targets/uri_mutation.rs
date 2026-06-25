//! Fuzz target for URI component mutation/building APIs.
//!
//! Goals: arbitrary component bytes passed through setters and mutation guards
//! never panic, exercise rendering/reparsing paths, and keep encoded/decoded
//! component views callable after each mutation.
//!
//! Run with:
//!     cargo +nightly fuzz run uri_mutation
#![no_main]

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary},
    fuzz_target,
};
use rama::net::uri::Uri;

#[derive(Arbitrary, Debug)]
struct Input {
    base: Vec<u8>,
    path: Vec<u8>,
    segment: Vec<u8>,
    extra_segments: Vec<u8>,
    query: Vec<u8>,
    query_name: Vec<u8>,
    query_value: Vec<u8>,
    fragment: Vec<u8>,
    pop_segments: u8,
    strip_segments: u8,
    clear_path: bool,
    unset_query: bool,
    unset_fragment: bool,
}

fn exercise_views(uri: &Uri) {
    drop(uri.to_string().parse::<Uri>());
    drop(uri.request_target());

    if let Some(path) = uri.path() {
        drop(path.as_encoded_str());
        drop(path.as_decoded_str());
        drop(path.trimmed_slashes().as_encoded_str());
        for segment in path.segments() {
            drop(segment.as_encoded_str());
            drop(segment.as_decoded_str());
        }
    }

    if let Some(query) = uri.query() {
        drop(query.as_encoded_str());
        drop(query.as_decoded_str());
        for pair in query.pairs() {
            drop(pair.name_encoded());
            drop(pair.value_encoded());
            drop(pair.name_decoded());
            drop(pair.value_decoded());
        }
    }

    if let Some(fragment) = uri.fragment() {
        drop(fragment.as_encoded_str());
        drop(fragment.as_decoded_str());
    }
}

fuzz_target!(|input: Input| {
    let mut uri = Uri::parse(input.base.as_slice()).unwrap_or_else(|_| Uri::from_static("/"));

    uri.set_path(input.path.clone());
    exercise_views(&uri);

    {
        let mut path = uri.path_mut();
        if input.clear_path {
            path.clear();
        }
        path.push_segment(input.segment.as_slice())
            .push_segments(input.extra_segments.as_slice());
        let _ = path.pop_segments((input.pop_segments % 8) as usize);
        let _ = path.strip_prefix_segments((input.strip_segments % 8) as usize);
        path.trim_trailing_slash();
        path.append_trailing_slash();
    }
    exercise_views(&uri);

    uri.set_query_from_bytes(input.query.clone());
    {
        let mut query = uri.query_mut();
        query
            .push_pair(input.query_name.as_slice(), input.query_value.as_slice())
            .push_key(input.query_name.as_slice());
        let _ = query.pop();
        let drained = query.drain();
        for pair in drained {
            drop(pair.name_encoded());
            drop(pair.value_encoded());
            drop(pair.name_decoded());
            drop(pair.value_decoded());
        }
    }
    if input.unset_query {
        uri.unset_query();
    }
    exercise_views(&uri);

    uri.set_fragment(input.fragment);
    if input.unset_fragment {
        uri.unset_fragment();
    }
    exercise_views(&uri);
});
