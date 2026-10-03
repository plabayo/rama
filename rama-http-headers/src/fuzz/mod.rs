//! Bounded synchronous fuzz entry points driving every typed header through its public API.
//!
//! A unit test fails when a type implementing [`HeaderDecode`](crate::HeaderDecode) is missing
//! from `headers/`, so a new typed header only needs one entry in the matching group.

#[macro_use]
mod macros;

mod headers;
mod numbers;
mod parts;
mod probes;
mod strs;
mod support;
mod values;

#[cfg(test)]
mod tests;

use rama_http_types::HeaderValue;

/// A named exercise over the values of one header field.
pub(crate) type ValuesExercise = (&'static str, fn(&[HeaderValue]));

/// A named exercise over a single untrusted string.
pub(crate) type StrExercise = (&'static str, fn(&str));

/// A named exercise of fallible constructors over two input-derived numbers.
pub(crate) type NumbersExercise = (&'static str, fn(u64, u64));

/// Upper bound on the header values `exercise_bytes` splits its input into.
pub const MAX_VALUES: usize = 16;

fn values_exercises() -> impl Iterator<Item = &'static ValuesExercise> {
    headers::GROUPS
        .iter()
        .flat_map(|group| group.iter())
        .chain(values::VALUES)
}

/// Decode every typed header from `values` and drive each success through its public API.
pub fn exercise_header_values(values: &[HeaderValue]) {
    for (_, exercise) in values_exercises() {
        exercise(values);
    }
}

/// Run every public string parser of this crate on `s` and drive each success through its API.
pub fn exercise_str(s: &str) {
    for (_, exercise) in strs::STRS {
        exercise(s);
    }
}

/// Run every fallible numeric constructor of this crate on `a` and `b`.
pub fn exercise_numbers(a: u64, b: u64) {
    for (_, exercise) in numbers::NUMBERS {
        exercise(a, b);
    }
}

/// Fuzz entry point: `data` is split on `\n` into header values and strings.
pub fn exercise_bytes(data: &[u8]) {
    let chunks: Vec<&[u8]> = data.split(|byte| *byte == b'\n').take(MAX_VALUES).collect();
    let values: Vec<HeaderValue> = chunks
        .iter()
        .filter_map(|chunk| HeaderValue::from_bytes(chunk).ok())
        .collect();
    exercise_header_values(&values);
    if values.len() > 1 {
        for value in &values {
            exercise_header_values(std::slice::from_ref(value));
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        exercise_str(s);
    }
    if chunks.len() > 1 {
        for s in chunks
            .iter()
            .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        {
            exercise_str(s);
        }
    }
    let mut numbers = data.chunks(8).map(|chunk| {
        let mut buf = [0u8; 8];
        for (dst, src) in buf.iter_mut().zip(chunk) {
            *dst = *src;
        }
        u64::from_le_bytes(buf)
    });
    let a = numbers.next().unwrap_or_default();
    let b = numbers.next().unwrap_or_default();
    exercise_numbers(a, b);
}
