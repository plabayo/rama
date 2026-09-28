//! Every exercise must survive the adversarial corpus without panicking.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    panic::{self, AssertUnwindSafe},
    sync::Once,
};

use super::{exercise_bytes, numbers, strs, values_exercises};

mod corpus;
mod coverage;

use corpus::{EDGE_NUMBERS, XorShift, str_corpus, value_corpus};

thread_local! {
    static CAPTURING: Cell<bool> = const { Cell::new(false) };
    static CAPTURED: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
}

fn install_panic_capture() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if CAPTURING.get() {
                let location = info
                    .location()
                    .map(|l| format!("{}:{}", l.file(), l.line()))
                    .unwrap_or_default();
                let message = info.payload_as_str().unwrap_or_default().to_owned();
                CAPTURED.set(Some((location, message)));
            } else {
                previous(info);
            }
        }));
    });
}

#[derive(Default)]
struct Failures {
    sites: BTreeMap<(String, String), (String, String, usize)>,
}

impl Failures {
    fn check(&mut self, exercise: &str, input: impl FnOnce() -> String, f: impl FnOnce()) {
        CAPTURING.set(true);
        let result = panic::catch_unwind(AssertUnwindSafe(f));
        CAPTURING.set(false);
        if result.is_ok() {
            return;
        }
        let (location, message) = CAPTURED.take().unwrap_or_default();
        let input = input();
        let entry = self
            .sites
            .entry((exercise.to_owned(), location))
            .or_insert_with(|| (message.clone(), input.clone(), 0));
        entry.2 = entry.2.saturating_add(1);
        if input.len() < entry.1.len() {
            entry.0 = message;
            entry.1 = input;
        }
    }

    fn assert_empty(self, kind: &str) {
        let report: Vec<String> = self
            .sites
            .into_iter()
            .map(|((exercise, location), (message, input, count))| {
                let mut input = input;
                if input.len() > 160 {
                    let cut = (0..=160).rev().find(|i| input.is_char_boundary(*i)).unwrap_or(0);
                    input.truncate(cut);
                    input.push_str("...");
                }
                format!("{exercise} @ {location} ({count} inputs): {message}\n    minimal input: {input}")
            })
            .collect();
        assert!(
            report.is_empty(),
            "{} distinct {kind} panic sites:\n{}",
            report.len(),
            report.join("\n")
        );
    }
}

#[test]
fn typed_headers_never_panic_on_adversarial_values() {
    install_panic_capture();
    let mut failures = Failures::default();
    for values in value_corpus() {
        for (name, exercise) in values_exercises() {
            failures.check(name, || format!("{values:?}"), || exercise(&values));
        }
    }
    failures.assert_empty("header value");
}

#[test]
fn string_parsers_never_panic_on_adversarial_input() {
    install_panic_capture();
    let mut failures = Failures::default();
    for s in str_corpus() {
        for (name, exercise) in strs::STRS {
            failures.check(name, || format!("{s:?}"), || exercise(&s));
        }
    }
    failures.assert_empty("string");
}

#[test]
fn numeric_constructors_never_panic_on_edge_values() {
    install_panic_capture();
    let mut failures = Failures::default();
    for &a in EDGE_NUMBERS {
        for &b in EDGE_NUMBERS {
            for (name, exercise) in numbers::NUMBERS {
                failures.check(name, || format!("({a}, {b})"), || exercise(a, b));
            }
        }
    }
    failures.assert_empty("numeric constructor");
}

#[test]
fn exercise_bytes_accepts_arbitrary_data() {
    install_panic_capture();
    let mut failures = Failures::default();
    let mut rng = XorShift(0xdead_beef_cafe_f00d);
    for _ in 0..200 {
        let data: Vec<u8> = (0..rng.below(4).saturating_add(1))
            .flat_map(|_| {
                let mut chunk = rng.bytes();
                chunk.push(b'\n');
                chunk
            })
            .collect();
        failures.check(
            "exercise_bytes",
            || format!("{data:?}"),
            || exercise_bytes(&data),
        );
    }
    failures.assert_empty("exercise_bytes");
}
