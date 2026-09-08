//! Match displayed values without allocating an intermediate formatted string.
use std::{
    collections::VecDeque,
    fmt::{self, Write},
};

pub fn matches_display(value: &impl fmt::Display, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    struct Matcher {
        needle: Vec<char>,
        window: VecDeque<char>,
        matched: bool,
    }
    impl Write for Matcher {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            for c in value.chars().flat_map(char::to_lowercase) {
                self.window.push_back(c);
                if self.window.len() > self.needle.len() {
                    self.window.pop_front();
                }
                if self.window.iter().eq(self.needle.iter()) {
                    self.matched = true;
                    return Err(fmt::Error);
                }
            }
            Ok(())
        }
    }
    let needle: Vec<_> = needle.chars().flat_map(char::to_lowercase).collect();
    let mut matcher = Matcher {
        window: VecDeque::with_capacity(needle.len()),
        needle,
        matched: false,
    };
    _ = write!(&mut matcher, "{value}");
    matcher.matched
}
