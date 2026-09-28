//! Every `HeaderDecode` and `ForwardHeader` implementation must be exercised by the harness.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use super::super::parts::FORWARD_HEADERS;
use super::values_exercises;

// Directories under `src/` that hold no live typed headers.
const SKIPPED_DIRS: &[&str] = &["disabled", "fuzz"];

#[test]
fn every_typed_header_is_exercised() {
    let sources = sources();
    let headers = implementations(&sources, "HeaderDecode");

    // guard the scanner itself against silently finding nothing
    for known in [
        "IfNoneMatch",
        "Authorization",
        "Accept",
        "AcceptCh",
        "CFConnectingIp",
    ] {
        assert!(
            headers.contains(known),
            "scanner missed {known}: {headers:?}"
        );
    }

    let exercised: BTreeSet<&str> = values_exercises()
        .map(|(name, _)| base_name(name))
        .collect();
    assert_all_exercised(&headers, &exercised, "src/fuzz/headers");
}

#[test]
fn every_forward_header_is_converted() {
    let sources = sources();
    let headers = implementations(&sources, "ForwardHeader");
    for known in ["Forwarded", "Via", "XRealIp"] {
        assert!(
            headers.contains(known),
            "scanner missed {known}: {headers:?}"
        );
    }

    let converted: BTreeSet<&str> = FORWARD_HEADERS
        .iter()
        .map(|(name, _)| base_name(name))
        .collect();
    assert_all_exercised(&headers, &converted, "FORWARD_HEADERS in src/fuzz/parts.rs");
}

#[test]
fn scanner_handles_wrapped_and_nested_shapes() {
    let source = r#"
        impl HeaderDecode
            for WrappedProbe<A, B>
        {}

        macro_rules! inner_probe {
            ($type:ident) => { impl crate::HeaderDecode for $type {} };
        }
        macro_rules! outer_probe {
            ($type:ident) => { inner_probe!($type); };
        }
        macro_rules! list_probe {
            ($($type:ident => $name:ident),+) => { $(impl HeaderDecode for $type {})+ };
        }

        outer_probe!(DelegatedProbe);
        list_probe! { FirstListProbe => SERVER, SecondListProbe => SERVER }
    "#;
    let found = implementations(&[source.to_owned()], "HeaderDecode");
    for expected in [
        "WrappedProbe",
        "DelegatedProbe",
        "FirstListProbe",
        "SecondListProbe",
    ] {
        assert!(found.contains(expected), "missed {expected}: {found:?}");
    }
}

fn assert_all_exercised(implemented: &BTreeSet<String>, exercised: &BTreeSet<&str>, home: &str) {
    let missing: Vec<&String> = implemented
        .iter()
        .filter(|name| !exercised.contains(name.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "implementations without an entry in {home}: {missing:?}"
    );
}

fn base_name(name: &str) -> &str {
    name.split('<').next().unwrap_or(name).trim()
}

/// Every `src/**/*.rs` outside [`SKIPPED_DIRS`].
fn sources() -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let skipped: Vec<PathBuf> = SKIPPED_DIRS.iter().map(|dir| root.join(dir)).collect();
    let mut sources = Vec::new();
    collect_sources(&root, &skipped, &mut sources);
    sources
}

fn collect_sources(dir: &Path, skipped: &[PathBuf], out: &mut Vec<String>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if !skipped.contains(&path) {
                collect_sources(&path, skipped, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(fs::read_to_string(&path).unwrap());
        }
    }
}

/// Type names implementing `trait_name`, by hand or through (nested) macros.
fn implementations(sources: &[String], trait_name: &str) -> BTreeSet<String> {
    let sources: Vec<String> = sources.iter().map(|source| normalize(source)).collect();
    let pattern = format!("{trait_name} for ");

    let mut macros = BTreeSet::new();
    loop {
        let before = macros.len();
        for source in &sources {
            generating_macros(source, &pattern, &mut macros);
        }
        if macros.len() == before {
            break;
        }
    }

    let mut types = BTreeSet::new();
    for source in &sources {
        for (start, found) in source.match_indices(&pattern) {
            let name = ident(&source[start + found.len()..]);
            if is_type_name(name) {
                types.insert(name.to_owned());
            }
        }
        macro_generated(source, &macros, &mut types);
    }
    types
}

/// Drop line comments and collapse whitespace, so wrapped impl lines still match.
fn normalize(source: &str) -> String {
    let code: Vec<&str> = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    code.join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `macro_rules!` whose expansion implements the trait, directly or via another such macro.
fn generating_macros(source: &str, pattern: &str, macros: &mut BTreeSet<String>) {
    for (start, found) in source.match_indices("macro_rules! ") {
        let rest = &source[start + found.len()..];
        let name = ident(rest);
        let Some(body) = delimited(&rest[name.len()..]) else {
            continue;
        };
        let generates =
            body.contains(&format!("{pattern}$")) || macros.iter().any(|known| calls(body, known));
        if generates {
            macros.insert(name.to_owned());
        }
    }
}

fn calls(body: &str, macro_name: &str) -> bool {
    body.match_indices(&format!("{macro_name}!"))
        .any(|(start, _)| !is_ident_suffix(&body[..start]))
}

/// Types declared through invocations of a generating macro.
fn macro_generated(source: &str, macros: &BTreeSet<String>, out: &mut BTreeSet<String>) {
    for name in macros {
        let call = format!("{name}!");
        for (start, _) in source.match_indices(&call) {
            let before = &source[..start];
            if before.ends_with("macro_rules! ") || is_ident_suffix(before) {
                continue;
            }
            if let Some(body) = delimited(&source[start + call.len()..]) {
                out.extend(declared_types(body));
            }
        }
    }
}

/// Every `struct Name` in the invocation, else every UpperCamel identifier in it.
fn declared_types(body: &str) -> Vec<String> {
    let code = strip_attributes(body);
    let structs: Vec<String> = code
        .match_indices("struct ")
        .map(|(start, pattern)| ident(&code[start + pattern.len()..]).to_owned())
        .filter(|name| is_type_name(name))
        .collect();
    if !structs.is_empty() {
        return structs;
    }
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| is_type_name(token))
        .map(str::to_owned)
        .collect()
}

fn strip_attributes(body: &str) -> String {
    let mut code = String::with_capacity(body.len());
    let mut depth = 0usize;
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if depth == 0 && c == '#' && chars.peek() == Some(&'[') {
            chars.next();
            depth = 1;
        } else if depth > 0 {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            }
        } else {
            code.push(c);
        }
    }
    code
}

/// The text inside the first bracket pair of `s`.
fn delimited(s: &str) -> Option<&str> {
    let start = s.find(['{', '(', '['])?;
    let open = s[start..].chars().next()?;
    let close = match open {
        '{' => '}',
        '(' => ')',
        _ => ']',
    };
    let mut depth = 0usize;
    for (offset, c) in s[start..].char_indices() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return s.get(start + 1..start + offset);
            }
        }
    }
    None
}

fn ident(s: &str) -> &str {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .unwrap_or(s.len());
    &s[..end]
}

fn is_ident_suffix(before: &str) -> bool {
    before
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// UpperCamel, so `$type` and SCREAMING_CASE header name constants are skipped.
fn is_type_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_uppercase())
        && name.chars().any(|c| c.is_ascii_lowercase())
}
