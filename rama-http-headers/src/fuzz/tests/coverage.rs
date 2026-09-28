//! Every type implementing `HeaderDecode` in this crate must be exercised by the harness.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use super::values_exercises;

// Scanned directories that hold no live typed headers.
const SKIPPED_DIRS: &[&str] = &["disabled", "fuzz"];

#[test]
fn every_typed_header_is_exercised() {
    let mut sources = Vec::new();
    collect_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );

    let mut macros = BTreeSet::new();
    for source in &sources {
        generating_macros(source, &mut macros);
    }
    let mut headers = BTreeSet::new();
    for source in &sources {
        direct_impls(source, &mut headers);
        macro_generated(source, &macros, &mut headers);
    }

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
        .map(|(name, _)| name.split('<').next().unwrap_or(name).trim())
        .collect();
    let missing: Vec<&String> = headers
        .iter()
        .filter(|header| !exercised.contains(header.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "typed headers without an entry in rama-http-headers/src/fuzz/headers: {missing:?}"
    );
}

fn collect_sources(dir: &Path, out: &mut Vec<String>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            let skipped = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| SKIPPED_DIRS.contains(&name));
            if !skipped {
                collect_sources(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(fs::read_to_string(&path).unwrap());
        }
    }
}

/// `impl ... HeaderDecode for Name` written out by hand.
fn direct_impls(source: &str, out: &mut BTreeSet<String>) {
    for (start, pattern) in source.match_indices("HeaderDecode for ") {
        let name = ident(&source[start + pattern.len()..]);
        if is_type_name(name) {
            out.insert(name.to_owned());
        }
    }
}

/// Names of the `macro_rules!` whose expansion implements `HeaderDecode`.
fn generating_macros(source: &str, out: &mut BTreeSet<String>) {
    for (start, pattern) in source.match_indices("macro_rules! ") {
        let rest = &source[start + pattern.len()..];
        let name = ident(rest);
        if delimited(&rest[name.len()..]).is_some_and(|body| body.contains("HeaderDecode for $")) {
            out.insert(name.to_owned());
        }
    }
}

/// Header types declared through invocations of a generating macro.
fn macro_generated(source: &str, macros: &BTreeSet<String>, out: &mut BTreeSet<String>) {
    for name in macros {
        let call = format!("{name}!");
        for (start, _) in source.match_indices(&call) {
            let before = &source[..start];
            let is_definition = before.ends_with("macro_rules! ");
            let is_suffix = before
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            if is_definition || is_suffix {
                continue;
            }
            if let Some(body) = delimited(&source[start + call.len()..]) {
                out.extend(declared_types(body));
            }
        }
    }
}

/// Every `struct Name` in the invocation, else its first identifier (`derive_header!(ETag(_), ..)`).
fn declared_types(body: &str) -> Vec<String> {
    let code = strip_attributes_and_comments(body);
    let structs: Vec<String> = code
        .match_indices("struct ")
        .map(|(start, pattern)| ident(&code[start + pattern.len()..]).to_owned())
        .filter(|name| is_type_name(name))
        .collect();
    if !structs.is_empty() {
        return structs;
    }
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find(|token| !token.is_empty())
        .filter(|token| is_type_name(token))
        .map(str::to_owned)
        .into_iter()
        .collect()
}

fn strip_attributes_and_comments(body: &str) -> String {
    let without_comments: String = body
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut code = String::with_capacity(without_comments.len());
    let mut depth = 0usize;
    let mut chars = without_comments.chars().peekable();
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

fn is_type_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_uppercase())
}
