//! Implementation details of the `include_dir`.
//!
//! You probably don't want to use this crate directly.

use proc_macro::{TokenStream, TokenTree};
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Literal, Span};
use quote::quote;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    path::{Path, PathBuf},
    time::SystemTime,
};

pub(super) fn execute(input: TokenStream) -> TokenStream {
    let tokens: Vec<_> = input.into_iter().collect();

    let path = match tokens.as_slice() {
        [TokenTree::Literal(lit)] => unwrap_string_literal(lit),
        _ => panic!("This macro only accepts a single, non-empty string argument"),
    };

    let path = resolve_path_from_callee(&path, get_env).unwrap();
    let root_crate = support_root_ts();

    expand_dir(&path, &path, &root_crate).into()
}

fn unwrap_string_literal(lit: &proc_macro::Literal) -> String {
    let mut repr = lit.to_string();
    if !repr.starts_with('"') || !repr.ends_with('"') {
        panic!("This macro only accepts a single, non-empty string argument")
    }

    repr.remove(0);
    repr.pop();

    if repr.is_empty() {
        panic!("This macro only accepts a single, non-empty string argument")
    }

    repr
}

fn expand_dir(
    root: &Path,
    path: &Path,
    root_crate: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let children = read_dir(path).unwrap_or_else(|e| {
        panic!(
            "Unable to read the entries in \"{}\": {}",
            path.display(),
            e
        )
    });

    let mut child_tokens = Vec::new();

    for child in children {
        if child.is_dir() {
            let tokens = expand_dir(root, &child, root_crate);
            child_tokens.push(quote! {
                #root_crate::include_dir::DirEntry::Dir(#tokens)
            });
        } else if child.is_file() {
            let tokens = expand_file(root, &child, root_crate);
            child_tokens.push(quote! {
                #root_crate::include_dir::DirEntry::File(#tokens)
            });
        } else {
            panic!("\"{}\" is neither a file nor a directory", child.display());
        }
    }

    let normalized_path = normalize_path(root, path);
    quote! {
        #root_crate::include_dir::Dir::new(#normalized_path, {
            const ENTRIES: &'static [#root_crate::include_dir::DirEntry<'static>] = &[ #(#child_tokens),*];
            ENTRIES
        })
    }
}

fn expand_file(
    root: &Path,
    path: &Path,
    root_crate: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let abs = path
        .canonicalize()
        .unwrap_or_else(|e| panic!("failed to resolve \"{}\": {}", path.display(), e));
    let literal = if let Some(abs) = abs.to_str() {
        quote!(include_bytes!(#abs))
    } else {
        let contents = read_file(path);
        let literal = Literal::byte_string(&contents);
        quote!(#literal)
    };

    let normalized_path = normalize_path(root, path);
    let tokens = quote! {
        #root_crate::include_dir::File::new(#normalized_path, #literal)
    };

    match metadata(path, root_crate) {
        Some(metadata) => quote!(#tokens.with_metadata(#metadata)),
        None => tokens,
    }
}

fn metadata(
    path: &Path,
    root_crate: &proc_macro2::TokenStream,
) -> Option<proc_macro2::TokenStream> {
    fn to_unix(t: SystemTime) -> u64 {
        t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }

    let meta = path.metadata().ok()?;
    let accessed = meta.accessed().map(to_unix).ok()?;
    let created = meta.created().map(to_unix).ok()?;
    let modified = meta.modified().map(to_unix).ok()?;

    Some(quote! {
        #root_crate::include_dir::Metadata::new(
            std::time::Duration::from_secs(#accessed),
            std::time::Duration::from_secs(#created),
            std::time::Duration::from_secs(#modified),
        )
    })
}

fn normalize_path<'a>(root: &Path, path: &'a Path) -> &'a str {
    path.strip_prefix(root)
        .expect("Should only ever be called using paths inside the root path")
        .to_str()
        .expect("path must be valid UTF-8; open a PR in rama if you know how to accept non UTF-8 in const contexts")
}

fn read_dir(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    if !dir.is_dir() {
        panic!("\"{}\" is not a directory", dir.display());
    }

    track_path(dir);

    let mut paths = Vec::new();

    for entry in dir.read_dir()? {
        let entry = entry?;
        paths.push(entry.path());
    }

    paths.sort();

    Ok(paths)
}

fn read_file(path: &Path) -> Vec<u8> {
    track_path(path);
    std::fs::read(path).unwrap_or_else(|e| panic!("Unable to read \"{}\": {}", path.display(), e))
}

fn resolve_path_from_callee(
    raw: &str,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<PathBuf, Box<dyn Error>> {
    let resolved = resolve_path(raw, get_env)?;

    #[cfg(target_os = "windows")]
    let resolved = resolved.replace('/', "\\");
    #[cfg(not(target_os = "windows"))]
    let resolved = resolved.replace('\\', "/");

    let resolved = PathBuf::from(resolved);

    Ok(
        if !resolved.is_absolute()
            && let Some(parent) = proc_macro::Span::call_site()
                .local_file()
                .and_then(|f| f.parent().map(|p| p.to_owned()))
        {
            parent.join(resolved)
        } else {
            resolved
        },
    )
}

fn resolve_path(
    raw: &str,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<String, Box<dyn Error>> {
    let mut unprocessed = raw;
    let mut resolved = String::new();

    while let Some(dollar_sign) = unprocessed.find('$') {
        let (head, tail) = unprocessed.split_at(dollar_sign);
        resolved.push_str(head);

        match parse_identifier(&tail[1..]) {
            Some((variable, rest)) => {
                let value = get_env(variable).ok_or_else(|| MissingVariable {
                    variable: variable.to_owned(),
                })?;
                resolved.push_str(&value);
                unprocessed = rest;
            }
            None => {
                return Err(UnableToParseVariable { rest: tail.into() }.into());
            }
        }
    }
    resolved.push_str(unprocessed);
    Ok(resolved)
}

#[derive(Debug, PartialEq)]
struct MissingVariable {
    variable: String,
}

impl Error for MissingVariable {}

impl Display for MissingVariable {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Unable to resolve ${}", self.variable)
    }
}

#[derive(Debug, PartialEq)]
struct UnableToParseVariable {
    rest: String,
}

impl Error for UnableToParseVariable {}

impl Display for UnableToParseVariable {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Unable to parse a variable from \"{}\"", self.rest)
    }
}

fn parse_identifier(text: &str) -> Option<(&str, &str)> {
    let mut calls = 0;

    let (head, tail) = take_while(text, |c| {
        calls += 1;

        match c {
            '_' => true,
            letter if letter.is_ascii_alphabetic() => true,
            digit if digit.is_ascii_digit() && calls > 1 => true,
            _ => false,
        }
    });

    if head.is_empty() {
        None
    } else {
        Some((head, tail))
    }
}

fn take_while(s: &str, mut predicate: impl FnMut(char) -> bool) -> (&str, &str) {
    let mut index = 0;

    for c in s.chars() {
        if predicate(c) {
            index += c.len_utf8();
        } else {
            break;
        }
    }

    s.split_at(index)
}

fn get_env(variable: &str) -> Option<String> {
    std::env::var(variable).ok()
}

fn track_path(_path: &Path) {
    // #[cfg(feature = "nightly")]
    // proc_macro::tracked_path::path(_path.to_string_lossy());
}

fn support_root_ts() -> proc_macro2::TokenStream {
    // Prefer the umbrella crate
    if let Ok(found) = crate_name("rama") {
        let ident = match found {
            FoundCrate::Itself => Ident::new("rama", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };
        return quote!(::#ident::utils);
    }

    // Fall back to the utils crate directly
    if let Ok(found) = crate_name("rama-utils") {
        return match found {
            FoundCrate::Itself => quote!(crate),
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site());
                quote!(::#ident)
            }
        };
    }

    quote! {
        { compile_error!(
            "include_dir could not find support types. \
             Add a dependency on `rama` or `rama-utils`."
        ); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_path_with_no_environment_variables() {
        let path = "./file.txt";

        let resolved = resolve_path(path, |_| unreachable!()).unwrap();

        assert_eq!(resolved, path);
    }

    #[test]
    fn simple_environment_variable() {
        let path = "./$VAR";

        let resolved = resolve_path(path, |name| {
            assert_eq!(name, "VAR");
            Some("file.txt".to_owned())
        })
        .unwrap();

        assert_eq!(resolved, "./file.txt");
    }

    #[test]
    fn dont_resolve_recursively() {
        let path = "./$TOP_LEVEL.txt";

        let resolved = resolve_path(path, |name| match name {
            "TOP_LEVEL" => Some("$NESTED".to_owned()),
            "$NESTED" => unreachable!("Shouldn't resolve recursively"),
            _ => unreachable!(),
        })
        .unwrap();

        assert_eq!(resolved, "./$NESTED.txt");
    }

    #[test]
    fn parse_valid_identifiers() {
        let inputs = vec![
            ("a", "a"),
            ("a_", "a_"),
            ("_asf", "_asf"),
            ("a1", "a1"),
            ("a1_#sd", "a1_"),
        ];

        for (src, expected) in inputs {
            let (got, rest) = parse_identifier(src).unwrap();
            assert_eq!(got.len() + rest.len(), src.len());
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn unknown_environment_variable() {
        let path = "$UNKNOWN";

        let err = resolve_path(path, |_| None).unwrap_err();

        let missing_variable = err.downcast::<MissingVariable>().unwrap();
        assert_eq!(
            *missing_variable,
            MissingVariable {
                variable: String::from("UNKNOWN"),
            }
        );
    }

    #[test]
    fn invalid_variables() {
        let inputs = ["$1", "$"];

        for input in inputs {
            let err = resolve_path(input, |_| unreachable!()).unwrap_err();

            let err = err.downcast::<UnableToParseVariable>().unwrap();
            assert_eq!(
                *err,
                UnableToParseVariable {
                    rest: input.to_owned()
                }
            );
        }
    }
}
