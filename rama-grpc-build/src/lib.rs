//! Grpc codgen support for rama

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]
#![allow(clippy::disallowed_types)] // for interfacing with protobuf it is easier to allow things like std HashMap)]

use proc_macro2::{Delimiter, Group, Ident, Literal, Punct, Spacing, Span, TokenStream};
use quote::TokenStreamExt;

pub mod manual;

#[cfg(feature = "protobuf")]
pub mod protobuf;

/// Service code generation for client
mod client;
/// Service code generation for Server
mod server;

mod root_crate;

mod code_gen;
pub(crate) use code_gen::CodeGenBuilder;

/// Service generation trait.
///
/// This trait can be implemented and consumed
/// by `client::generate` and `server::generate`
/// to allow any codegen module to generate service
/// abstractions.
pub trait Service {
    /// Comment type.
    type Comment: AsRef<str>;

    /// Method type.
    type Method: Method;

    /// Name of service.
    fn name(&self) -> &str;
    /// Package name of service.
    fn package(&self) -> &str;
    /// Identifier used to generate type name.
    fn identifier(&self) -> &str;
    /// Methods provided by service.
    fn methods(&self) -> &[Self::Method];
    /// Get comments about this item.
    fn comment(&self) -> &[Self::Comment];
}

/// Method generation trait.
///
/// Each service contains a set of generic
/// `Methods`'s that will be used by codegen
/// to generate abstraction implementations for
/// the provided methods.
pub trait Method {
    /// Comment type.
    type Comment: AsRef<str>;

    /// Name of method.
    fn name(&self) -> &str;
    /// Identifier used to generate type name.
    fn identifier(&self) -> &str;
    /// Path to the codec.
    fn codec_path(&self) -> &str;
    /// Method is streamed by client.
    fn client_streaming(&self) -> bool;
    /// Method is streamed by server.
    fn server_streaming(&self) -> bool;
    /// Get comments about this item.
    fn comment(&self) -> &[Self::Comment];
    /// Method is deprecated.
    fn deprecated(&self) -> bool {
        false
    }
    /// Type name of request and response.
    fn request_response_name(
        &self,
        proto_path: &str,
        compile_well_known_types: bool,
    ) -> (TokenStream, TokenStream);
}

/// Attributes that will be added to `mod` and `struct` items.
#[derive(Debug, Default, Clone)]
pub struct Attributes {
    /// `mod` attributes.
    module: Vec<(String, String)>,
    /// `struct` attributes.
    structure: Vec<(String, String)>,
    /// `trait` attributes.
    trait_attributes: Vec<(String, String)>,
}

impl Attributes {
    fn for_mod(&self, name: &str) -> Vec<syn::Attribute> {
        generate_attributes(name, &self.module)
    }

    fn for_struct(&self, name: &str) -> Vec<syn::Attribute> {
        generate_attributes(name, &self.structure)
    }

    fn for_trait(&self, name: &str) -> Vec<syn::Attribute> {
        generate_attributes(name, &self.trait_attributes)
    }

    /// Add an attribute that will be added to `mod` items matching the given pattern.
    pub fn push_mod(&mut self, pattern: impl Into<String>, attr: impl Into<String>) {
        self.module.push((pattern.into(), attr.into()));
    }

    /// Add an attribute that will be added to `struct` items matching the given pattern.
    pub fn push_struct(&mut self, pattern: impl Into<String>, attr: impl Into<String>) {
        self.structure.push((pattern.into(), attr.into()));
    }

    /// Add an attribute that will be added to `trait` items matching the given pattern.
    pub fn push_trait(&mut self, pattern: impl Into<String>, attr: impl Into<String>) {
        self.trait_attributes.push((pattern.into(), attr.into()));
    }
}

fn format_service_name<T: Service>(service: &T, emit_package: bool) -> String {
    let package = if emit_package { service.package() } else { "" };
    format!(
        "{}{}{}",
        package,
        if package.is_empty() { "" } else { "." },
        service.identifier(),
    )
}

fn format_method_path<T: Service>(service: &T, method: &T::Method, emit_package: bool) -> String {
    format!(
        "/{}/{}",
        format_service_name(service, emit_package),
        method.identifier()
    )
}

fn format_method_name<T: Service>(service: &T, method: &T::Method, emit_package: bool) -> String {
    format!(
        "{}.{}",
        format_service_name(service, emit_package),
        method.identifier()
    )
}

// Generates attributes given a list of (`pattern`, `attribute`) pairs. If `pattern` matches `name`, `attribute` will be included.
fn generate_attributes<'a>(
    name: &str,
    attrs: impl IntoIterator<Item = &'a (String, String)>,
) -> Vec<syn::Attribute> {
    attrs
        .into_iter()
        .filter(|(matcher, _)| match_name(matcher, name))
        .flat_map(|(_, attr)| {
            // attributes cannot be parsed directly, so we pretend they're on a struct
            syn::parse_str::<syn::DeriveInput>(&format!("{attr}\nstruct fake;"))
                .unwrap()
                .attrs
        })
        .collect::<Vec<_>>()
}

fn generate_deprecated() -> TokenStream {
    let mut deprecated_stream = TokenStream::new();
    deprecated_stream.append(Ident::new("deprecated", Span::call_site()));

    let group = Group::new(Delimiter::Bracket, deprecated_stream);

    let mut stream = TokenStream::new();
    stream.append(Punct::new('#', Spacing::Alone));
    stream.append(group);

    stream
}

// Generate a singular line of a doc comment
fn generate_doc_comment<S: AsRef<str>>(comment: S) -> TokenStream {
    let comment = comment.as_ref();

    let comment = if !comment.starts_with(' ') {
        format!(" {comment}")
    } else {
        comment.to_owned()
    };

    let mut doc_stream = TokenStream::new();

    doc_stream.append(Ident::new("doc", Span::call_site()));
    doc_stream.append(Punct::new('=', Spacing::Alone));
    doc_stream.append(Literal::string(comment.as_ref()));

    let group = Group::new(Delimiter::Bracket, doc_stream);

    let mut stream = TokenStream::new();
    stream.append(Punct::new('#', Spacing::Alone));
    stream.append(group);
    stream
}

// Generate a larger doc comment composed of many lines of doc comments
fn generate_doc_comments<T: AsRef<str>>(comments: &[T]) -> TokenStream {
    let mut stream = TokenStream::new();

    for comment in comments {
        stream.extend(generate_doc_comment(comment));
    }

    stream
}

// Checks whether a path pattern matches a given path.
pub(crate) fn match_name(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() {
        false
    } else if pattern == "." || pattern == path {
        true
    } else {
        let pattern_segments = pattern.split('.').collect::<Vec<_>>();
        let path_segments = path.split('.').collect::<Vec<_>>();

        if &pattern[..1] == "." {
            // prefix match
            if pattern_segments.len() > path_segments.len() {
                false
            } else {
                pattern_segments[..] == path_segments[..pattern_segments.len()]
            }
        // suffix match
        } else if pattern_segments.len() > path_segments.len() {
            false
        } else {
            pattern_segments[..] == path_segments[path_segments.len() - pattern_segments.len()..]
        }
    }
}

fn naive_snake_case(name: &str) -> String {
    let mut s = String::new();
    let mut it = name.chars().peekable();

    while let Some(x) = it.next() {
        s.push(x.to_ascii_lowercase());
        if let Some(y) = it.peek()
            && y.is_uppercase()
        {
            s.push('_');
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_name() {
        assert!(match_name(".", ".my.protos"));
        assert!(match_name(".", ".protos"));

        assert!(match_name(".my", ".my"));
        assert!(match_name(".my", ".my.protos"));
        assert!(match_name(".my.protos.Service", ".my.protos.Service"));

        assert!(match_name("Service", ".my.protos.Service"));

        assert!(!match_name(".m", ".my.protos"));
        assert!(!match_name(".p", ".protos"));

        assert!(!match_name(".my", ".myy"));
        assert!(!match_name(".protos", ".my.protos"));
        assert!(!match_name(".Service", ".my.protos.Service"));

        assert!(!match_name("service", ".my.protos.Service"));
    }

    #[test]
    fn test_snake_case() {
        for case in &[
            ("Service", "service"),
            ("ThatHasALongName", "that_has_a_long_name"),
            ("greeter", "greeter"),
            ("ABCServiceX", "a_b_c_service_x"),
        ] {
            assert_eq!(naive_snake_case(case.0), case.1)
        }
    }
}
