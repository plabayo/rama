use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, quote};
use rama_grpc_build::{manual, naive_snake_case};
use syn::{
    Attribute, Expr, ExprLit, GenericArgument, Ident, Lit, LitBool, LitStr, Meta, Path,
    PathArguments, PathSegment, Token, Type, braced, parenthesized,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

mod kw {
    syn::custom_keyword!(package);
    syn::custom_keyword!(codec);
    syn::custom_keyword!(client);
    syn::custom_keyword!(server);
    syn::custom_keyword!(service);
    syn::custom_keyword!(rpc);
    syn::custom_keyword!(stream);
}

/// The full input of the `define_service!` macro:
/// the settings shared by all services, followed by the services themselves.
pub(crate) struct ServiceDefinitions {
    package: LitStr,
    codec: Option<Path>,
    build_client: bool,
    build_server: bool,
    services: Vec<ServiceDefinition>,
}

struct ServiceDefinition {
    comments: Vec<String>,
    name: Ident,
    codec: Option<Path>,
    methods: Vec<MethodDefinition>,
}

struct MethodDefinition {
    comments: Vec<String>,
    deprecated: bool,
    codec: Option<Path>,
    /// The method name as used in the route, PascalCase by convention.
    name: Ident,
    client_streaming: bool,
    input_type: Path,
    server_streaming: bool,
    output_type: Path,
}

impl Parse for ServiceDefinitions {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut package = None;
        let mut codec = None;
        let mut build_client = None;
        let mut build_server = None;
        let mut services = Vec::new();

        while !input.is_empty() {
            let attrs = input.call(Attribute::parse_outer)?;

            if input.peek(kw::service) {
                services.push(ServiceDefinition::parse(input, attrs)?);
                continue;
            }

            if let Some(attr) = attrs.first() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "attributes are only supported on `service` and `rpc` definitions",
                ));
            }

            let lookahead = input.lookahead1();
            if lookahead.peek(kw::package) {
                let key = input.parse::<kw::package>()?;
                set_setting(
                    &mut package,
                    parse_setting_value::<LitStr>(input)?,
                    key.span,
                )?;
            } else if lookahead.peek(kw::codec) {
                let key = input.parse::<kw::codec>()?;
                set_setting(&mut codec, parse_setting_value::<Path>(input)?, key.span)?;
            } else if lookahead.peek(kw::client) {
                let key = input.parse::<kw::client>()?;
                let value = parse_setting_value::<LitBool>(input)?;
                set_setting(&mut build_client, value.value(), key.span)?;
            } else if lookahead.peek(kw::server) {
                let key = input.parse::<kw::server>()?;
                let value = parse_setting_value::<LitBool>(input)?;
                set_setting(&mut build_server, value.value(), key.span)?;
            } else {
                return Err(lookahead.error());
            }
        }

        let Some(package) = package else {
            return Err(syn::Error::new(
                Span::call_site(),
                r#"missing `package = "<name>";` setting"#,
            ));
        };

        if services.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                "expected at least one `service <Name> { ... }` definition",
            ));
        }

        Ok(Self {
            package,
            codec,
            build_client: build_client.unwrap_or(true),
            build_server: build_server.unwrap_or(true),
            services,
        })
    }
}

impl ServiceDefinitions {
    /// Generate the client and server stubs for all defined services.
    pub(crate) fn generate(self) -> syn::Result<TokenStream> {
        let builder = manual::RamaGrpcBuilder::new()
            .with_build_client(self.build_client)
            .with_build_server(self.build_server);

        let mut module_name = String::from("__rama_grpc");
        let mut generated = TokenStream::new();
        for service in self.services {
            module_name.push('_');
            module_name.push_str(&naive_snake_case(&service.name.to_string()));

            let service = service.build(&self.package, self.codec.as_ref())?;
            generated.extend(builder.generate(&service));
        }
        let module_name = Ident::new(&module_name, Span::call_site());

        // The generated stubs live in modules of their own and refer to the user's types as
        // `super::<Type>`, which is one level too shallow: wrapping them in a module which
        // glob-imports its parent is what makes those paths resolve to whatever is in scope
        // where this macro is invoked.
        Ok(quote! {
            #[doc(hidden)]
            mod #module_name {
                #![allow(
                    unused_imports,
                    missing_docs,
                    unreachable_pub,
                    clippy::all,
                    clippy::pedantic,
                    clippy::restriction,
                    clippy::nursery,
                )]

                use super::*;

                #generated
            }

            pub use #module_name::*;
        })
    }
}

impl ServiceDefinition {
    fn parse(input: ParseStream, attrs: Vec<Attribute>) -> syn::Result<Self> {
        let attrs = ItemAttributes::parse(attrs, false)?;

        input.parse::<kw::service>()?;
        let name = input.parse::<Ident>()?;

        let content;
        braced!(content in input);

        let mut codec = None;
        let mut methods = Vec::new();
        while !content.is_empty() {
            let method_attrs = content.call(Attribute::parse_outer)?;

            if method_attrs.is_empty() && content.peek(kw::codec) {
                let key = content.parse::<kw::codec>()?;
                set_setting(&mut codec, parse_setting_value::<Path>(&content)?, key.span)?;
                continue;
            }

            methods.push(MethodDefinition::parse(&content, method_attrs)?);
        }

        if methods.is_empty() {
            return Err(syn::Error::new(
                name.span(),
                "expected at least one `rpc` definition",
            ));
        }

        Ok(Self {
            comments: attrs.comments,
            name,
            codec,
            methods,
        })
    }

    fn build(self, package: &LitStr, default_codec: Option<&Path>) -> syn::Result<manual::Service> {
        let codec = self.codec.as_ref().or(default_codec);

        let mut builder = manual::Service::builder()
            .with_name(self.name.to_string())
            .with_package(package.value());

        for comment in self.comments {
            builder.set_comment(comment);
        }

        if let Some(codec) = codec {
            builder.set_codec_path(codec_path(codec));
        }

        for method in self.methods {
            if method.codec.is_none() && codec.is_none() {
                return Err(syn::Error::new(
                    method.name.span(),
                    "no codec defined for this method: \
                     define one with `codec = <path>;` or `#[codec(<path>)]`",
                ));
            }
            builder.set_method(method.build());
        }

        Ok(builder.build())
    }
}

impl MethodDefinition {
    fn parse(input: ParseStream, attrs: Vec<Attribute>) -> syn::Result<Self> {
        let attrs = ItemAttributes::parse(attrs, true)?;

        input.parse::<kw::rpc>()?;
        let name = input.parse::<Ident>()?;

        let request;
        parenthesized!(request in input);
        let client_streaming = parse_stream_marker(&request)?;
        let input_type = request.parse::<Path>()?;
        if !request.is_empty() {
            return Err(request.error("expected a single request type"));
        }

        input.parse::<Token![->]>()?;
        let server_streaming = parse_stream_marker(input)?;
        let output_type = input.parse::<Path>()?;
        input.parse::<Token![;]>()?;

        Ok(Self {
            comments: attrs.comments,
            deprecated: attrs.deprecated,
            codec: attrs.codec,
            name,
            client_streaming,
            input_type,
            server_streaming,
            output_type,
        })
    }

    fn build(self) -> manual::RamaGrpcMethodBuilder {
        let route_name = self.name.to_string();

        let mut builder = manual::RamaGrpcMethod::builder()
            .with_name(naive_snake_case(&route_name))
            .with_route_name(route_name)
            .with_input_type(type_path(&self.input_type))
            .with_output_type(type_path(&self.output_type));

        for comment in self.comments {
            builder.set_comment(comment);
        }

        if let Some(codec) = &self.codec {
            builder.set_codec_path(codec_path(codec));
        }

        if self.client_streaming {
            builder.set_client_streaming();
        }

        if self.server_streaming {
            builder.set_server_streaming();
        }

        if self.deprecated {
            builder.set_deprecated();
        }

        builder
    }
}

#[derive(Default)]
struct ItemAttributes {
    comments: Vec<String>,
    deprecated: bool,
    codec: Option<Path>,
}

impl ItemAttributes {
    fn parse(attrs: Vec<Attribute>, is_method: bool) -> syn::Result<Self> {
        let mut out = Self::default();

        for attr in attrs {
            if attr.path().is_ident("doc") {
                let Meta::NameValue(meta) = &attr.meta else {
                    return Err(syn::Error::new_spanned(&attr, "expected a doc comment"));
                };
                let Expr::Lit(ExprLit {
                    lit: Lit::Str(comment),
                    ..
                }) = &meta.value
                else {
                    return Err(syn::Error::new_spanned(&attr, "expected a doc comment"));
                };
                out.comments.push(comment.value());
            } else if is_method && attr.path().is_ident("deprecated") {
                if attr.meta.require_path_only().is_err() {
                    return Err(syn::Error::new_spanned(
                        &attr,
                        "`#[deprecated]` takes no arguments here",
                    ));
                }
                out.deprecated = true;
            } else if is_method && attr.path().is_ident("codec") {
                out.codec = Some(attr.parse_args::<Path>()?);
            } else if is_method {
                return Err(syn::Error::new_spanned(
                    &attr,
                    "unsupported attribute: only doc comments, \
                     `#[deprecated]` and `#[codec(<path>)]` are supported here",
                ));
            } else {
                return Err(syn::Error::new_spanned(
                    &attr,
                    "unsupported attribute: only doc comments are supported here",
                ));
            }
        }

        Ok(out)
    }
}

fn parse_setting_value<T: Parse>(input: ParseStream) -> syn::Result<T> {
    input.parse::<Token![=]>()?;
    let value = input.parse::<T>()?;
    input.parse::<Token![;]>()?;
    Ok(value)
}

fn set_setting<T>(slot: &mut Option<T>, value: T, span: Span) -> syn::Result<()> {
    if slot.replace(value).is_some() {
        return Err(syn::Error::new(span, "duplicate setting"));
    }
    Ok(())
}

fn parse_stream_marker(input: ParseStream) -> syn::Result<bool> {
    if input.peek(kw::stream) {
        input.parse::<kw::stream>()?;
        return Ok(true);
    }
    Ok(false)
}

/// Rewrite a message type as it is to be used from within the generated module.
fn type_path(path: &Path) -> String {
    qualified(path).to_token_stream().to_string()
}

/// Rewrite a codec type as it is to be used from within the generated module.
///
/// The codec is referenced in expression position (`<codec>::default()`),
/// where generic arguments need to be turbofished,
/// so that `SerdeCodec<JsonFormat>` is accepted just as `SerdeCodec::<JsonFormat>` is.
fn codec_path(path: &Path) -> String {
    let mut path = qualified(path);
    for segment in &mut path.segments {
        if let PathArguments::AngleBracketed(args) = &mut segment.arguments {
            args.colon2_token.get_or_insert_with(<Token![::]>::default);
        }
    }
    path.to_token_stream().to_string()
}

/// Make a path written in the module invoking the macro
/// resolve the same from within the generated module, which is one level deeper.
///
/// Paths rooted in `crate` or `::` already resolve from anywhere and are kept as-is.
fn qualified(path: &Path) -> Path {
    let mut path = path.clone();

    // generic arguments are written in that same module, so they move along with it
    for segment in &mut path.segments {
        if let PathArguments::AngleBracketed(args) = &mut segment.arguments {
            for arg in &mut args.args {
                if let GenericArgument::Type(Type::Path(type_path)) = arg
                    && type_path.qself.is_none()
                {
                    type_path.path = qualified(&type_path.path);
                }
            }
        }
    }

    if path.leading_colon.is_some() {
        return path;
    }

    let Some(first) = path.segments.first_mut() else {
        return path;
    };

    if first.ident == "crate" {
        return path;
    }

    if first.ident == "self" {
        first.ident = Ident::new("super", first.ident.span());
        return path;
    }

    let mut segments = Punctuated::new();
    segments.push(PathSegment::from(Ident::new("super", Span::call_site())));
    segments.extend(path.segments);

    Path {
        leading_colon: None,
        segments,
    }
}
