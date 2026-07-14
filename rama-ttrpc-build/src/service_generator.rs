use proc_macro2::TokenStream;
use prost_build::{Comments, Method, Service, ServiceGenerator};
use quote::{format_ident, quote};

use crate::root_crate::root_crate_name_ts;

/// A service generator that takes a service descriptor and generates Rust code for a `ttrpc` service.
///
/// It generates a trait describing methods of the service and implements the trait for the
/// `rama-ttrpc` `Client`. To implement a server, users should implement the trait on their own
/// objects. All references to `rama-ttrpc` are emitted through `root_crate_name_ts` so the
/// generated code works whether the consumer depends on `rama` or `rama-ttrpc`.
pub struct TtrpcServiceGenerator;

impl ServiceGenerator for TtrpcServiceGenerator {
    fn generate(&mut self, service: Service, buf: &mut String) {
        let root = root_crate_name_ts();
        let service_ident = format_ident!("{}", service.name);
        let service_comments = doc_comments(&service.comments);

        let trait_methods = service
            .methods
            .iter()
            .map(|m| trait_method(&service, m, &root));
        let client_methods = service
            .methods
            .iter()
            .map(|m| client_method(&service, m, &root));
        let dispatch_branches = service
            .methods
            .iter()
            .map(|m| dispatch_branch(&service, m, &root));

        let tokens = quote! {
            #[allow(dead_code, non_snake_case)]
            pub fn #service_ident<T: #service_ident>(
                target: impl std::convert::Into<std::sync::Arc<T>>,
            ) -> impl #root::__codegen_prelude::Service {
                struct Service<T: #service_ident> {
                    target: std::sync::Arc<T>,
                }
                impl<T: #service_ident> #root::__codegen_prelude::Service for Service<T> {
                    fn methods(
                        &self,
                    ) -> std::vec::Vec<(
                        &'static str,
                        std::sync::Arc<dyn #root::__codegen_prelude::MethodHandler + Send + Sync>,
                    )> {
                        let target = &self.target;
                        vec![
                            #(#dispatch_branches)*
                        ]
                    }
                }
                Service { target: target.into() }
            }

            #service_comments
            pub trait #service_ident: Send + Sync + 'static {
                #(#trait_methods)*
            }

            impl #service_ident for #root::Client {
                #(#client_methods)*
            }
        };

        buf.push_str(&tokens.to_string());
    }
}

fn trait_method(service: &Service, method: &Method, root: &TokenStream) -> TokenStream {
    let name = format_ident!("{}", method.name);
    let input_name = format_ident!("{}", camel2snake(&method.input_type));
    let input_type = input_type(method, root);
    let output_type = output_type(method, root);
    let comments = doc_comments(&method.comments);

    // UNIMPLEMENTED matches the Go implementation for unhandled methods
    // (containerd/ttrpc services.go `codes.Unimplemented`), which capability-probing
    // clients rely on.
    let unimplemented_message = format!("{} is not supported", method_path(service, method));
    let unimplemented_body = if method.server_streaming {
        quote! { #root::stream::once(async move { Err(unimplemented) }) }
    } else {
        quote! { async move { Err(unimplemented) } }
    };

    quote! {
        #comments
        #[allow(unused_variables)]
        fn #name(&self, #input_name: #input_type) -> #output_type {
            let unimplemented = #root::Status {
                code: #root::Code::Unimplemented as i32,
                message: #unimplemented_message.into(),
                details: vec![],
            };
            #unimplemented_body
        }
    }
}

fn client_method(service: &Service, method: &Method, root: &TokenStream) -> TokenStream {
    let name = format_ident!("{}", method.name);
    let input_name = format_ident!("{}", camel2snake(&method.input_type));
    let input_type = input_type(method, root);
    let output_type = output_type(method, root);
    let request_handler = format_ident!("{}", request_handler(method));
    let service_name = service_name(service);
    let proto_name = &method.proto_name;

    quote! {
        fn #name(&self, #input_name: #input_type) -> #output_type {
            #root::__codegen_prelude::RequestHandler::#request_handler(
                self,
                #service_name,
                #proto_name,
                #input_name,
            )
        }
    }
}

fn dispatch_branch(service: &Service, method: &Method, root: &TokenStream) -> TokenStream {
    let path = method_path(service, method);
    let name = format_ident!("{}", method.name);
    let wrapper = format_ident!("{}", wrapper(method));

    let output_handler = if method.server_streaming {
        quote! {
            #root::stream::stream_fn(move |mut yielder| async move {
                let stream = target.#name(input);
                let mut stream = std::pin::pin!(stream);
                while let Some(value) = #root::stream::StreamExt::next(&mut stream).await {
                    yielder.yield_item(value).await;
                }
            })
        }
    } else {
        quote! { async move { target.#name(input).await } }
    };

    quote! {
        (
            #path,
            {
                let target = std::sync::Arc::clone(&target);
                std::sync::Arc::new(#root::__codegen_prelude::#wrapper::new(move |input| {
                    let target = std::sync::Arc::clone(&target);
                    #output_handler
                }))
            },
        ),
    }
}

/// The request/response type in method signatures, wrapped for streaming as needed.
fn input_type(method: &Method, root: &TokenStream) -> TokenStream {
    let ty = parse_type(&method.input_type);
    if method.client_streaming {
        quote! { impl #root::prelude::Stream<Item = #ty> + Send }
    } else {
        ty
    }
}

fn output_type(method: &Method, root: &TokenStream) -> TokenStream {
    let ty = parse_type(&method.output_type);
    if method.server_streaming {
        quote! { impl #root::prelude::Stream<Item = #root::Result<#ty>> + Send }
    } else {
        quote! { impl #root::prelude::Future<Output = #root::Result<#ty>> + Send }
    }
}

fn wrapper(method: &Method) -> &'static str {
    match (method.client_streaming, method.server_streaming) {
        (false, false) => "UnaryMethod",
        (false, true) => "ServerStreamingMethod",
        (true, false) => "ClientStreamingMethod",
        (true, true) => "DuplexStreamingMethod",
    }
}

fn request_handler(method: &Method) -> &'static str {
    match (method.client_streaming, method.server_streaming) {
        (false, false) => "handle_unary_request",
        (false, true) => "handle_server_streaming_request",
        (true, false) => "handle_client_streaming_request",
        (true, true) => "handle_duplex_streaming_request",
    }
}

/// The fully-qualified proto service name, e.g. `rama.examples.greeter.v1.Greeter`.
fn service_name(service: &Service) -> String {
    qualified_service_name(&service.package, &service.proto_name)
}

/// Join a proto package and service into a fully-qualified name, matching protobuf's rule that a
/// package-less service's full name is just the service name (no leading dot).
fn qualified_service_name(package: &str, proto_name: &str) -> String {
    if package.is_empty() {
        proto_name.to_owned()
    } else {
        format!("{package}.{proto_name}")
    }
}

/// The ttRPC method path, e.g. `/rama.examples.greeter.v1.Greeter/SayHello`.
fn method_path(service: &Service, method: &Method) -> String {
    format!("/{}/{}", service_name(service), method.proto_name)
}

/// Turn prost leading comments into `#[doc = "..."]` attributes.
fn doc_comments(comments: &Comments) -> TokenStream {
    let docs = comments.leading.iter().map(|line| {
        let line = if line.starts_with(' ') {
            line.clone()
        } else {
            format!(" {line}")
        };
        quote! { #[doc = #line] }
    });
    quote! { #(#docs)* }
}

fn parse_type(ty: &str) -> TokenStream {
    ty.parse().unwrap()
}

fn camel2snake(name: impl AsRef<str>) -> String {
    let name = name.as_ref();
    // take the last `::`-separated segment (the bare type name)
    let name = name.rsplit("::").next().unwrap_or(name);
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            // word boundary: after a non-uppercase char, or the last char of an acronym
            // run ("HTTPRequest" -> "http_request", not "h_t_t_p_request")
            let after_lower = i > 0 && !chars[i - 1].is_uppercase();
            let acronym_end = chars.get(i + 1).is_some_and(|next| next.is_lowercase());
            if i > 0 && (after_lower || acronym_end) {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{camel2snake, qualified_service_name};

    #[test]
    fn qualified_service_name_omits_empty_package() {
        // protobuf full name of a package-less service is the bare service name, not `.Greeter`.
        assert_eq!(qualified_service_name("", "Greeter"), "Greeter");
        assert_eq!(
            qualified_service_name("pkg.v1", "Greeter"),
            "pkg.v1.Greeter"
        );
    }

    #[test]
    fn camel2snake_handles_acronyms_and_paths() {
        assert_eq!(camel2snake("HelloRequest"), "hello_request");
        assert_eq!(camel2snake("HTTPRequest"), "http_request");
        assert_eq!(camel2snake("MyHTTPRequest"), "my_http_request");
        assert_eq!(camel2snake("super::pb::EchoRequest"), "echo_request");
        assert_eq!(camel2snake("Request2X"), "request2_x");
        assert_eq!(camel2snake("lowercase"), "lowercase");
    }
}
