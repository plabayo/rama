use proc_macro2::TokenStream;
use prost_build::{Comments, Method, Service, ServiceGenerator};
use quote::{format_ident, quote};

use crate::root_crate::root_crate_name_ts;

/// A service generator that takes a service descriptor and generates Rust code for a `ttrpc` service.
///
/// It generates a trait describing methods of the service and implements the trait for the
/// `rama-ttrpc` `Client`. To implement a server, users should implement the trait on their own
/// objects. All references to `rama-ttrpc` are emitted through [`root_crate_name_ts`] so the
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

    let not_found_message = format!("{} is not supported", method_path(service, method));
    let not_found_body = if method.server_streaming {
        quote! { #root::stream::once(async move { Err(not_found) }) }
    } else {
        quote! { async move { Err(not_found) } }
    };

    quote! {
        #comments
        #[allow(unused_variables)]
        fn #name(&self, #input_name: #input_type) -> #output_type {
            let not_found = #root::Status {
                code: #root::Code::NotFound as i32,
                message: #not_found_message.into(),
                details: vec![],
            };
            #not_found_body
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
                #service_name.into(),
                #proto_name.into(),
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
    format!("{}.{}", service.package, service.proto_name)
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
    name.chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i > 0 && c.is_uppercase() {
                vec!['_'].into_iter().chain(c.to_lowercase())
            } else {
                vec![].into_iter().chain(c.to_lowercase())
            }
        })
        .collect()
}
