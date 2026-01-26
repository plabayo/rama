use std::collections::HashSet;

use super::{Attributes, Method, Service};
use crate::{
    format_method_name, format_method_path, format_service_name, generate_deprecated,
    generate_doc_comments, naive_snake_case,
};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(crate) fn generate_internal<T: Service>(
    service: &T,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    attributes: &Attributes,
    disable_comments: &HashSet<String>,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let service_ident = quote::format_ident!("{}Client", service.name());
    let client_mod = quote::format_ident!("{}_client", naive_snake_case(service.name()));
    let methods = generate_methods(
        service,
        emit_package,
        proto_path,
        compile_well_known_types,
        disable_comments,
        root_crate_name,
    );

    let package = if emit_package { service.package() } else { "" };
    let service_name = format_service_name(service, emit_package);

    let service_doc = if disable_comments.contains(&service_name) {
        TokenStream::new()
    } else {
        generate_doc_comments(service.comment())
    };

    let mod_attributes = attributes.for_mod(package);
    let struct_attributes = attributes.for_struct(&service_name);

    quote! {
        /// Generated client implementations.
        #(#mod_attributes)*
        pub mod #client_mod {
            #![allow(
                unused_variables,
                dead_code,
                missing_docs,
                clippy::all,
                clippy::pedantic,
                clippy::restriction,
                clippy::nursery,
            )]

            #service_doc
            #(#struct_attributes)*
            #[derive(Debug, Clone)]
            pub struct #service_ident<T> {
                inner: #root_crate_name::client::Grpc<T>,
            }

            impl<T> #service_ident<T>
            where
                T: #root_crate_name::client::GrpcService<
                    #root_crate_name::codegen::http::Body,
                    Error: Into<#root_crate_name::codegen::BoxError>,
                    ResponseBody: #root_crate_name::codegen::http::StreamingBody<
                        Data = #root_crate_name::codegen::Bytes,
                        Error: Into<#root_crate_name::codegen::BoxError> + Send
                    > + Send  + Sync + 'static,
                >,
            {
                pub fn new(inner: T, origin: #root_crate_name::codegen::http::Uri) -> Self {
                    let inner = #root_crate_name::client::Grpc::new(inner, origin);
                    Self { inner }
                }

                pub fn into_inner(self) -> #root_crate_name::client::Grpc<T> {
                    self.inner
                }

                pub fn into_transport(self) -> T {
                    self.inner.into_inner()
                }

                #root_crate_name::codegen::generate_set_and_with! {
                    /// Compress requests with the given encoding.
                    ///
                    /// This requires the server to support it otherwise it might respond with an
                    /// error.
                    pub fn send_compressed(mut self, encoding: #root_crate_name::codec::CompressionEncoding) -> Self {
                        self.inner.set_send_compressed(encoding);
                        self
                    }
                }

                #root_crate_name::codegen::generate_set_and_with! {
                    /// Enable decompressing responses.
                    pub fn accept_compressed(mut self, encoding: #root_crate_name::codec::CompressionEncoding) -> Self {
                        self.inner.set_accept_compressed(encoding);
                        self
                    }
                }

                #root_crate_name::codegen::generate_set_and_with! {
                    /// Limits the maximum size of a decoded message.
                    ///
                    /// Default: `4MB`
                    pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
                        self.inner.set_max_decoding_message_size(limit);
                        self
                    }
                }

                #root_crate_name::codegen::generate_set_and_with! {
                    /// Limits the maximum size of an encoded message.
                    ///
                    /// Default: `usize::MAX`
                    pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
                        self.inner.set_max_encoding_message_size(limit);
                        self
                    }
                }

                #methods
            }
        }
    }
}

fn generate_methods<T: Service>(
    service: &T,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    disable_comments: &HashSet<String>,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let mut stream = TokenStream::new();

    for method in service.methods() {
        if !disable_comments.contains(&format_method_name(service, method, emit_package)) {
            stream.extend(generate_doc_comments(method.comment()));
        }
        if method.deprecated() {
            stream.extend(generate_deprecated());
        }

        let method = match (method.client_streaming(), method.server_streaming()) {
            (false, false) => generate_unary(
                service,
                method,
                emit_package,
                proto_path,
                compile_well_known_types,
                root_crate_name,
            ),
            (false, true) => generate_server_streaming(
                service,
                method,
                emit_package,
                proto_path,
                compile_well_known_types,
                root_crate_name,
            ),
            (true, false) => generate_client_streaming(
                service,
                method,
                emit_package,
                proto_path,
                compile_well_known_types,
                root_crate_name,
            ),
            (true, true) => generate_streaming(
                service,
                method,
                emit_package,
                proto_path,
                compile_well_known_types,
                root_crate_name,
            ),
        };

        stream.extend(method);
    }

    stream
}

fn generate_unary<T: Service>(
    service: &T,
    method: &T::Method,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let codec_name = syn::parse_str::<syn::Path>(method.codec_path()).unwrap();
    let ident = format_ident!("{}", method.name());
    let (request, response) = method.request_response_name(proto_path, compile_well_known_types);
    let service_name = format_service_name(service, emit_package);
    let path = format_method_path(service, method, emit_package);
    let method_name = method.identifier();

    quote! {
        pub async fn #ident(
            &self,
            request: impl #root_crate_name::IntoRequest<#request>,
        ) -> std::result::Result<#root_crate_name::Response<#response>, #root_crate_name::Status> {
            use #root_crate_name::codegen::ExtensionsMut as _;

            let codec = #codec_name::default();
            let path = #root_crate_name::codegen::http::uri::PathAndQuery::from_static(#path);
            let mut req = request.into_request();
            req.extensions_mut().insert(#root_crate_name::GrpcMethod::new(#service_name, #method_name));
            self.inner.unary(req, path, codec).await
        }
    }
}

fn generate_server_streaming<T: Service>(
    service: &T,
    method: &T::Method,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let codec_name = syn::parse_str::<syn::Path>(method.codec_path()).unwrap();
    let ident = format_ident!("{}", method.name());
    let (request, response) = method.request_response_name(proto_path, compile_well_known_types);
    let service_name = format_service_name(service, emit_package);
    let path = format_method_path(service, method, emit_package);
    let method_name = method.identifier();

    quote! {
        pub async fn #ident(
            &self,
            request: impl #root_crate_name::IntoRequest<#request>,
        ) -> std::result::Result<#root_crate_name::Response<#root_crate_name::codec::Streaming<#response>>, #root_crate_name::Status> {
            use #root_crate_name::codegen::ExtensionsMut as _;

            let codec = #codec_name::default();
            let path = #root_crate_name::codegen::http::uri::PathAndQuery::from_static(#path);
            let mut req = request.into_request();
            req.extensions_mut().insert(#root_crate_name::GrpcMethod::new(#service_name, #method_name));
            self.inner.server_streaming(req, path, codec).await
        }
    }
}

fn generate_client_streaming<T: Service>(
    service: &T,
    method: &T::Method,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let codec_name = syn::parse_str::<syn::Path>(method.codec_path()).unwrap();
    let ident = format_ident!("{}", method.name());
    let (request, response) = method.request_response_name(proto_path, compile_well_known_types);
    let service_name = format_service_name(service, emit_package);
    let path = format_method_path(service, method, emit_package);
    let method_name = method.identifier();

    quote! {
        pub async fn #ident(
            &self,
            request: impl #root_crate_name::IntoStreamingRequest<Message = #request>
        ) -> std::result::Result<#root_crate_name::Response<#response>, #root_crate_name::Status> {
            use #root_crate_name::codegen::ExtensionsMut as _;

            let codec = #codec_name::default();
            let path = #root_crate_name::codegen::http::uri::PathAndQuery::from_static(#path);
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(#root_crate_name::GrpcMethod::new(#service_name, #method_name));
            self.inner.client_streaming(req, path, codec).await
        }
    }
}

fn generate_streaming<T: Service>(
    service: &T,
    method: &T::Method,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let codec_name = syn::parse_str::<syn::Path>(method.codec_path()).unwrap();
    let ident = format_ident!("{}", method.name());
    let (request, response) = method.request_response_name(proto_path, compile_well_known_types);
    let service_name = format_service_name(service, emit_package);
    let path = format_method_path(service, method, emit_package);
    let method_name = method.identifier();

    quote! {
        pub async fn #ident(
            &self,
            request: impl #root_crate_name::IntoStreamingRequest<Message = #request>
        ) -> std::result::Result<#root_crate_name::Response<#root_crate_name::codec::Streaming<#response>>, #root_crate_name::Status> {
            use #root_crate_name::codegen::ExtensionsMut as _;

            let codec = #codec_name::default();
            let path = #root_crate_name::codegen::http::uri::PathAndQuery::from_static(#path);
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(#root_crate_name::GrpcMethod::new(#service_name,#method_name));
            self.inner.streaming(req, path, codec).await
        }
    }
}
