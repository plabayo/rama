use std::collections::HashSet;

use super::{Attributes, Method, Service};
use crate::{
    format_method_name, format_method_path, format_service_name, generate_doc_comment,
    generate_doc_comments, naive_snake_case,
};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{Ident, Lit, LitStr};

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_internal<T: Service>(
    service: &T,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    attributes: &Attributes,
    disable_comments: &HashSet<String>,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let methods = generate_methods(
        service,
        emit_package,
        proto_path,
        compile_well_known_types,
        root_crate_name,
    );

    let server_service = quote::format_ident!("{}Server", service.name());
    let server_trait = quote::format_ident!("{}", service.name());
    let server_mod = quote::format_ident!("{}_server", naive_snake_case(service.name()));
    let trait_attributes = attributes.for_trait(service.name());
    let generated_trait = generate_trait(
        service,
        emit_package,
        proto_path,
        compile_well_known_types,
        &server_trait,
        disable_comments,
        trait_attributes.as_slice(),
        root_crate_name,
    );
    let package = if emit_package { service.package() } else { "" };
    // Transport based implementations
    let service_name = format_service_name(service, emit_package);

    let service_doc = if disable_comments.contains(&service_name) {
        TokenStream::new()
    } else {
        generate_doc_comments(service.comment())
    };

    let named = generate_named(&server_service, &service_name, root_crate_name);
    let mod_attributes = attributes.for_mod(package);
    let struct_attributes = attributes.for_struct(&service_name);

    let configure_compression_methods = quote! {
        #root_crate_name::codegen::generate_set_and_with! {
            /// Enable decompressing requests with the given encoding.
            pub fn accept_compressed(mut self, encoding: #root_crate_name::codec::CompressionEncoding) -> Self {
                self.accept_compression_encodings.enable(encoding);
                self
            }
        }

        #root_crate_name::codegen::generate_set_and_with! {
            /// Compress responses with the given encoding, if the client supports it.
            pub fn send_compressed(mut self, encoding: #root_crate_name::codec::CompressionEncoding) -> Self {
                self.send_compression_encodings.enable(encoding);
                self
            }
        }
    };

    let configure_max_message_size_methods = quote! {
        #root_crate_name::codegen::generate_set_and_with! {
            /// Limits the maximum size of a decoded message.
            ///
            /// Default: `4MB`
            pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
                self.max_decoding_message_size = Some(limit);
                self
            }
        }

        #root_crate_name::codegen::generate_set_and_with! {
            /// Limits the maximum size of an encoded message.
            ///
            /// Default: `usize::MAX`
            pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
                self.max_encoding_message_size = Some(limit);
                self
            }
        }
    };

    quote! {
        /// Generated server implementations.
        #(#mod_attributes)*
        pub mod #server_mod {
            #![allow(
                unused_variables,
                dead_code,
                missing_docs,
                clippy::all,
                clippy::pedantic,
                clippy::restriction,
                clippy::nursery,
            )]

            #generated_trait

            #service_doc
            #(#struct_attributes)*
            #[derive(Debug)]
            pub struct #server_service<T> {
                inner: std::sync::Arc<T>,
                accept_compression_encodings: #root_crate_name::codec::EnabledCompressionEncodings,
                send_compression_encodings: #root_crate_name::codec::EnabledCompressionEncodings,
                max_decoding_message_size: Option<usize>,
                max_encoding_message_size: Option<usize>,
            }

            impl<T> #server_service<T> {
                pub fn new(inner: T) -> Self {
                    Self::from_arc(std::sync::Arc::new(inner))
                }

                pub fn from_arc(inner: std::sync::Arc<T>) -> Self {
                    Self {
                        inner,
                        accept_compression_encodings: Default::default(),
                        send_compression_encodings: Default::default(),
                        max_decoding_message_size: None,
                        max_encoding_message_size: None,
                    }
                }

                #configure_compression_methods

                #configure_max_message_size_methods
            }

            impl<T, B> #root_crate_name::codegen::Service<#root_crate_name::codegen::http::Request<B>> for #server_service<T>
                where
                    T: #server_trait,
                    B: #root_crate_name::codegen::http::StreamingBody<
                        Error: Into<#root_crate_name::codegen::BoxError> + Send + 'static
                    > + Send + Sync + 'static,
            {
                type Output = #root_crate_name::codegen::http::Response;
                type Error = std::convert::Infallible;

                async fn serve(&self, req: #root_crate_name::codegen::http::Request<B>)
                    -> std::result::Result<Self::Output, Self::Error> {
                    match req.uri().path() {
                        #methods

                        _ => {
                            let mut response = #root_crate_name::codegen::http::Response::new(
                                #root_crate_name::codegen::http::Body::default()
                            );
                            let headers = response.headers_mut();
                            headers.insert(
                                #root_crate_name::Status::GRPC_STATUS,
                                (#root_crate_name::Code::Unimplemented as i32).into(),
                            );
                            headers.insert(
                                #root_crate_name::codegen::http::header::CONTENT_TYPE,
                                #root_crate_name::metadata::GRPC_CONTENT_TYPE,
                            );
                            Ok(response)
                        },
                    }
                }
            }

            impl<T> Clone for #server_service<T> {
                fn clone(&self) -> Self {
                    let inner = self.inner.clone();
                    Self {
                        inner,
                        accept_compression_encodings: self.accept_compression_encodings,
                        send_compression_encodings: self.send_compression_encodings,
                        max_decoding_message_size: self.max_decoding_message_size,
                        max_encoding_message_size: self.max_encoding_message_size,
                    }
                }
            }

            #named
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_trait<T: Service>(
    service: &T,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    server_trait: &Ident,
    disable_comments: &HashSet<String>,
    trait_attributes: &[syn::Attribute],
    root_crate_name: &TokenStream,
) -> TokenStream {
    let methods = generate_trait_methods(
        service,
        emit_package,
        proto_path,
        compile_well_known_types,
        disable_comments,
        root_crate_name,
    );
    let trait_doc = generate_doc_comment(format!(
        " Generated trait containing gRPC methods that should be implemented for use with {}Server.",
        service.name()
    ));

    quote! {
        #trait_doc
        #(#trait_attributes)*
        pub trait #server_trait : Send + Sync + 'static {
            #methods
        }
    }
}

fn generate_trait_methods<T: Service>(
    service: &T,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    disable_comments: &HashSet<String>,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let mut stream = TokenStream::new();

    for method in service.methods() {
        let name = quote::format_ident!("{}", method.name());

        let (req_message, res_message) =
            method.request_response_name(proto_path, compile_well_known_types);

        let method_doc =
            if disable_comments.contains(&format_method_name(service, method, emit_package)) {
                TokenStream::new()
            } else {
                generate_doc_comments(method.comment())
            };

        let method = match (method.client_streaming(), method.server_streaming()) {
            (false, false) => {
                quote! {
                    #method_doc
                    fn #name(&self, request: #root_crate_name::Request<#req_message>)
                        -> impl Future<
                            Output = std::result::Result<#root_crate_name::Response<#res_message>, #root_crate_name::Status>,
                        > + Send + '_;
                }
            }
            (true, false) => {
                quote! {
                    #method_doc
                    fn #name(&self, request: #root_crate_name::Request<#root_crate_name::Streaming<#req_message>>)
                        -> impl Future<
                            Output = std::result::Result<#root_crate_name::Response<#res_message>, #root_crate_name::Status>,
                        > + Send + '_;
                }
            }
            (false, true) => {
                // TOOD: in a future Rust version (edition 2027???)
                // we might be able to get away here without
                // having to specify a stream type here. That would require however
                // that we can point to a type of a impl return type of a trait...

                let stream = quote::format_ident!("{}Stream", method.identifier());
                let stream_doc = generate_doc_comment(format!(
                    " Server streaming response type for the {} method.",
                    method.identifier()
                ));

                quote! {
                    #stream_doc
                    type #stream: #root_crate_name::codegen::Stream<
                        Item = std::result::Result<#res_message, #root_crate_name::Status>
                        > + Send + Sync + 'static;

                    #method_doc
                    fn #name(&self, request: #root_crate_name::Request<#req_message>)
                        -> impl Future<
                            Output = std::result::Result<#root_crate_name::Response<Self::#stream>, #root_crate_name::Status>,
                        > + Send + '_;
                }
            }
            (true, true) => {
                // TOOD: in a future Rust version (edition 2027???)
                // we might be able to get away here without
                // having to specify a stream type here. That would require however
                // that we can point to a type of a impl return type of a trait...

                let stream = quote::format_ident!("{}Stream", method.identifier());
                let stream_doc = generate_doc_comment(format!(
                    " Server streaming response type for the {} method.",
                    method.identifier()
                ));

                quote! {
                    #stream_doc
                    type #stream: #root_crate_name::codegen::Stream<
                        Item = std::result::Result<#res_message, #root_crate_name::Status>
                    > + Send + Sync + 'static;

                    #method_doc
                    fn #name(&self, request: #root_crate_name::Request<#root_crate_name::Streaming<#req_message>>)
                        -> impl Future<
                            Output = std::result::Result<#root_crate_name::Response<Self::#stream>, #root_crate_name::Status>,
                        > + Send + '_;
                }
            }
        };

        stream.extend(method);
    }

    stream
}

fn generate_named(
    server_service: &syn::Ident,
    service_name: &str,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let service_name = syn::LitStr::new(service_name, proc_macro2::Span::call_site());
    let name_doc = generate_doc_comment(" Generated gRPC service name");

    quote! {
        #name_doc
        pub const SERVICE_NAME: &str = #service_name;

        impl<T> #root_crate_name::server::NamedService for #server_service<T> {
            const NAME: &'static str = SERVICE_NAME;
        }
    }
}

fn generate_methods<T: Service>(
    service: &T,
    emit_package: bool,
    proto_path: &str,
    compile_well_known_types: bool,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let mut stream = TokenStream::new();

    for method in service.methods() {
        let path = format_method_path(service, method, emit_package);
        let method_path = Lit::Str(LitStr::new(&path, Span::call_site()));
        let ident = quote::format_ident!("{}", method.name());
        let server_trait = quote::format_ident!("{}", service.name());

        let method_stream = match (method.client_streaming(), method.server_streaming()) {
            (false, false) => generate_unary(
                method,
                proto_path,
                compile_well_known_types,
                &ident,
                &server_trait,
                root_crate_name,
            ),

            (false, true) => generate_server_streaming(
                method,
                proto_path,
                compile_well_known_types,
                &ident,
                &server_trait,
                root_crate_name,
            ),
            (true, false) => generate_client_streaming(
                method,
                proto_path,
                compile_well_known_types,
                &ident,
                &server_trait,
                root_crate_name,
            ),

            (true, true) => generate_streaming(
                method,
                proto_path,
                compile_well_known_types,
                &ident,
                &server_trait,
                root_crate_name,
            ),
        };

        let method = quote! {
            #method_path => {
                #method_stream
            }
        };
        stream.extend(method);
    }

    stream
}

fn generate_unary<T: Method>(
    method: &T,
    proto_path: &str,
    compile_well_known_types: bool,
    method_ident: &Ident,
    server_trait: &Ident,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let codec_name = syn::parse_str::<syn::Path>(method.codec_path()).unwrap();

    let service_ident = quote::format_ident!("{}Svc", method.identifier());

    let (request, response) = method.request_response_name(proto_path, compile_well_known_types);

    quote! {
        #[allow(non_camel_case_types)]
        struct #service_ident<T: #server_trait >(pub std::sync::Arc<T>);

        impl<T: #server_trait> #root_crate_name::server::UnaryService<#request> for #service_ident<T> {
            type Response = #response;

            async fn serve(&self, request: #root_crate_name::Request<#request>)
                -> std::result::Result<#root_crate_name::Response<Self::Response>, #root_crate_name::Status>
            {
                <T as #server_trait>::#method_ident(self.0.as_ref(), request).await
            }
        }

        let accept_compression_encodings = self.accept_compression_encodings;
        let send_compression_encodings = self.send_compression_encodings;
        let max_decoding_message_size = self.max_decoding_message_size;
        let max_encoding_message_size = self.max_encoding_message_size;
        let inner = self.inner.clone();

        let method = #service_ident(inner);
        let codec = #codec_name::default();

        let mut grpc = #root_crate_name::server::Grpc::new(codec)
            .with_compression_config(accept_compression_encodings, send_compression_encodings)
            .with_max_message_size_config(max_decoding_message_size, max_encoding_message_size);

        Ok(grpc.unary(method, req).await.unwrap_or_else(
            #root_crate_name::server::error::unexpected_error_into_http_response
        ))
    }
}

fn generate_server_streaming<T: Method>(
    method: &T,
    proto_path: &str,
    compile_well_known_types: bool,
    method_ident: &Ident,
    server_trait: &Ident,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let codec_name = syn::parse_str::<syn::Path>(method.codec_path()).unwrap();

    let service_ident = quote::format_ident!("{}Svc", method.identifier());

    let (request, response) = method.request_response_name(proto_path, compile_well_known_types);

    let response_stream = {
        let stream = quote::format_ident!("{}Stream", method.identifier());
        quote!(type ResponseStream = T::#stream)
    };

    quote! {
        #[allow(non_camel_case_types)]
        struct #service_ident<T: #server_trait >(pub std::sync::Arc<T>);

        impl<T: #server_trait> #root_crate_name::server::ServerStreamingService<#request> for #service_ident<T> {
            type Response = #response;
            #response_stream;

            async fn serve(&self, request: #root_crate_name::Request<#request>)
                -> std::result::Result<#root_crate_name::Response<Self::ResponseStream>, #root_crate_name::Status> {
                <T as #server_trait>::#method_ident(self.0.as_ref(), request).await
            }
        }

        let accept_compression_encodings = self.accept_compression_encodings;
        let send_compression_encodings = self.send_compression_encodings;
        let max_decoding_message_size = self.max_decoding_message_size;
        let max_encoding_message_size = self.max_encoding_message_size;
        let inner = self.inner.clone();

        let method = #service_ident(inner);
        let codec = #codec_name::default();

        let mut grpc = #root_crate_name::server::Grpc::new(codec)
            .with_compression_config(accept_compression_encodings, send_compression_encodings)
            .with_max_message_size_config(max_decoding_message_size, max_encoding_message_size);

        Ok(grpc.server_streaming(method, req).await.unwrap_or_else(
            #root_crate_name::server::error::unexpected_error_into_http_response
        ))
    }
}

fn generate_client_streaming<T: Method>(
    method: &T,
    proto_path: &str,
    compile_well_known_types: bool,
    method_ident: &Ident,
    server_trait: &Ident,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let service_ident = quote::format_ident!("{}Svc", method.identifier());

    let (request, response) = method.request_response_name(proto_path, compile_well_known_types);
    let codec_name = syn::parse_str::<syn::Path>(method.codec_path()).unwrap();

    quote! {
        #[allow(non_camel_case_types)]
        struct #service_ident<T: #server_trait >(pub std::sync::Arc<T>);

        impl<T: #server_trait> #root_crate_name::server::ClientStreamingService<#request> for #service_ident<T>
        {
            type Response = #response;

            async fn serve(&self, request: #root_crate_name::Request<#root_crate_name::Streaming<#request>>)
                -> std::result::Result<#root_crate_name::Response<Self::Response>, #root_crate_name::Status> {
                <T as #server_trait>::#method_ident(self.0.as_ref(), request).await
            }
        }

        let accept_compression_encodings = self.accept_compression_encodings;
        let send_compression_encodings = self.send_compression_encodings;
        let max_decoding_message_size = self.max_decoding_message_size;
        let max_encoding_message_size = self.max_encoding_message_size;
        let inner = self.inner.clone();

        let method = #service_ident(inner);
        let codec = #codec_name::default();

        let mut grpc = #root_crate_name::server::Grpc::new(codec)
            .with_compression_config(accept_compression_encodings, send_compression_encodings)
            .with_max_message_size_config(max_decoding_message_size, max_encoding_message_size);

        Ok(grpc.client_streaming(method, req).await.unwrap_or_else(
            #root_crate_name::server::error::unexpected_error_into_http_response
        ))
    }
}

fn generate_streaming<T: Method>(
    method: &T,
    proto_path: &str,
    compile_well_known_types: bool,
    method_ident: &Ident,
    server_trait: &Ident,
    root_crate_name: &TokenStream,
) -> TokenStream {
    let codec_name = syn::parse_str::<syn::Path>(method.codec_path()).unwrap();

    let service_ident = quote::format_ident!("{}Svc", method.identifier());

    let (request, response) = method.request_response_name(proto_path, compile_well_known_types);

    let response_stream = {
        let stream = quote::format_ident!("{}Stream", method.identifier());
        quote!(type ResponseStream = T::#stream)
    };

    quote! {
        #[allow(non_camel_case_types)]
        struct #service_ident<T: #server_trait>(pub std::sync::Arc<T>);

        impl<T: #server_trait> #root_crate_name::server::StreamingService<#request> for #service_ident<T>
        {
            type Response = #response;
            #response_stream;

            async fn serve(&self, request: #root_crate_name::Request<#root_crate_name::Streaming<#request>>)
                -> std::result::Result<#root_crate_name::Response<Self::ResponseStream>, #root_crate_name::Status> {
                <T as #server_trait>::#method_ident(self.0.as_ref(), request).await
            }
        }

        let accept_compression_encodings = self.accept_compression_encodings;
        let send_compression_encodings = self.send_compression_encodings;
        let max_decoding_message_size = self.max_decoding_message_size;
        let max_encoding_message_size = self.max_encoding_message_size;
        let inner = self.inner.clone();

        let method = #service_ident(inner);
        let codec = #codec_name::default();

        let mut grpc = #root_crate_name::server::Grpc::new(codec)
            .with_compression_config(accept_compression_encodings, send_compression_encodings)
            .with_max_message_size_config(max_decoding_message_size, max_encoding_message_size);

        Ok(grpc.streaming(method, req).await.unwrap_or_else(
            #root_crate_name::server::error::unexpected_error_into_http_response
        ))
    }
}
