//! Procedural macros for rama's grpc support.
//!
//! Do not use this crate directly, use the macros re-exported by `rama-grpc`
//! (or the `rama` crate) instead.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod service;

#[cfg(test)]
mod tests;

/// Define a gRPC service inline, without a `.proto` file or a build script.
///
/// This generates the same client and server stubs as the `.proto` driven codegen does,
/// but from a definition written directly in Rust, using the message types you already have,
/// serialized by the codec of your choice.
///
/// A service `Echo` in package `rama.examples.echo.v1` defines the routes
/// `/rama.examples.echo.v1.Echo/<Method>`, and generates an `echo_client` module with an
/// `EchoClient`, together with an `echo_server` module containing an `Echo` trait to
/// implement and an `EchoServer` to serve it.
///
/// The `grpc_json_echo` example of the rama repository defines, serves and calls a service
/// this way.
///
/// # Syntax
///
/// The macro takes any number of settings, followed by any number of services:
///
/// - `package = "<name>";`: the gRPC package, used as the first part of every route (required)
/// - `codec = <path>;`: the codec used by services which do not define one themselves
/// - `client = <bool>;`: generate the client stubs, `true` by default
/// - `server = <bool>;`: generate the server stubs, `true` by default
///
/// A service is defined as `service <Name> { ... }`, containing an optional
/// `codec = <path>;` used by its methods, and a method per RPC, written as
/// `rpc <Name>(<request type>) -> <response type>;`.
///
/// Prefix either type with `stream` to make that side of the RPC streaming.
/// Doc comments on a service or method end up on the generated items,
/// `#[deprecated]` on a method marks the generated methods as deprecated,
/// and `#[codec(<path>)]` on a method overrules the codec of its service.
///
/// # Paths
///
/// The generated stubs live in modules of their own, so every path you write is resolved
/// as if it were written in the module which invokes this macro: `EchoRequest` refers to
/// the type next to the macro, or to whatever you imported under that name.
///
/// Paths which start with `crate` or `::` are used as-is, which is how you refer to
/// types that are not in scope, e.g. `::std::string::String`.
#[proc_macro]
pub fn define_service(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    match syn::parse::<service::ServiceDefinitions>(input)
        .and_then(service::ServiceDefinitions::generate)
    {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}
