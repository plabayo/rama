/// Include generated ttRPC service items (message types, service traits, client impls).
///
/// You must specify the protobuf package name. This only works if the
/// `rama-ttrpc-build` output directory has been left at its default (the `OUT_DIR`
/// environment variable set by Cargo for build scripts).
///
/// ```rust,ignore
/// mod pb {
///     rama_ttrpc::include_proto!("nri.pkg.api.v1alpha1");
/// }
/// ```
///
/// The argument is a path stem relative to `OUT_DIR`, so a build script that writes into a
/// subdirectory (for example to namespace generated code by RPC flavour and avoid file-name
/// collisions) can be included by prefixing that subdirectory:
///
/// ```rust,ignore
/// mod pb {
///     // reads `OUT_DIR/ttrpc/my.package.rs`
///     rama_ttrpc::include_proto!("ttrpc/my.package");
/// }
/// ```
///
/// If the output directory is elsewhere entirely, use `include!` directly instead:
///
/// ```rust,ignore
/// mod pb {
///     include!("/relative/protobuf/directory/package.rs");
/// }
/// ```
#[macro_export]
macro_rules! include_proto {
    ($package: tt) => {
        include!(concat!(env!("OUT_DIR"), concat!("/", $package, ".rs")));
    };
}
