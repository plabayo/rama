#[rustversion::nightly]
fn main() {
    println!("cargo:rustc-cfg=nightly_error_messages");
    generate_example_protos();
}

#[rustversion::not(nightly)]
fn main() {
    generate_example_protos();
}

/// Compile the RPC examples' `.proto` files into Rust stubs.
///
/// Each RPC flavour writes into its own `OUT_DIR/<flavour>/` subdirectory so the same
/// package name never collides between flavours (prost-build names output files by
/// package). Examples and their integration tests `include!` the generated file from the
/// matching subdirectory. Only runs for the flavours whose feature is enabled, so the
/// common build stays protoc-free.
fn generate_example_protos() {
    #[cfg(feature = "_ttrpc-example")]
    {
        #[expect(
            clippy::expect_used,
            reason = "build script: abort the build if the example protos cannot be compiled"
        )]
        compile_ttrpc_example_protos().expect("compile ttrpc example protos");
    }

    #[cfg(feature = "_grpc-example")]
    {
        #[expect(
            clippy::expect_used,
            reason = "build script: abort the build if the example protos cannot be compiled"
        )]
        compile_grpc_example_protos().expect("compile grpc example protos");
    }
}

#[cfg(feature = "_ttrpc-example")]
fn compile_ttrpc_example_protos() -> std::io::Result<()> {
    let out = example_proto_out_dir("ttrpc")?;
    rama_ttrpc_build::configure()
        .with_out_dir(out)
        .compile_protos(&["examples/proto/greeter.proto"], &["examples/proto"])
}

#[cfg(feature = "_grpc-example")]
fn compile_grpc_example_protos() -> std::io::Result<()> {
    let out = example_proto_out_dir("grpc")?;
    rama_grpc_build::protobuf::configure()
        .with_out_dir(out)
        .compile_protos(&["examples/proto/greeter.proto"], &["examples/proto"])
}

/// `OUT_DIR/<flavour>/`, created if missing.
#[cfg(any(feature = "_ttrpc-example", feature = "_grpc-example"))]
fn example_proto_out_dir(flavour: &str) -> std::io::Result<std::path::PathBuf> {
    let out_dir = std::env::var_os("OUT_DIR")
        .ok_or_else(|| std::io::Error::other("OUT_DIR is not set by cargo"))?;
    let dir = std::path::PathBuf::from(out_dir).join(flavour);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
