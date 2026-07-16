fn main() -> std::io::Result<()> {
    generate_example_protos()
}

/// Compile the RPC examples' `.proto` files into Rust stubs.
///
/// Each RPC flavour writes into its own `OUT_DIR/<flavour>/` subdirectory so the same
/// package name never collides between flavours (prost-build names output files by
/// package). Examples and their integration tests `include!` the generated file from the
/// matching subdirectory. Only runs when the matching feature is enabled, so builds that
/// don't touch an RPC flavour stay protoc-free.
fn generate_example_protos() -> std::io::Result<()> {
    #[cfg(feature = "ttrpc")]
    compile_ttrpc_example_protos()?;

    Ok(())
}

#[cfg(feature = "ttrpc")]
fn compile_ttrpc_example_protos() -> std::io::Result<()> {
    let out = example_proto_out_dir("ttrpc")?;
    rama_ttrpc_build::configure()
        .with_out_dir(out)
        .compile_protos(&["proto/greeter.proto"], &["proto"])
}

/// `OUT_DIR/<flavour>/`, created if missing.
#[cfg(feature = "ttrpc")]
fn example_proto_out_dir(flavour: &str) -> std::io::Result<std::path::PathBuf> {
    let out_dir = std::env::var_os("OUT_DIR")
        .ok_or_else(|| std::io::Error::other("OUT_DIR is not set by cargo"))?;
    let dir = std::path::PathBuf::from(out_dir).join(flavour);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
