fn main() {
    #[cfg(feature = "protobuf")]
    {
        rama_grpc_build::protobuf::compile_protos("proto/health.proto").unwrap();
        println!("cargo::rerun-if-changed=proto");
    }
}
