#![expect(
    clippy::unwrap_used,
    reason = "build script: panicking on codegen failure aborts the build, which is the desired behavior"
)]

fn main() {
    rama::http::grpc::build::protobuf::configure()
        .compile_protos(&["uuid/uuid.proto"], &["../proto/"])
        .unwrap();
}
