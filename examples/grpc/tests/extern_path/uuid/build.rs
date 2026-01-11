fn main() {
    rama::http::grpc::build::protobuf::configure()
        .compile_protos(&["uuid/uuid.proto"], &["../proto/"])
        .unwrap();
}
