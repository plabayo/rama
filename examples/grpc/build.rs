use std::{env, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    rama::http::grpc::build::protobuf::configure()
        .with_file_descriptor_set_path(out_dir.join("helloworld_descriptor.bin"))
        .compile_protos(&["proto/helloworld/helloworld.proto"], &["proto"])
        .unwrap();

    rama::http::grpc::build::protobuf::compile_protos("proto/echo/echo.proto").unwrap();

    rama::http::grpc::build::protobuf::configure()
        .with_build_server(false)
        .compile_protos(
            &["proto/googleapis/google/pubsub/v1/pubsub.proto"],
            &["proto/googleapis"],
        )
        .unwrap();
}
