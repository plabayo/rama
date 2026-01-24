use std::{env, path::PathBuf};

fn main() {
    build_examples();
    build_tests();

    println!("cargo::rerun-if-changed=proto");
}

fn build_examples() {
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

fn build_tests() {
    build_tests_compile();
    build_tests_compression();
    build_tests_deprecated_methods();
    build_tests_disable_comments();
    build_tests_wellknown();
    build_tests_wellknown_compiled();
    build_tests_web();
    build_tests_integration();
}

fn build_tests_compile() {
    rama::http::grpc::build::protobuf::compile_protos("proto/tests/compile/result.proto").unwrap();
    rama::http::grpc::build::protobuf::compile_protos("proto/tests/compile/service.proto").unwrap();
    rama::http::grpc::build::protobuf::compile_protos("proto/tests/compile/stream.proto").unwrap();
    rama::http::grpc::build::protobuf::compile_protos("proto/tests/compile/same_name.proto")
        .unwrap();
    rama::http::grpc::build::protobuf::compile_protos(
        "proto/tests/compile/ambiguous_methods.proto",
    )
    .unwrap();
    rama::http::grpc::build::protobuf::compile_protos("proto/tests/compile/includer.proto")
        .unwrap();
    rama::http::grpc::build::protobuf::configure()
        .with_extern_path(".root_crate_path.Animal", "crate::Animal")
        .compile_protos(&["proto/tests/compile/root_crate_path.proto"], &["."])
        .unwrap();
    rama::http::grpc::build::protobuf::configure()
        .with_skip_debug(["skip_debug.Test"])
        .with_skip_debug(["skip_debug.Output"])
        .with_build_client(true)
        .with_build_server(true)
        .compile_protos(&["proto/tests/compile/skip_debug.proto"], &["proto"])
        .unwrap();
}

fn build_tests_compression() {
    rama::http::grpc::build::protobuf::compile_protos(
        "proto/tests/compression/compression_test.proto",
    )
    .unwrap();
}

fn build_tests_deprecated_methods() {
    rama::http::grpc::build::protobuf::compile_protos(
        "proto/tests/deprecated_methods/deprecated_test.proto",
    )
    .unwrap();
}

fn build_tests_disable_comments() {
    rama::http::grpc::build::protobuf::configure()
        .with_disable_comments(["disable_comments.Service1"])
        .with_disable_comments(["disable_comments.Service1.Rpc1"])
        .with_build_client(true)
        .with_build_server(true)
        .compile_protos(
            &["proto/tests/disable_comments/disable_comments.proto"],
            &["proto/tests/disable_comments/disable_comments"],
        )
        .unwrap();
}

fn build_tests_wellknown() {
    rama::http::grpc::build::protobuf::compile_protos("proto/tests/wellknown/wellknown.proto")
        .unwrap();
}

fn build_tests_wellknown_compiled() {
    rama::http::grpc::build::protobuf::configure()
        .with_extern_path(".google.protobuf.Empty", "()")
        .with_compile_well_known_types(true)
        .compile_protos(
            &[
                "proto/tests/wellknown_compiled/google.proto",
                "proto/tests/wellknown_compiled/wellknown_compiled.proto",
            ],
            &["proto"],
        )
        .unwrap();
}

fn build_tests_web() {
    let protos = &["proto/tests/web/web.proto"];

    rama::http::grpc::build::protobuf::configure()
        .compile_protos(protos, &["proto/tests/web"])
        .unwrap();
}

fn build_tests_integration() {
    rama::http::grpc::build::protobuf::compile_protos("proto/tests/integration/test.proto")
        .unwrap();
    rama::http::grpc::build::protobuf::compile_protos("proto/tests/integration/stream.proto")
        .unwrap();
}
