fn main() {
    #[cfg(feature = "protobuf")]
    {
        rama_grpc_build::protobuf::compile_protos("proto/health.proto").unwrap();
        println!("cargo::rerun-if-changed=proto");
    }

    #[cfg(feature = "opentelemetry")]
    {
        // Proto files vendored from https://github.com/open-telemetry/opentelemetry-proto
        // tag: v1.5.0, commit: 2bd940b2b77c1ab57c27166af21384906da7bb2b
        let mut config = prost_build::Config::new();
        config.disable_comments(["."]);

        // Use vendored protoc to avoid requiring system protoc installation
        if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
            config.protoc_executable(path);
        }

        config
            .compile_protos(
                &[
                    "proto/opentelemetry/proto/collector/trace/v1/trace_service.proto",
                    "proto/opentelemetry/proto/collector/metrics/v1/metrics_service.proto",
                ],
                &["proto/"],
            )
            .unwrap();
    }
}
