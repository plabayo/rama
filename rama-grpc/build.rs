fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    #[cfg(feature = "protobuf")]
    {
        rama_grpc_build::protobuf::compile_protos("proto/health.proto").unwrap();
    }

    #[cfg(feature = "opentelemetry")]
    {
        // OTLP proto files vendored from open-telemetry/opentelemetry-proto
        // commit: 3ca54b660a5b307a618c59840b88532b18673869
        rama_grpc_build::protobuf::configure()
            .with_disable_comments(["."])
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
