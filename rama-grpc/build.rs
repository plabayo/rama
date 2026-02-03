fn main() {
    #[cfg(feature = "protobuf")]
    {
        rama_grpc_build::protobuf::compile_protos("proto/health.proto").unwrap();
        println!("cargo::rerun-if-changed=proto");
    }

    #[cfg(feature = "opentelemetry")]
    {
        println!("cargo::rerun-if-env-changed=OTEL_EXPORTER_OTLP_ENDPOINT");
        println!("cargo::rerun-if-env-changed=OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
        println!("cargo::rerun-if-env-changed=OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
    }
}
