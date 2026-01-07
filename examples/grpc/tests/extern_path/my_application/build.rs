fn main() -> Result<(), std::io::Error> {
    rama::http::grpc::build::protobuf::configure()
        .with_build_server(false)
        .with_build_client(true)
        .with_extern_path(".uuid", "::uuid")
        .compile_protos(
            &["service.proto", "uuid.proto"],
            &["../proto/my_application", "../proto/uuid"],
        )?;
    Ok(())
}
