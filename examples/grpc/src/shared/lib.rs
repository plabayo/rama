//! shared by all Grpc examples + tests for core logic

pub mod hello_world {
    rama::http::grpc::include_proto!("helloworld");
}
