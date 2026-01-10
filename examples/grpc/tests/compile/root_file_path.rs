#[derive(Clone, PartialEq, ::rama::http::grpc::protobuf::prost::Message)]
#[prost(prost_path = ":: rama :: http :: grpc::protobuf::prost")]
struct Animal {
    #[prost(string, optional, tag = "1")]
    pub name: ::core::option::Option<::rama::http::grpc::protobuf::prost::alloc::string::String>,
}

mod pb {
    rama::http::grpc::include_proto!("root_crate_path");
}

fn main() {}
