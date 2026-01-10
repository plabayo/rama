pub mod r#gen {
    pub mod google {
        pub mod protobuf {
            #![allow(clippy::pedantic, clippy::restriction, clippy::style, clippy::nursery)]
            rama::http::grpc::include_proto!("google.protobuf");
        }
    }

    pub mod test {
        rama::http::grpc::include_proto!("wellknown_compiled");
    }
}

pub fn grok() {
    let _any = self::r#gen::google::protobuf::Any {
        type_url: "foo".to_owned(),
        value: Vec::new(),
    };
}
