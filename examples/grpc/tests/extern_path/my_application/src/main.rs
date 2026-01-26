pub mod pb {
    #![allow(clippy::pedantic, clippy::restriction, clippy::nursery)]

    rama::http::grpc::include_proto!("my_application");
}

use uuid::DoSomething;

fn main() {
    // verify that extern_path to replace proto's with impl's from other crates works.
    let message = pb::MyMessage {
        message_id: Some(::uuid::Uuid {
            uuid_str: "".to_owned(),
        }),
        some_payload: "".to_owned(),
    };
    dbg!(message.message_id.unwrap().do_it());
}

#[cfg(test)]
#[test]
fn service_types_have_extern_types() {
    // verify that extern_path to replace proto's with impl's from other crates works.
    let message = pb::MyMessage {
        message_id: Some(::uuid::Uuid {
            uuid_str: "not really a uuid".to_owned(),
        }),
        some_payload: "payload".to_owned(),
    };
    assert_eq!(message.message_id.unwrap().do_it(), "Done");
}
