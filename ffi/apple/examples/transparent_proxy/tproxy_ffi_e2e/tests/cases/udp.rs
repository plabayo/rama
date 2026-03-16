//! UDP ABI smoke coverage.

use serial_test::serial;

use crate::shared::{clients::udp_roundtrip, env::setup_env, types::localhost};

#[tokio::test]
#[serial]
async fn ffi_contract_udp_basic_echo() {
    let env = setup_env().await;
    let response = udp_roundtrip(env.engine, localhost(env.ports.udp), b"udp ffi").await;
    assert_eq!(response, b"UDP FFI");
}
