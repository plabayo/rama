#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::dbg_macro,
    clippy::unreachable,
    clippy::allow_attributes,
    reason = "integration tests: panic-on-error and print-for-output are the standard patterns for harnesses"
)]

mod utils;

mod help;

mod serve_discard;
mod serve_echo;
mod serve_fp;
mod serve_fs;
mod serve_http_test;
mod serve_icap;
mod serve_ip;
mod serve_proxy;
mod serve_stunnel;

mod pac;
mod probe;
mod resolve;
mod send_data;
mod send_feed;
mod send_file;
mod send_json;
