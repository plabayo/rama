//! Test entry-point module: declares per-topic submodules so each topic
//! lives in its own file rather than one ~1300-line `tests.rs`.

mod common;

mod backpressure;
mod decision;
mod flow_meta;
mod leak;
mod lifecycle;
mod safety;
mod tcp;
mod udp;
