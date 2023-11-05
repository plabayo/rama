fmt:
	cargo fmt --all

sort:
	cargo sort --workspace --grouped

lint: fmt sort

check:
	cargo check --all --all-targets --all-features

clippy:
	cargo clippy --all --all-targets --all-features

clippy-fix:
	cargo clippy --fix

doc:
	RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc --all-features --no-deps

hack:
	cargo hack check --each-feature --no-dev-deps --workspace

test:
	cargo test --all-features

qa: lint check clippy doc hack test

rama:
    FULL_BACKTRACE=1 cargo run -p rama --bin rama

docker-build:
    docker build -t rama:latest -f Dockerfile .

example-tcp-hello:
		cargo run -p rama --example tokio_tcp_hello

example-tcp-echo:
		cargo run -p rama --example tokio_tcp_echo_server
