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

typos:
	typos -w

doc:
	RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc --all-features --no-deps

doc-open:
	RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc --all-features --no-deps --open

hack:
	cargo hack check --each-feature --no-dev-deps --workspace

test:
	cargo test --all-features

qa: lint check clippy doc hack test

rama +ARGS:
    cargo run -p rama-cli -- {{ARGS}}

docker-build:
    docker build -t rama:latest -f Dockerfile .

example NAME:
		cargo run -p rama --example {{NAME}}
