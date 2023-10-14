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

test:
	cargo test --all-features

doc:
	RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc --all-features --no-deps

qa: lint check clippy doc test

rama:
    FULL_BACKTRACE=1 cargo run -p rama --bin rama
