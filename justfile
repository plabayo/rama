fmt:
	cargo fmt --all

sort:
	cargo sort --workspace --grouped

lint: fmt sort

check:
	cargo check --workspace --all-targets --all-features

clippy:
	cargo clippy --workspace --all-targets --all-features

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
	cargo test --all-features --workspace

test-ignored:
	cargo test --features=cli,telemetry,compression,rustls --workspace -- --ignored

qa: lint check clippy doc test

qa-full: lint check clippy doc hack test test-ignored fuzz-60s

upgrades:
    cargo upgrades

watch-docs:
	cargo watch -x doc

watch-check:
	cargo watch -x check -x test

rama +ARGS:
    cargo run -p rama-cli -- {{ARGS}}

rama-fp *ARGS:
	cargo run -p rama-fp -- {{ARGS}}

watch-rama-fp *ARGS:
	RUST_LOG=debug cargo watch -x 'run -p rama-fp -- {{ARGS}}'

docker-build-rama-fp:
	docker build -f rama-fp/infra/Dockerfile -t glendc/rama-fp:latest .

docker-push-rama-fp: docker-build-rama-fp
	docker push glendc/rama-fp:latest

browserstack-rama-fp:
	cd rama-fp/browserstack && \
		(pip install -r requirements.txt || true) && \
		python main.py

example NAME:
		cargo run -p rama --example {{NAME}}

self-signed-certs CRT KEY:
    openssl req -new -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out {{CRT}} -keyout {{KEY}}

report-code-lines:
	find . -type f -name '*.rs' -exec cat {} + \
		| grep -v target | tr -d ' ' | grep -v '^$' | grep -v '^//' \
		| wc -l

fuzz:
	cargo +nightly fuzz run ua_parse -- -max_len=131072

fuzz-60s:
	cargo +nightly fuzz run ua_parse -- -max_len=131072 -max_total_time=60

bench:
	cargo bench

vet:
	cargo vet

miri:
	cargo +nightly miri test

detect-unused-deps:
	cargo machete --skip-target-dir

detect-biggest-fn:
	cargo bloat --package rama-cli --release -n 10

detect-biggest-crates:
	cargo bloat --package rama-cli --release --crates

mdbook-serve:
	cd docs/book && mdbook serve

rama-cli-release-build TARGET:
	cargo build -p rama-cli --bin rama --release --target {{TARGET}}
	VERSION="$(cat Cargo.toml | grep -E '^version = "' | cut -d\" -f2)" && \
		cd target/{{TARGET}}/release && \
		tar -czf rama-cli-${VERSION}-{{TARGET}}.tar.gz rama && \
		shasum -a 256 rama-cli-${VERSION}-{{TARGET}}.tar.gz > rama-cli-${VERSION}-{{TARGET}}.tar.gz.sha256

rama-cli-release-build-all:
	just rama-cli-release-build x86_64-apple-darwin
	just rama-cli-release-build aarch64-apple-darwin
