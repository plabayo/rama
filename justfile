fmt:
	cargo fmt --all

sort:
	cargo sort --workspace --grouped

lint: fmt sort

check:
	cargo check --workspace --all-targets --all-features

clippy:
	cargo clippy --workspace --all-targets --all-features

clippy-fix *ARGS:
	cargo clippy --workspace --all-targets --all-features --fix {{ARGS}}

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

test-spec-h2 *ARGS:
    bash rama-http-core/ci/h2spec.sh {{ARGS}}

test-spec: test-spec-h2

test-ignored:
	cargo test --features=cli,telemetry,compression,http-full,proxy-full,tcp,rustls --workspace -- --ignored

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

fuzz-ua:
	cargo +nightly fuzz run ua_parse -- -max_len=131072

fuzz-ua-60s:
	cargo +nightly fuzz run ua_parse -- -max_len=131072 -max_total_time=60

fuzz-h2-main:
    # cargo install honggfuzz
    cd rama-http-core/tests/h2-fuzz && \
        HFUZZ_RUN_ARGS="-t 1" cargo hfuzz run h2-fuzz

fuzz-h2-client:
	cargo +nightly fuzz run h2_client

fuzz-h2-hpack:
	cargo +nightly fuzz run h2_hpack

fuzz-h2-e2e:
	cargo +nightly fuzz run h2_e2e

fuzz-h2-60s:
	cargo +nightly fuzz run h2_client -- -max_total_time=60
	cargo +nightly fuzz run h2_hpack -- -max_total_time=60
	cargo +nightly fuzz run h2_e2e -- -max_total_time=60

fuzz-60s: fuzz-ua-60s fuzz-h2-60s

fuzz-full: fuzz-60s fuzz-h2-main

bench:
	cargo bench --features=full

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

rama-cli-build:
	rama-cli/scripts/build.sh

publish:
    cargo publish -p rama-error
    cargo publish -p rama-macros
    cargo publish -p rama-utils
    cargo publish -p rama-core
    cargo publish -p rama-http-types
    cargo publish -p rama-net
    cargo publish -p rama-ua
    cargo publish -p rama-dns
    cargo publish -p rama-tcp
    cargo publish -p rama-tls
    cargo publish -p rama-http-core
    cargo publish -p rama-http-backend
    cargo publish -p rama-http
    cargo publish -p rama-haproxy
    cargo publish -p rama-proxy
    cargo publish -p rama-udp
    cargo publish -p rama-socks5
    cargo publish -p rama
    cargo publish -p rama-cli
