set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

export RUSTFLAGS := "-D warnings"
export RUSTDOCFLAGS := "-D rustdoc::broken-intra-doc-links"
export RUST_LOG := "debug"

fmt *ARGS:
	cargo fmt --all {{ARGS}}

fmt-crate CRATE *ARGS:
	cargo fmt --all -p {{CRATE}} {{ARGS}}

sort:
	@cargo install cargo-sort
	cargo sort --workspace --grouped

lint: fmt sort

check:
	cargo check --workspace --all-targets --all-features

check-crate CRATE:
	cargo check -p {{CRATE}} --all-targets --all-features

check-links:
    lychee .

clippy:
	cargo clippy --workspace --all-targets --all-features

clippy-crate CRATE:
	cargo clippy -p {{CRATE}} --all-targets --all-features

clippy-fix *ARGS:
	cargo clippy --workspace --all-targets --all-features --fix {{ARGS}}

clippy-fix-crate CRATE *ARGS:
	cargo clippy -p {{CRATE}} --all-targets --all-features --fix {{ARGS}}

typos:
	typos -w

extra-checks:
	{{justfile_directory()}}/scripts/extra-checks.sh

doc:
	cargo doc --all-features --no-deps

doc-crate CRATE:
	cargo doc --all-features --no-deps -p {{CRATE}}

doc-open:
	cargo doc --all-features --no-deps --open

hack:
	@cargo install cargo-hack
	cargo hack check --each-feature --no-dev-deps --workspace

test *ARGS:
	cargo test --all-features --workspace {{ARGS}}

test-crate CRATE *ARGS:
	cargo test --all-features -p {{CRATE}} {{ARGS}}

test-spec-h2 *ARGS:
    bash rama-http-core/ci/h2spec.sh {{ARGS}}

test-spec: test-spec-h2

test-ignored:
	cargo test --features=cli,http-full,proxy-full,rustls --workspace -- --ignored

qq: lint check clippy doc extra-checks

qa: qq test

qa-crate CRATE:
    just check-crate {{CRATE}}
    just clippy-crate {{CRATE}}
    just doc-crate {{CRATE}}
    just test-crate {{CRATE}}

qa-full: qa hack test-ignored fuzz-60s check-links

clean:
    cargo clean

upgrades:
    @cargo install cargo-upgrades
    cargo upgrades

watch-docs:
	@cargo install cargo-watch
	cargo watch -x doc

watch-check:
	@cargo install cargo-watch
	cargo watch -x check -x test

rama +ARGS:
    cargo run -p rama-cli -- {{ARGS}}

rama-fp *ARGS:
	cargo run -p rama-fp -- {{ARGS}}

watch-rama-fp *ARGS:
	@cargo install cargo-watch
	cargo watch -x 'run -p rama-fp -- {{ARGS}}'

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

fuzz-http-headers-x-robots-tag:
	cargo +nightly fuzz run http_header_x_robots_tag -- -max_len=131072

fuzz-http-headers-x-robots-tag-60s:
	cargo +nightly fuzz run http_header_x_robots_tag -- -max_len=131072 -max_total_time=60

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

fuzz-60s: fuzz-ua-60s fuzz-h2-60s fuzz-http-headers-x-robots-tag-60s

fuzz-full: fuzz-60s fuzz-h2-main

bench:
	cargo bench --features=full

vet:
	cargo vet

miri:
	cargo +nightly miri test

detect-unused-deps:
	@cargo install cargo-machete
	cargo machete --skip-target-dir

detect-biggest-fn:
	cargo bloat --package rama-cli --release -n 10

detect-biggest-crates:
	cargo bloat --package rama-cli --release --crates

mdbook-serve:
	cd docs/book && mdbook serve

publish *ARGS:
    cargo publish --workspace {{ARGS}}

[working-directory: './rama-cli/manifests/winget/Plabayo/Rama/Preview']
@submit-rama-cli-winget-preview:
    wingetcreate submit -p 'Plabayo.Rama.Preview version bump' .

update-deps:
    cargo upgrades
    cargo update
