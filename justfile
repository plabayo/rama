set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# `--cfg tokio_unstable` enables Tokio's unstable runtime APIs that
# `dial9-tokio-telemetry` requires. It is benign for crates that do
# not opt into the `dial9` feature; the workspace `.cargo/config.toml`
# carries the same flag for raw `cargo` invocations. We set it via env
# here because justfile's `export RUSTFLAGS` overrides cargo's config.
export RUSTFLAGS := "-D warnings --cfg tokio_unstable"
export RUST_LOG := "debug"

fmt *ARGS:
    cargo fmt --all {{ARGS}}

fmt-crate CRATE *ARGS:
    cargo fmt --all -p {{CRATE}} {{ARGS}}

fmt-check *ARGS:
    cargo fmt --all --check {{ARGS}}

fmt-check-crate CRATE *ARGS:
    cargo fmt --all -p {{CRATE}} --check {{ARGS}}

sort:
    @command -v cargo-sort >/dev/null || cargo install cargo-sort --locked
    cargo sort --workspace --grouped

lint: fmt sort

deny:
    @cargo install cargo-deny
    cargo deny --workspace --all-features check

check:
    cargo check --workspace --all-targets --all-features

check-crate CRATE:
    cargo check -p {{CRATE}} --all-targets --all-features

check-crate-linux CRATE:
  cargo check -p {{CRATE}} --target x86_64-unknown-linux-gnu --all-features
  cargo check -p {{CRATE}} --target aarch64-unknown-linux-gnu --all-features

check-links:
    lychee .

clippy:
    cargo clippy --workspace --all-targets --all-features

clippy-beta:
    cargo +beta clippy --workspace --all-targets --all-features

clippy-beta-crate CRATE:
    cargo +beta clippy -p {{CRATE}} --all-targets --all-features

clippy-crate CRATE:
    cargo clippy -p {{CRATE}} --all-targets --all-features

clippy-fix *ARGS:
    cargo clippy --workspace --all-targets --all-features --fix {{ARGS}}

clippy-fix-crate CRATE *ARGS:
    cargo clippy -p {{CRATE}} --all-targets --all-features --fix {{ARGS}}

typos:
    typos -w

extra-checks:
    @just _extra-checks-{{os_family()}}

_extra-checks-unix:
    {{justfile_directory()}}/scripts/extra-checks.sh

_extra-checks-windows:
    @echo "Skipping extra checks on Windows"

doc:
    cargo doc --all-features --no-deps --workspace --exclude rama-cli --exclude rama-net-apple-xpc
    just doc-crate rama-cli

doc-crate CRATE:
    cargo doc --all-features --no-deps -p {{CRATE}}

hack:
    @cargo install cargo-hack
    cargo hack check --each-feature --no-dev-deps --workspace

test *ARGS:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo nextest run --all-features --workspace {{ARGS}}

test-doc *ARGS:
    cargo test --doc --all-features --workspace {{ARGS}}

test-crate CRATE *ARGS:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo nextest run --all-features -p {{CRATE}} {{ARGS}}

test-doc-crate CRATE *ARGS:
    cargo test --doc --all-features -p {{CRATE}} {{ARGS}}

test-spec-h2 *ARGS:
    bash rama-http-core/ci/h2spec.sh {{ARGS}}

test-spec: test-spec-h2

test-ignored:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo nextest run --all-features --workspace --run-ignored=only

test-ignored-release:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo nextest run --all-features --release --workspace --run-ignored=only

test-loom:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    RUSTFLAGS="--cfg loom -Dwarnings" cargo nextest run --all-features -p rama-utils

qq: fmt-check check clippy doc extra-checks

qa: qq test test-doc deny

# QA pass for the optional `dial9` runtime-telemetry feature. Builds, lints
# and tests the rama crates that opt into dial9. `tokio_unstable` is
# required by `dial9-tokio-telemetry` and is set workspace-wide in
# `.cargo/config.toml` so this recipe does not need to set it explicitly.
#
# Kept separate from the main `qa` recipe so the standard QA path stays
# focused — but is part of `qa-full` so anyone running the full suite
# covers it. CI runs it as its own job.
qa-dial9:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo check -p rama-net -p rama-net-apple-networkextension -p rama-dns -p rama-tls-rustls -p rama-tls-boring -p rama-socks5 -p rama --features dial9 --all-targets
    cargo clippy -p rama-net -p rama-net-apple-networkextension -p rama-dns -p rama-tls-rustls -p rama-tls-boring -p rama-socks5 -p rama --features dial9 --all-targets
    cargo nextest run -p rama-net -p rama-net-apple-networkextension -p rama-dns -p rama-socks5 --features dial9

qa-crate CRATE:
    just fmt-check-crate {{CRATE}}
    just check-crate {{CRATE}}
    just clippy-crate {{CRATE}}
    just doc-crate {{CRATE}}
    just test-crate {{CRATE}}
    just test-doc-crate {{CRATE}}

qa-ffi-apple:
    RAMA_TPROXY_SKIP_CODESIGNING=1 RAMA_TPROXY_ISOLATED_CACHE=1 just ./ffi/apple/examples/transparent_proxy/qa

qa-xpc-apple:
    cargo check -p rama-net-apple-xpc
    cargo clippy -p rama-net-apple-xpc --all-targets -- -D warnings
    cargo doc --all-features --no-deps -p rama-net-apple-xpc
    cargo check -p rama --features net-apple-xpc
    cargo run --example xpc_echo --features=net-apple-xpc
    cargo run --example xpc_ca_exchange --features=net-apple-xpc

test-e2e-ffi-apple:
    just ./ffi/apple/examples/transparent_proxy/test-e2e

test-e2e-ffi-swift:
    just ./ffi/apple/examples/transparent_proxy/run-tproxy-ffi-e2e-swift

test-ffi-apple-full: qa-ffi-apple test-e2e-ffi-apple test-e2e-ffi-swift qa-xpc-apple

qa-full: qa qa-dial9 hack test-ignored test-ignored-release test-loom fuzz-60s check-links

bench-e2e-http-client-server *ARGS:
    ./scripts/bench/e2e_http_client_server.py {{ARGS}}

clean:
    cargo clean
    just ./ffi/apple/examples/transparent_proxy/clean

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

docker-build-rama-cli:
    docker build -f rama-cli/infra/Dockerfile -t glendc/rama-cli:latest .
    echo 'glendc/rama-cli:latest ready to use'

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
    cargo machete --skip-target-dir --with-metadata

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
    @cargo install cargo-edit --locked
    cargo upgrade && cargo update
    cargo update mimalloc --precise 0.1.48
    cargo update libmimalloc-sys --precise 0.1.44
    just ./ffi/apple/examples/transparent_proxy/clean
    just ./ffi/apple/examples/transparent_proxy/update-deps

oss-endpoint-healthcheck:
    bash rama-fp/infra/scripts/remote-healthcheck.sh
