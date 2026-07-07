set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# `--cfg tokio_unstable` enables Tokio's unstable runtime APIs that
# `dial9-tokio-telemetry` requires. It is benign for crates that do
# not opt into the `dial9` feature; the workspace `.cargo/config.toml`
# carries the same flag for raw `cargo` invocations. We set it via env
# here because justfile's `export RUSTFLAGS` overrides cargo's config.
#
# Set `ALLOW_WARNINGS=true` for local iteration to drop `-D warnings`
# so in-progress code with unused imports / dead code still builds.
export RUSTFLAGS := \
    if env_var_or_default("ALLOW_WARNINGS", "false") == "true" { \
        "--cfg tokio_unstable" \
    } else { \
        "-D warnings --cfg tokio_unstable" \
    }
# Mirror CI's doc job: rustdoc warnings (e.g. private intra-doc links) fail
# locally too, unless ALLOW_WARNINGS=true. rustdoc reads RUSTDOCFLAGS, not
# RUSTFLAGS, so it needs its own export.
export RUSTDOCFLAGS := \
    if env_var_or_default("ALLOW_WARNINGS", "false") == "true" { \
        "" \
    } else { \
        "-D warnings" \
    }
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

sort-check *ARGS:
    cargo sort --workspace --check {{ARGS}}

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

# check no_std crates against a target without std: any dep that links
# std fails loudly here instead of poisoning downstream no_std consumers
# (e.g. kernel drivers hit E0152 duplicate panic_impl)
check-nostd:
    @rustup target list --installed | grep -q x86_64-unknown-none || rustup target add x86_64-unknown-none
    cargo check -p rama-error --no-default-features --target x86_64-unknown-none
    cargo check -p rama-utils --no-default-features --target x86_64-unknown-none
    cargo check -p rama-core --no-default-features --target x86_64-unknown-none
    cargo check -p rama-net --no-default-features --target x86_64-unknown-none
    cargo check -p rama --no-default-features --target x86_64-unknown-none
    cargo check -p rama --no-default-features --features net --target x86_64-unknown-none

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

# Each publishable crate is documented on nightly with its own
# [package.metadata.docs.rs] flags, the workspace tokio_unstable rustflags
# overridden (the clean-env mismatch that broke 0.3.0-rc.1 on docs.rs).
# The script sets RUSTFLAGS/RUSTDOCFLAGS itself, so the justfile exports
# above don't apply.
# Emulate per-crate docs.rs builds; run before every release
docsrs-check:
    python3 {{justfile_directory()}}/scripts/docsrs_check.py

hack:
    @cargo install cargo-hack
    cargo hack check --each-feature --no-dev-deps --workspace

test *ARGS:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo nextest run --all-features --workspace {{ARGS}}

test-no-default-features *ARGS:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo nextest run --no-default-features --workspace {{ARGS}}

test-doc *ARGS:
    cargo test --doc --all-features --workspace {{ARGS}}

test-crate CRATE *ARGS:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo nextest run --all-features -p {{CRATE}} {{ARGS}}

test-doc-crate CRATE *ARGS:
    cargo test --doc --all-features -p {{CRATE}} {{ARGS}}

test-spec-h2 *ARGS:
    bash rama-http-core/ci/h2spec.sh {{ARGS}}

# MITM revocation gate (Linux/macOS): hermetic staple matrix (curl --cert-status,
# incl. the no-staple negative) + proxy-hosted CRL/OCSP endpoint acceptance
# (openssl -crl_check / ocsp) + a real-crates.io curl/cargo leg through the
# CONNECT proxy. Skips the strict legs if no OpenSSL-backed curl is found (set
# OCSP_GATE_REQUIRE=1 to make that a failure, as CI does).
test-revocation-gate *ARGS:
    bash scripts/ocsp-relay-gate.sh {{ARGS}}

# MITM revocation gate (Windows): cargo through the CONNECT proxy to real
# crates.io, where schannel enforces revocation (the customer scenario).
test-revocation-gate-windows:
    pwsh scripts/ocsp-relay-gate.ps1

test-spec: test-spec-h2 test-revocation-gate

test-ignored:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo nextest run --all-features --workspace --run-ignored=only

test-ignored-release:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo nextest run --all-features --release --workspace --run-ignored=only

test-loom:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    RUSTFLAGS="--cfg loom -Dwarnings" cargo nextest run --all-features -p rama-utils

qq: sort-check fmt-check check check-nostd clippy doc extra-checks

qa: qq test test-no-default-features test-doc deny

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

# Interactive: boot the fastcgi-php gateway demo (HTTPS → FastCGI/TCP → php-fpm)
# and leave it running until Ctrl-C so you can curl / browse it.
example-fastcgi-php-gateway:
    ./examples/gateway/fastcgi-php/gateway/run.sh run

# Interactive: boot the fastcgi-php migration demo (HTTP → router → FastCGI/Unix → php-fpm).
example-fastcgi-php-migration:
    ./examples/gateway/fastcgi-php/migration/run.sh run

# CI/test: boot both, run jq assertions, tear down.
test-fastcgi-php:
    ./examples/gateway/fastcgi-php/test.sh test

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

fuzz-http-header-map:
    cargo +nightly fuzz run http_header_map -- -max_len=131072

fuzz-http-header-map-60s:
    cargo +nightly fuzz run http_header_map -- -max_len=131072 -max_total_time=60

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

fuzz-60s: fuzz-ua-60s fuzz-h2-60s fuzz-http-headers-x-robots-tag-60s fuzz-http-header-map-60s

fuzz-full: fuzz-60s fuzz-h2-main

bench:
    cargo bench --features=full

vet:
    cargo vet

miri:
    cargo +nightly miri test

# Narrow Miri pass for the Apple NetworkExtension crate's pure Rust FFI
# ownership/conversion tests. Keep this separate from `miri`: the full
# workspace pass is broader, while this target is intended as the fast
# preflight for Apple bridge hardening work.
miri-apple-ne-ffi:
    cargo +nightly miri test -p rama-net-apple-networkextension ffi::bytes --lib
    cargo +nightly miri test -p rama-net-apple-networkextension ffi::tproxy::tests::ffi_enum_decoders_fail_safe_on_bad_byte --lib
    cargo +nightly miri test -p rama-net-apple-networkextension ffi::tproxy::tests::ffi_struct_layout_matches_c_header_on_64_bit_targets --lib

# Targeted mutation pass for the Apple NetworkExtension FFI/config boundary.
# This intentionally avoids the full Apple e2e surface so cargo-mutants can
# produce useful signal without spending most of its time in system-extension
# setup. Install with: cargo install cargo-mutants --locked
mutants-apple-ne-ffi:
    cargo mutants --package rama-net-apple-networkextension --file rama-net-apple-networkextension/src/ffi/bytes.rs --file rama-net-apple-networkextension/src/ffi/tproxy.rs --file rama-net-apple-networkextension/src/tproxy/types.rs --timeout 120

mutants-http-headers:
    cargo mutants --package rama-http-types --file rama-http-types/src/header/name.rs --file rama-http-types/src/header/map.rs --timeout 120

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
    cargo upgrade --incompatible && cargo update
    just ./ffi/apple/examples/transparent_proxy/update-deps

oss-endpoint-healthcheck:
    bash rama-fp/infra/scripts/remote-healthcheck.sh
