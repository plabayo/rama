set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Set `ALLOW_WARNINGS=true` for local iteration to drop `-D warnings`
# so in-progress code with unused imports / dead code still builds.
#
# Set `TOKIO_UNSTABLE=true` to add `--cfg tokio_unstable`, which widens
# dial9's task coverage.

# This is an `export` rather than a `.cargo/config.toml` entry because
# justfile's `export RUSTFLAGS` overrides cargo's config either way.
export RUSTFLAGS := \
    (if env_var_or_default("ALLOW_WARNINGS", "false") == "true" { \
        "" \
    } else { \
        "-D warnings" \
    }) + (if env_var_or_default("TOKIO_UNSTABLE", "false") == "true" { \
        " --cfg tokio_unstable" \
    } else { \
        "" \
    })
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

# Cross-link the same bounded Linux GNU coverage used by CI. The default
# target keeps compatibility with glibc 2.17; pass another cargo-zigbuild
# target explicitly when a different architecture or baseline is needed.
test-zigbuild-linux-gnu TARGET="x86_64-unknown-linux-gnu.2.17":
    just test-zigbuild-linux-gnu-sentinels {{TARGET}}
    just test-zigbuild-linux-gnu-cli {{TARGET}}
    just test-zigbuild-linux-gnu-all {{TARGET}}

# Cross-link configurations where all-features could mask a target ABI issue
# or activate several interchangeable backends at once.
test-zigbuild-linux-gnu-sentinels TARGET="x86_64-unknown-linux-gnu.2.17":
    @just _zigbuild-linux-gnu-with-native-env _zigbuild-linux-gnu-sentinels {{TARGET}}

_zigbuild-linux-gnu-sentinels TARGET:
    cargo zigbuild --locked -p rama --tests --no-default-features --target {{TARGET}}
    just test-zigbuild-linux-gnu-native-dns {{TARGET}}
    cargo zigbuild --locked -p rama --tests --no-default-features --features rustls,ring --target {{TARGET}}
    cargo zigbuild --locked -p rama --tests --no-default-features --features rustls,aws-lc --target {{TARGET}}
    cargo zigbuild --locked -p rama-examples --bin tls_boring_dynamic_certs --no-default-features --features boring,http-full --target {{TARGET}}

# Link the focused downstream path that originally exposed the glibc resolver
# symbol mismatch. This is also the inexpensive AArch64 CI gate.
test-zigbuild-linux-gnu-native-dns TARGET="x86_64-unknown-linux-gnu.2.17":
    cargo zigbuild --locked -p rama-examples --bin native_dns --features dns --target {{TARGET}}

# Build the real CLI with its curated distribution features, independently of
# workspace-wide feature unification.
test-zigbuild-linux-gnu-cli TARGET="x86_64-unknown-linux-gnu.2.17":
    @just _zigbuild-linux-gnu-with-native-env _zigbuild-linux-gnu-cli {{TARGET}}

_zigbuild-linux-gnu-cli TARGET:
    cargo zigbuild --locked -p rama-cli --bin rama --target {{TARGET}}

# On a Linux x86_64 host, start the cross-built CLI to verify its ELF loader,
# dynamic dependencies, allocator, and command-line entry point.
test-zigbuild-linux-gnu-smoke BINARY="target/x86_64-unknown-linux-gnu/debug/rama":
    chmod +x {{BINARY}}
    {{BINARY}} --version

# Cross-link every workspace target and feature. rama-fuzz is a cargo-fuzz
# harness and gets its entry points from cargo fuzz rather than plain Cargo.
test-zigbuild-linux-gnu-all TARGET="x86_64-unknown-linux-gnu.2.17":
    @just _zigbuild-linux-gnu-with-native-env _zigbuild-linux-gnu-all {{TARGET}}

_zigbuild-linux-gnu-all TARGET:
    cargo zigbuild --locked --workspace --all-targets --all-features --exclude rama-fuzz --target {{TARGET}}

# Native dependencies need the target archiver, while AWS-LC's cc builder uses
# the compiler environment supplied by cargo-zigbuild. Keep the platform shell
# details below this shared recipe boundary.
_zigbuild-linux-gnu-with-native-env RECIPE TARGET:
    @just _zigbuild-linux-gnu-with-native-env-{{os_family()}} {{RECIPE}} {{TARGET}}

_zigbuild-linux-gnu-with-native-env-unix RECIPE TARGET:
    AR="zig ar" AWS_LC_SYS_CMAKE_BUILDER=0 just {{RECIPE}} {{TARGET}}

# jemalloc 0.7 links its installed archive, then removes out/build. Its
# unquoted install paths lose Windows backslashes in sh; install relative to
# out/build so the archive and headers land in out/lib and out/include.
_zigbuild-linux-gnu-with-native-env-windows RECIPE TARGET:
    $gitShell = (Get-Command sh.exe).Source; $shortShell = (New-Object -ComObject Scripting.FileSystemObject).GetFile($gitShell).ShortPath.Replace('\', '/'); $env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"; $env:MAKEFLAGS = "SHELL=$shortShell LIBDIR=../lib INCLUDEDIR=../include"; $env:AR = "zig ar"; $env:AWS_LC_SYS_CMAKE_BUILDER = "0"; just {{RECIPE}} {{TARGET}}

# check no_std crates against a target without std: any dep that links
# std fails loudly here instead of poisoning downstream no_std consumers
# (e.g. kernel drivers hit E0152 duplicate panic_impl)
check-nostd:
    @rustup target list --installed | grep -q x86_64-unknown-none || rustup target add x86_64-unknown-none
    cargo check -p rama-error --no-default-features --target x86_64-unknown-none
    cargo check -p rama-utils --no-default-features --target x86_64-unknown-none
    cargo check -p rama-core --no-default-features --target x86_64-unknown-none
    cargo check -p rama-net --no-default-features --target x86_64-unknown-none
    cargo check -p rama-icap --no-default-features --target x86_64-unknown-none
    cargo check -p rama --no-default-features --target x86_64-unknown-none
    cargo check -p rama --no-default-features --features icap --target x86_64-unknown-none
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

docsrs-metadata-check:
    @just _docsrs-metadata-check-{{os_family()}}

_docsrs-metadata-check-unix:
    {{justfile_directory()}}/scripts/docsrs-metadata-check.sh

_docsrs-metadata-check-windows:
    @echo "Skipping docs.rs metadata check on Windows"

doc:
    cargo doc --all-features --no-deps --workspace --exclude rama-cli --exclude rama-net-apple-xpc
    just doc-crate rama-cli

doc-crate CRATE:
    cargo doc --all-features --no-deps -p {{CRATE}}

# Build every publishable crate with its docs.rs metadata and declared targets.
# cargo-docs-rs supplies the docs.rs environment and rustdoc invocation.
docsrs-check:
    python3 {{justfile_directory()}}/scripts/docsrs_check.py

# Keep the explicit full recipe name for release tooling.
docsrs-check-full:
    python3 {{justfile_directory()}}/scripts/docsrs_check.py --all-targets

# Apply docs.rs settings while documenting the current host target.
docsrs-check-native:
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

test-datastar-sdk *ARGS:
    bash scripts/test-datastar-sdk.sh {{ARGS}}

test-proxy-dashboard-browser:
    node --test rama-cli/src/cmd/serve/proxy/dashboard-browser.test.cjs

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

qa: qq docsrs-metadata-check test test-no-default-features test-doc deny

# QA pass for the optional `dial9` runtime-telemetry feature. Builds, lints
# and tests the rama crates that opt into dial9, on stable Tokio. Use
# `qa-dial9-tokio-unstable` for the same pass with `--cfg tokio_unstable`.
#
# Kept separate from the main `qa` recipe so the standard QA path stays
# focused — but is part of `qa-full` so anyone running the full suite
# covers it. CI runs it as its own job.
qa-dial9:
    @command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked
    cargo check -p rama-core -p rama-http -p rama-ws -p rama-net -p rama-net-apple-networkextension -p rama-dns -p rama-tls-rustls -p rama-tls-boring -p rama-socks5 -p rama --features dial9 --all-targets
    cargo clippy -p rama-core -p rama-http -p rama-ws -p rama-net -p rama-net-apple-networkextension -p rama-dns -p rama-tls-rustls -p rama-tls-boring -p rama-socks5 -p rama --features dial9 --all-targets
    cargo nextest run -p rama-core -p rama-http -p rama-ws -p rama-net -p rama-net-apple-networkextension -p rama-dns -p rama-socks5 --features dial9

# `qa-dial9` under `--cfg tokio_unstable`, where dial9 gets its full task coverage.
qa-dial9-tokio-unstable:
    TOKIO_UNSTABLE=true just qa-dial9

# Interactive: boot the fastcgi-php gateway demo (HTTPS → FastCGI/TCP → php-fpm)
# and leave it running until Ctrl-C so you can curl / browse it.
example-fastcgi-php-gateway:
    ./examples/src/gateway/fastcgi-php/gateway/run.sh run

# Interactive: boot the fastcgi-php migration demo (HTTP → router → FastCGI/Unix → php-fpm).
example-fastcgi-php-migration:
    ./examples/src/gateway/fastcgi-php/migration/run.sh run

# CI/test: boot both, run jq assertions, tear down.
test-fastcgi-php:
    ./examples/src/gateway/fastcgi-php/test.sh test

# Build and start the pinned c-icap interoperability oracle.
icap-oracle-up:
    docker compose -f rama-icap/tests/oracle/c-icap/compose.yaml up --build --detach --wait

# Ask c-icap's own client to perform OPTIONS against the echo service.
icap-oracle-smoke: icap-oracle-up
    docker compose -f rama-icap/tests/oracle/c-icap/compose.yaml exec -T c-icap /opt/c-icap/bin/c-icap-client -i 127.0.0.1 -p 1344 -s echo
    docker compose -f rama-icap/tests/oracle/c-icap/compose.yaml exec -T c-icap-204 /opt/c-icap/bin/c-icap-client -i 127.0.0.1 -p 1344 -s echo

# Run c-icap's client against c-icap's servers across the reference scenario matrix.
icap-oracle-test:
    bash rama-icap/tests/oracle/c-icap/run-matrix.sh

# Run Rama's client against the pinned c-icap servers.
icap-oracle-test-rama-client: icap-oracle-up
    RAMA_ICAP_ORACLE_REQUIRED=1 RAMA_ICAP_ORACLE_ECHO_ADDR=127.0.0.1:${RAMA_ICAP_C_ICAP_PORT:-1345} RAMA_ICAP_ORACLE_204_ADDR=127.0.0.1:${RAMA_ICAP_C_ICAP_204_PORT:-1346} cargo test --locked -p rama-icap --features http --test c_icap_interop -- --include-ignored --nocapture

# Run c-icap's full client matrix against local Rama servers.
icap-oracle-test-rama-server-local:
    rama-icap/tests/oracle/c-icap/rama-server-matrix.sh

# Run the same C reference-client matrix against a Rama server on the host.
icap-oracle-test-rama-server MODE="normal" HOST="host.docker.internal" PORT="1344":
    docker compose -f rama-icap/tests/oracle/c-icap/compose.yaml run --build --rm --no-deps --entrypoint /opt/rama-icap-oracle/reference-matrix.sh c-icap {{MODE}} {{HOST}} {{PORT}} rama

# Stop the c-icap oracle and remove its Compose resources.
icap-oracle-down:
    docker compose -f rama-icap/tests/oracle/c-icap/compose.yaml down --volumes --remove-orphans

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
    cargo run -p rama-examples --bin xpc_echo --features=net-apple-xpc
    cargo run -p rama-examples --bin xpc_ca_exchange --features=net-apple-xpc

test-e2e-ffi-apple:
    just ./ffi/apple/examples/transparent_proxy/test-e2e

test-e2e-ffi-swift:
    just ./ffi/apple/examples/transparent_proxy/run-tproxy-ffi-e2e-swift

test-ffi-apple-full: qa-ffi-apple test-e2e-ffi-apple test-e2e-ffi-swift qa-xpc-apple

qa-full: qa qa-dial9 qa-dial9-tokio-unstable hack test-ignored test-ignored-release test-loom fuzz-60s check-links

bench-e2e-http-client-server *ARGS:
    ./scripts/bench/e2e_http_client_server.py {{ARGS}}

clean: clean-rust clean-ffi-apple clean-js

clean-rust:
    cargo clean
    cargo clean --target-dir examples/target

clean-ffi-apple:
    just ./ffi/apple/examples/transparent_proxy/clean

clean-js:
    @just _clean-js-{{os_family()}}

_clean-js-unix:
    rm -rf -- rama-js/engine/starling/.build

_clean-js-windows:
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue rama-js/engine/starling/.build

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
        cargo run -p rama-examples --bin {{NAME}}

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

fuzz-icap-seeds-check:
    @for seed in fuzz/corpus-seeds/icap_codec_roundtrip/*; do if [ "$(wc -c < "$seed")" -lt 38 ]; then echo "unreachable structured ICAP seed: $seed" >&2; exit 1; fi; done

fuzz-icap: fuzz-icap-seeds-check
    mkdir -p fuzz/corpus/icap_codec fuzz/corpus/icap_codec_roundtrip
    cargo +nightly fuzz run icap_codec fuzz/corpus/icap_codec fuzz/corpus-seeds/icap_codec -- -dict=fuzz/dictionaries/icap.dict -max_len=65536 -timeout=5
    cargo +nightly fuzz run icap_codec_roundtrip fuzz/corpus/icap_codec_roundtrip fuzz/corpus-seeds/icap_codec_roundtrip -- -max_len=64 -timeout=5

fuzz-icap-60s: fuzz-icap-seeds-check
    mkdir -p fuzz/corpus/icap_codec fuzz/corpus/icap_codec_roundtrip
    cargo +nightly fuzz run icap_codec fuzz/corpus/icap_codec fuzz/corpus-seeds/icap_codec -- -dict=fuzz/dictionaries/icap.dict -max_len=65536 -timeout=5 -max_total_time=60
    cargo +nightly fuzz run icap_codec_roundtrip fuzz/corpus/icap_codec_roundtrip fuzz/corpus-seeds/icap_codec_roundtrip -- -max_len=64 -timeout=5 -max_total_time=60

# Sustained pre-release ICAP fuzzing. Override the durations for a shorter
# local pass while keeping the release defaults visible and reproducible.
fuzz-icap-release RAW_SECONDS="21600" ROUNDTRIP_SECONDS="7200": fuzz-icap-seeds-check
    mkdir -p fuzz/corpus/icap_codec fuzz/corpus/icap_codec_roundtrip
    cargo +nightly fuzz run -j 4 icap_codec fuzz/corpus/icap_codec fuzz/corpus-seeds/icap_codec -- -dict=fuzz/dictionaries/icap.dict -max_len=65536 -timeout=5 -max_total_time={{RAW_SECONDS}}
    cargo +nightly fuzz run -j 4 icap_codec_roundtrip fuzz/corpus/icap_codec_roundtrip fuzz/corpus-seeds/icap_codec_roundtrip -- -max_len=64 -timeout=5 -max_total_time={{ROUNDTRIP_SECONDS}}

fuzz-dns-txt-rr:
    cargo +nightly fuzz run dns_txt_rr -- -max_len=4096

fuzz-dns-txt-rr-60s:
    cargo +nightly fuzz run dns_txt_rr -- -max_len=4096 -max_total_time=60

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

fuzz-60s: fuzz-ua-60s fuzz-h2-60s fuzz-http-headers-x-robots-tag-60s fuzz-http-header-map-60s fuzz-icap-60s

fuzz-full: fuzz-60s fuzz-h2-main

bench:
    cargo bench --features=full

bench-icap *ARGS:
    cargo bench -p rama-icap --features=http --bench icap -- {{ARGS}}

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

update-deps:
    @cargo install cargo-edit --locked
    cargo upgrade --incompatible && cargo update && cargo generate-lockfile
    just ./ffi/apple/examples/transparent_proxy/update-deps

oss-endpoint-healthcheck:
    bash rama-fp/infra/scripts/remote-healthcheck.sh
