FROM rustlang/rust:nightly-slim as builder

# Make a fake Rust app to keep a cached layer of compiled crates
RUN USER=root cargo new app
WORKDIR /usr/src/app
COPY Cargo.toml ./
# Needs at least a main.rs file with a main function
RUN mkdir -p rama/rama && echo "fn main(){}" > rama/bin/main.rs
# Will build all dependent crates in release mode
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    cargo build --release

# Copy the rest
COPY . .
# Build (install) the actual binary
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    cargo install --path . --bin rama

# Runtime image
FROM debian:bookworm-slim

# Run as "app" user
RUN useradd -ms /bin/bash app

USER app
WORKDIR /app

# Get compiled binary from builder's cargo install directory
COPY --from=builder /usr/local/cargo/bin/rama /app/rama

ENTRYPOINT [ "/app/rama" ]
