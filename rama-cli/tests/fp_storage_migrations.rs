//! Exercise the production migration module without linking unrelated CLI commands.

#[path = "../src/cmd/serve/fp/storage/migrations.rs"]
mod migrations;

#[path = "../src/cmd/serve/fp/storage/counted.rs"]
mod counted;
