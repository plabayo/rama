use clap::{Parser, Subcommand};

mod profile;
mod proxy;

/// A fictional versioning CLI
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "rama")]
#[command(about = "a distortion proxy cli", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Download and store web client profiles
    #[command(subcommand)]
    Profile(profile::Commands),

    /// Run the rama proxy
    Run,
}

#[rama::rt::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Profile(profile) => profile.run().await,
        Commands::Run => proxy::run().await,
    }
}
