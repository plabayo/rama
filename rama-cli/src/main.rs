use clap::{Parser, Subcommand};
use rama::error::BoxError;

mod echo;
use echo::CliCommandEcho;

mod http;
use http::CliCommandHttp;

mod proxy;
use proxy::CliCommandProxy;

mod ip;
use ip::CliCommandIp;

#[derive(Debug, Parser)]
#[command(name = "rama")]
#[command(bin_name = "rama")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmds: CliCommands,
}

#[derive(Debug, Subcommand)]
enum CliCommands {
    Echo(CliCommandEcho),
    Http(CliCommandHttp),
    Proxy(CliCommandProxy),
    Ip(CliCommandIp),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();

    match cli.cmds {
        CliCommands::Echo(cfg) => echo::run(cfg).await,
        CliCommands::Http(cfg) => http::run(cfg).await,
        CliCommands::Proxy(cfg) => proxy::run(cfg).await,
        CliCommands::Ip(cfg) => ip::run(cfg).await,
    }
}
