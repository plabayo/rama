use argh::FromArgs;
use rama::error::BoxError;

mod http;
use http::CliCommandHttp;

mod proxy;
use proxy::CliCommandProxy;

#[derive(Debug, FromArgs)]
/// rama cli to move and transform netwrok packets
/// 
/// https://ramaproxy.org
struct Cli {
    #[argh(subcommand)]
    cmds: CliCommands,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum CliCommands {
    Http(CliCommandHttp),
    Proxy(CliCommandProxy),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli: Cli = argh::from_env();
    match cli.cmds {
        CliCommands::Http(cfg) => http::run(cfg).await,
        CliCommands::Proxy(cfg) => proxy::run(cfg).await,
    }
}
