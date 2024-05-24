use argh::FromArgs;
use rama::error::BoxError;

mod proxy;
use proxy::CliCommandProxy;

#[derive(Debug, FromArgs)]
/// rama cli to move and transform netwrok packets
struct Cli {
    #[argh(subcommand)]
    cmds: CliCommands,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum CliCommands {
    Proxy(CliCommandProxy),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli: Cli = argh::from_env();
    match cli.cmds {
        CliCommands::Proxy(cfg) => proxy::run(cfg).await,
    }
}
