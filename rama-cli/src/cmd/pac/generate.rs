use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::Args;
use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    js::pac::{PacDirectives, PacGenerator},
    net::address::Domain,
};

#[derive(Debug, Args)]
pub(super) struct GenerateCommand {
    /// Ordered route in `DOMAINS=DIRECTIVES` form; prefix domains with
    /// `exact:` to exclude subdomains.
    #[arg(long = "route", value_name = "[exact:]DOMAINS=DIRECTIVES")]
    routes: Vec<RouteArg>,

    /// Directives returned when no route matches.
    #[arg(long, default_value = "DIRECT", value_name = "DIRECTIVES")]
    default: PacDirectives,

    /// Write the generated script to this file instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Replace an existing output file.
    #[arg(long, requires = "output")]
    force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteArg {
    domains: Vec<Domain>,
    directives: PacDirectives,
    exact: bool,
}

impl FromStr for RouteArg {
    type Err = BoxError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (domains, directives) = raw
            .split_once('=')
            .context("PAC route must use `[exact:]DOMAIN[,DOMAIN...]=DIRECTIVES` syntax")?;
        let (domains, exact) = domains
            .strip_prefix("exact:")
            .map_or((domains, false), |domains| (domains, true));
        if domains.trim().is_empty() {
            return Err(BoxError::from_static_str(
                "PAC route requires at least one domain",
            ));
        }

        let domains = domains
            .split(',')
            .map(str::trim)
            .map(|domain| {
                if domain.is_empty() {
                    return Err(BoxError::from_static_str(
                        "PAC route contains an empty domain",
                    ));
                }
                domain
                    .parse()
                    .context("parse PAC route domain")
                    .with_context_str_field("domain", || domain.to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let directives = directives
            .trim()
            .parse()
            .context("parse PAC route directives")?;

        Ok(Self {
            domains,
            directives,
            exact,
        })
    }
}

pub(super) fn run(config: GenerateCommand) -> Result<(), BoxError> {
    let mut generator = PacGenerator::new().with_default_route(config.default);
    for route in config.routes {
        if route.exact {
            generator.set_exact_route(route.directives, route.domains);
        } else {
            generator.set_route(route.directives, route.domains);
        }
    }

    let script = generator.generate();
    if let Some(path) = config.output {
        write_file(&path, script.as_str(), config.force)
    } else {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        stdout
            .write_all(script.as_str().as_bytes())
            .context("write generated PAC script to stdout")?;
        stdout.flush().context("flush generated PAC script")
    }
}

fn write_file(path: &Path, source: &str, force: bool) -> Result<(), BoxError> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists && !force => {
            return Err(BoxError::from_static_str(
                "PAC output file already exists; pass --force to replace it",
            )
            .context_debug_field("path", path.to_owned()));
        }
        Err(err) => {
            return Err(err)
                .context("open PAC output file")
                .with_context_debug_field("path", || path.to_owned());
        }
    };
    file.write_all(source.as_bytes())
        .context("write generated PAC script")
        .with_context_debug_field("path", || path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_parser_preserves_domain_order_and_exactness() {
        let route: RouteArg = "exact:api.example,*.corp.example=PROXY proxy.example:8080; DIRECT"
            .parse()
            .unwrap();

        assert!(route.exact);
        assert_eq!(route.domains[0].as_str(), "api.example");
        assert_eq!(route.domains[1].as_str(), "*.corp.example");
        assert_eq!(
            route.directives.to_string(),
            "PROXY proxy.example:8080; DIRECT"
        );
    }

    #[test]
    fn route_parser_rejects_malformed_inputs() {
        for raw in [
            "example.com",
            "=DIRECT",
            "example.com,=DIRECT",
            "not a domain=DIRECT",
            "example.com=unsupported value",
        ] {
            assert!(raw.parse::<RouteArg>().is_err(), "{raw}");
        }
    }

    #[test]
    fn generated_routes_keep_command_line_order() {
        let routes = ["b.example=PROXY first.example:80", "exact:a.example=DIRECT"]
            .into_iter()
            .map(str::parse::<RouteArg>)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let config = GenerateCommand {
            routes,
            default: "HTTPS fallback.example:443".parse().unwrap(),
            output: None,
            force: false,
        };

        let mut generator = PacGenerator::new().with_default_route(config.default);
        for route in config.routes {
            if route.exact {
                generator.set_exact_route(route.directives, route.domains);
            } else {
                generator.set_route(route.directives, route.domains);
            }
        }
        let source = generator.generate();

        let first = source.as_str().find(".b.example").unwrap();
        let second = source.as_str().find(".a.example").unwrap();
        assert!(first < second);
        assert!(source.as_str().contains("HTTPS fallback.example:443"));
    }

    #[test]
    fn file_output_does_not_overwrite_without_force() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("proxy.pac");
        std::fs::write(&path, "original").unwrap();

        let error = write_file(&path, "replacement", false).unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original");

        write_file(&path, "replacement", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");

        let missing_parent = directory.path().join("missing").join("proxy.pac");
        let error = write_file(&missing_parent, "source", false).unwrap_err();
        assert!(error.to_string().contains("open PAC output file"));
    }

    #[test]
    fn command_runner_writes_the_generated_policy() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("generated.pac");
        run(GenerateCommand {
            routes: vec!["example.com=PROXY proxy.example:8080".parse().unwrap()],
            default: "DIRECT".parse().unwrap(),
            output: Some(path.clone()),
            force: false,
        })
        .unwrap();

        let source = std::fs::read_to_string(path).unwrap();
        assert!(source.contains(".example.com"));
        assert!(source.contains("PROXY proxy.example:8080"));
        assert!(source.contains("return \"DIRECT\""));
    }
}
