use std::io::Write;

use rama::{
    error::{BoxError, ErrorContext},
    net::{
        address::ip::{IpScopes, ip_scope},
        socket::{Interface, InterfaceAddress, interfaces},
    },
};

use clap::Args;

#[derive(Args, Debug, Clone)]
/// rama iface probe command: enumerate the local network interfaces
pub struct CliCommandIface {
    /// only show IPv4 addresses
    #[arg(long = "ipv4", short = '4')]
    ipv4: bool,

    /// only show IPv6 addresses
    #[arg(long = "ipv6", short = '6')]
    ipv6: bool,

    /// only show interfaces that are up (administratively and operationally)
    #[arg(long)]
    up_only: bool,

    /// only show addresses in the given comma-separated ip scopes
    ///
    /// e.g. "global" or "private,loopback"; also available: link-local,
    /// shared, unspecified, multicast, documentation, benchmarking, reserved,
    /// and the aliases local, non-global and all
    #[arg(long)]
    scope: Option<IpScopes>,
}

/// Run the iface command
pub async fn run(cfg: CliCommandIface) -> Result<(), BoxError> {
    let interfaces = interfaces().context("enumerate local network interfaces")?;
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    write_interfaces(&mut stdout, &interfaces, &cfg).context("write interfaces to stdout")?;
    stdout.flush().context("flush stdout")?;
    Ok(())
}

fn write_interfaces(
    w: &mut impl Write,
    interfaces: &[Interface],
    cfg: &CliCommandIface,
) -> std::io::Result<()> {
    let scopes = cfg.scope.unwrap_or_else(IpScopes::all);
    let filtering_addresses = cfg.ipv4 || cfg.ipv6 || cfg.scope.is_some();

    let keep = |address: &InterfaceAddress| {
        let ip = address.address();
        if cfg.ipv4 && !cfg.ipv6 && !ip.is_ipv4() {
            return false;
        }
        if cfg.ipv6 && !cfg.ipv4 && !ip.is_ipv6() {
            return false;
        }
        scopes.intersects(ip_scope(ip))
    };

    let mut first = true;
    for interface in interfaces {
        if cfg.up_only && !interface.is_up() {
            continue;
        }
        if filtering_addresses && !interface.addresses().iter().any(&keep) {
            continue;
        }

        if !first {
            writeln!(w)?;
        }
        first = false;

        write!(w, "{}:", interface.name())?;
        if let Some(index) = interface.index() {
            write!(w, " index={index}")?;
        }
        let flags = interface.flags();
        if flags.is_empty() {
            write!(w, " flags=-")?;
        } else {
            write!(w, " flags={flags}")?;
        }
        if let Some(mac) = interface.hardware_address() {
            write!(w, " mac={mac}")?;
        }
        if let Some(description) = interface.description() {
            write!(w, " ({description})")?;
        }
        writeln!(w)?;

        for address in interface.addresses() {
            if !keep(address) {
                continue;
            }
            writeln!(w, "* {address} ({})", ip_scope(address.address()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_interfaces_smoke() {
        let interfaces = interfaces().unwrap();
        let cfg = CliCommandIface {
            ipv4: false,
            ipv6: false,
            up_only: false,
            scope: None,
        };

        let mut out = Vec::new();
        write_interfaces(&mut out, &interfaces, &cfg).unwrap();
        let out = String::from_utf8(out).unwrap();

        // every host we run tests on has a loopback address assigned
        assert!(
            out.contains("127.0.0.1") || out.contains("::1"),
            "no loopback address in:\n{out}"
        );

        // scoping to loopback only never yields more output than the full dump
        let cfg = CliCommandIface {
            scope: Some(IpScopes::LOOPBACK),
            ..cfg
        };
        let mut scoped = Vec::new();
        write_interfaces(&mut scoped, &interfaces, &cfg).unwrap();
        assert!(scoped.len() <= out.len());
    }
}
