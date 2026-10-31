//! native utilities unique to unix

use std::io;

use rama_core::telemetry::tracing;

pub use libc::rlim_t;

/// Raise the process soft file descriptor limit (RLIMIT_NOFILE) up to `target`.
///
/// Many network heavy applications such as HTTP proxies, gateways, and high concurrency servers
/// can hit the per process open file descriptor limit and fail with errors like
/// "Too many open files" (EMFILE). Sockets, accepted connections, pipes, and various runtime
/// resources all consume file descriptors.
///
/// This utility reads the current `RLIMIT_NOFILE` limits and tries to increase the soft limit
/// (`rlim_cur`) to `target`, but never above the hard limit (`rlim_max`). If the current soft
/// limit is already greater than or equal to the computed new soft limit, this function does
/// nothing.
///
/// Notes
/// - This function does not attempt to raise the hard limit. Raising the hard limit typically
///   requires elevated privileges or system configuration.
/// - In container or service environments, the effective hard limit may be constrained by the
///   supervisor. For example systemd, launchd, Docker, Kubernetes.
pub fn raise_nofile(target: rlim_t) -> io::Result<()> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit(2) writes one `struct rlimit` to its second argument;
    // `lim` is a live, aligned, writable local of that type.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let hard = lim.rlim_max;
    let new_soft = target.min(hard);

    if lim.rlim_cur >= new_soft {
        tracing::info!(
            "ulimit: keep current limit ({}) as it is higher than new soft limit ({new_soft}): nothing to do",
            lim.rlim_cur,
        );
        return Ok(());
    }

    let previous_value = lim.rlim_cur;
    lim.rlim_cur = new_soft;
    // SAFETY: setrlimit(2) reads one `struct rlimit` from its second
    // argument, a live, initialized local; the kernel validates the values.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    tracing::info!(
        "ulimit: applied new soft limit ({new_soft}); previous value = {previous_value}",
    );

    Ok(())
}
