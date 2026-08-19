# 🖥️ System-Wide Proxies

While application-specific settings are great for developers, they don't scale well in a corporate or "daily driver" environment. This is where **System Proxies** come in. Instead of hunting down config files for every app, you define the proxy at the operating system level, creating a centralized "suggestion" for how all network traffic should behave.

## 1. Configuring the System Gateway

System proxies act as a central repository of network intent. Most modern operating systems allow you to define these settings in a few standard formats:

* **Protocol-Specific URLs:** You can explicitly define different proxies for different traffic types. For example, you might route `HTTP` and `HTTPS` through a Rama MITM instance on port 8080, but send `SOCKS` traffic through a separate SSH tunnel on port 1080.
* **Automatic Configuration (PAC):** Instead of a static IP, you provide a URL to a **Proxy Auto-Configuration** file. This tells the system to download a script that makes dynamic decisions about which traffic needs a proxy and which should go "Direct."

## 2. How Network Stacks Fetch and Apply Settings

A system proxy is only useful if the software actually knows how to find it. This is not a "push" system; it is a "pull" system. When an application wants to connect to `google.com`, its networking library goes through a specific lookup routine.

### The Registry and System Stores

On **Windows**, these settings are primarily stored in the Registry (specifically under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`). On Apple platforms, they are exposed through CFNetwork's system proxy settings.

### Real-World Implementations

Rama supports system proxy discovery through `rama_net::client::SystemProxyLayer`:

* Windows reads the current user's WinINET Internet Options through the WinHTTP API; it does not read machine-wide `netsh winhttp` defaults.
* macOS and iOS read CFNetwork's system proxy dictionary.
* Android uses `ConnectivityManager.getDefaultProxy()`, with the legacy `Proxy` API on older versions.
* Linux and BSD read KDE or GNOME proxy settings, depending on the active desktop configuration.

On Linux and BSD, coverage follows the desktop configuration backend rather than the distribution. Rama understands GNOME-compatible GSettings and KDE's `kioslaverc`; desktops without either convention normally publish application proxy settings through the environment instead. Rama's environment layers cover that separate convention.

The layer is lazy: constructing it performs no platform lookup. The first request without an existing route loads a snapshot asynchronously. On macOS, Windows, and Linux, a private native monitor can request an earlier refresh when the underlying settings change. The default snapshot lifetime is ten seconds and remains the portable safety net. After either signal, one request refreshes the snapshot while concurrent requests keep using the last valid value; a failed refresh also retains that value. Android, Apple mobile platforms, and the BSDs use the TTL unless the embedding application supplies its own change trigger, because their notifications belong to an application-managed callback or event loop.

The native monitor can be replaced or disabled independently of periodic refresh. Refresh itself can also be disabled when a supplied snapshot must remain immutable. These controls and the optional error sink are described in the [`SystemProxyLayer` reference](https://ramaproxy.org/docs/rama/net/client/struct.SystemProxyLayer.html).

System-provided PAC URLs require a PAC resolver service. The [`rama-pac`](https://crates.io/crates/rama-pac) crate supplies [`SystemPacProxy`](https://ramaproxy.org/docs/rama/js/pac/struct.SystemPacProxy.html), which reuses the compiled resolver while evaluating the PAC decision for every request. Fetching and script caching remain explicit, composable concerns; see the [PAC chapter](./pac.md) for the model and the linked API reference for implementation details.

The Rama CLI installs these layers automatically. Its routing precedence is `NO_PROXY`, an explicit `--proxy`, proxy environment variables, and finally the operating-system settings. Existing route decisions are preserved unless a layer explicitly opts into overwriting them.

## A Final Warning: The "Respect" Factor

It is vital to remember that **System Proxies are not enforced.** Unlike a [Transparent Proxy](./transparent.md) which "snatches" packets at the kernel level, a System Proxy is merely a flag in the OS settings. It is a "social contract." While browsers like Chrome and Safari are very good at respecting this contract, many other applications—such as CLI tools, high-performance games, or poorly written background services—completely ignore these settings.

If an application is hard-coded to ignore the system's "suggestion," its traffic will bypass your Rama proxy entirely. If you require **strict enforcement** where no packet can escape without your say-so, you must look toward [Transparent Interception](./transparent.md).
