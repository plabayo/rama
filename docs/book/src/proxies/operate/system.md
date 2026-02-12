# 🖥️ System-Wide Proxies

While application-specific settings are great for developers, they don't scale well in a corporate or "daily driver" environment. This is where **System Proxies** come in. Instead of hunting down config files for every app, you define the proxy at the operating system level, creating a centralized "suggestion" for how all network traffic should behave.

## 1. Configuring the System Gateway

System proxies act as a central repository of network intent. Most modern operating systems allow you to define these settings in a few standard formats:

* **Protocol-Specific URLs:** You can explicitly define different proxies for different traffic types. For example, you might route `HTTP` and `HTTPS` through a Rama MITM instance on port 8080, but send `SOCKS` traffic through a separate SSH tunnel on port 1080.
* **Automatic Configuration (PAC):** Instead of a static IP, you provide a URL to a **Proxy Auto-Configuration** file. This tells the system to download a script that makes dynamic decisions about which traffic needs a proxy and which should go "Direct."

## 2. How Network Stacks Fetch and Apply Settings

A system proxy is only useful if the software actually knows how to find it. This is not a "push" system; it is a "pull" system. When an application wants to connect to `google.com`, its networking library goes through a specific lookup routine.

### The Registry and System Stores

On **Windows**, these settings are primarily stored in the Registry (specifically under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`). On **macOS**, they are managed by `SystemConfiguration.framework`.

### Real-World Implementations

> TODO: add Rama docs + Example once we have support for system proxies (it's on roadmap)

## A Final Warning: The "Respect" Factor

It is vital to remember that **System Proxies are not enforced.** Unlike a [Transparent Proxy](./transparent.md) which "snatches" packets at the kernel level, a System Proxy is merely a flag in the OS settings. It is a "social contract." While browsers like Chrome and Safari are very good at respecting this contract, many other applications—such as CLI tools, high-performance games, or poorly written background services—completely ignore these settings.

If an application is hard-coded to ignore the system's "suggestion," its traffic will bypass your Rama proxy entirely. If you require **strict enforcement** where no packet can escape without your say-so, you must look toward [Transparent Interception](./transparent.md).
