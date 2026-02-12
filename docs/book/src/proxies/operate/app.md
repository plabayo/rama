# 🛠️ Application-Specific Proxies

In many development and debugging scenarios, you don't want to overhaul your entire operating system's network configuration. Instead, you just want one specific process—whether it's a web crawler, a CLI tool, or a microservice—to route its traffic through your Rama gateway. This is known as application-level proxying.

## Environment Variables: The "Silent" Configuration

The most common way to steer application traffic is through environment variables. Most modern networking libraries (and languages like Rust, Go, and Python) are programmed to check the environment for specific "magic" keys before they open a connection.

By setting these in your shell, you tell the next command you run exactly where to go:

* `HTTP_PROXY`: The gateway for unencrypted web traffic.
* `HTTPS_PROXY`: The gateway for encrypted traffic (this usually triggers a **CONNECT** request to your proxy).
* `NO_PROXY`: A comma-separated list of hostnames or IPs that should bypass the proxy entirely (like `localhost` or internal dev servers).

This is a "voluntary" handshake. The application sees these variables and chooses to wrap its data in a proxy protocol (like HTTP or SOCKS5) before sending it out.

## The CLI Tooling: Explicit Steering

When you are testing your Rama proxy, you often use specialized CLI tools. These tools typically offer flags that override any environment variables, giving you precise control over a single request.

### CLI Arguments

Using the `-x` (or `--proxy`) flag, you can point it at your Rama instance:

- using cURL: `curl -x http://127.0.0.1:8080 https://example.com`
- using rama-cli: `rama -x http://127.0.0.1:8080 https://example.com`

## Local Configuration Files

Beyond environment variables, many heavy-duty applications—think IDEs like VS Code, database clients, or Docker—maintain their own internal configuration files.

These are useful because they stay "pinned" to that specific app. You might want your Docker daemon to pull images through a proxy to save bandwidth, while keeping your browser on a direct connection. While this is highly granular, it can also lead to "configuration drift," where you forget which app is talking through which gateway.

## Why use this over a System Proxy?

The beauty of application-specific proxying is **isolation**. Because the proxy logic is contained within the environment of a single process, you don't risk breaking your entire machine if your Rama instance goes down or if you're experimenting with a "noisy" MITM configuration. It’s the safest way to iterate during development before you decide to "go global" with a system-wide or transparent setup.
