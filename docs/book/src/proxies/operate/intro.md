# Operate Proxies

After building a proxy, the next question is how traffic reaches it. Applications and operating systems connect directly by default, and getting their traffic routed through your Rama proxy is often the harder part of operating one. There are four common setups, described below.

## Application Proxy Settings

Some applications support proxies themselves: they read a setting such as the `http_proxy` environment variable or a browser's proxy configuration, and connect to the proxy instead of the target. This is the simplest setup, because the application does the routing.

## Managed Rules and PAC Files

In larger or corporate environments, proxies are configured as "System Proxies": instead of configuring every application, you set the proxy in the operating system, and applications that read those settings use it. This is often where **PAC (Proxy Auto-Configuration)** files come in. A PAC file is a JavaScript function that returns, per request, whether to connect directly or through a proxy. For example: connect directly to internal company sites, and use the Rama proxy for everything else.

## Proxies and VPNs

A VPN changes routing at a low level. It can route traffic past the proxy, or create a routing loop where the proxy's own upstream traffic is sent back to the proxy. Operating a proxy alongside a VPN means controlling the order: the proxy has to see the traffic before the VPN encrypts it.

## Transparent Interception

With **Transparent Proxying** the client is not configured for a proxy at all. The operating system redirects its traffic to the proxy, using mechanisms such as TPROXY on Linux or Network Extensions on macOS. Use it for clients without proxy settings, such as IoT devices, or for machines where you cannot change the application configuration. It covers all applications, but each platform has its own interception mechanism to set up.

This is also the option to use if the proxy has to work alongside other technologies such as VPNs.
