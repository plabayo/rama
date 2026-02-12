# 🦾 Operating Transparent Proxies

Operating a transparent proxy is a fundamental departure from the "social contract" of system proxies. Here, we move away from asking applications for cooperation and instead use the operating system’s kernel to forcibly redirect traffic.

This approach is the most robust way to ensure that every byte of traffic—even from "proxy-unaware" applications or universal devices—passes through your Rama instance.

## 1. Linux: The TPROXY Powerhouse

On Linux, transparent proxying is handled by the **Netfilter** framework. The preferred method is **TPROXY** because it allows your proxy to receive traffic on a local port while the kernel maintains the original destination IP and port in the socket metadata.

### How to Operate:

To get traffic into Rama, you need a combination of a routing rule and an `nftables` (or `iptables`) rule:

1. **Mark the packets:** Tell the firewall to intercept specific traffic (e.g., port 80/443) and assign it a "mark".
2. **Policy Routing:** Create a routing rule that sends any packet with that mark to the local loopback interface.
3. **The Rama Listener:** Configure your Rama (net) Socket to use the `IP_TRANSPARENT` socket option, which allows it to "claim" these hijacked packets.

* **Official Documentation:** [Linux Kernel TPROXY](https://www.kernel.org/doc/Documentation/networking/tproxy.txt)
* **Useful Tooling:** `nftables` is the modern standard for defining these rules. For advanced filtering based on the application owner, the **`xt_owner`** module allows you to redirect traffic based on the User ID (UID) of the process that created the packet.

## 2. macOS: Network Extensions

On macOS, Apple has deprecated traditional kernel extensions in favor of a much safer, user-space framework called **Network Extensions**.

### How to Operate:

You implement a subclass of **`NETransparentProxyProvider`**. Unlike Linux, where you manually manage firewall rules, macOS handles the "hooking" for you once your extension is active.

1. **Define Rules:** You provide the system with `NENetworkRule` objects. For example, you can tell macOS to "Capture all TCP traffic destined for any remote port 443".
2. **Flow Handling:** macOS hands your code an `NEAppProxyFlow`. Because this is a flow-based API, you don't have to worry about raw IP packets; you get a clean stream of data to pipe into a "Stream" Service.
3. **Identification:** To make smart filtering decisions, you often pair this with an **`NEFilterDataProvider`**. This allows you to inspect the "Audit Token" to see exactly which app (e.g., Slack vs. Safari) is generating the traffic.

* **Official Documentation:** [Apple Developer: Network Extension](https://developer.apple.com/documentation/networkextension)

## 3. Windows: Windows Filtering Platform (WFP)

Windows uses the **WFP**, a powerful set of API and system services that allow you to "plumb" the networking stack.

### How to Operate:

For a truly transparent experience that catches all apps, you typically need a **WFP Callout Driver**.

1. **ALE Layers:** You set filters at the **Application Layer Enforcement (ALE)** layers. These layers are hit exactly when an app tries to `connect()` or `bind()`.
2. **Connect Redirection:** Your driver tells WFP to "Redirect" the connection. Instead of the packet going to the internet, WFP silently points the socket at `127.0.0.1:[RAMA_PORT]`.
3. **Persistence:** Unlike Linux commands that disappear on reboot, WFP filters are persistent. You must manage the lifecycle of these filters carefully to ensure you don't "soft-brick" the machine’s internet if your proxy service stops.

* **Official Documentation:** [Microsoft: Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
* **Useful Tooling:** The **`AppId`** and **`UserId`** metadata provided at the ALE layer are essential for filtering "Work" traffic vs. "Personal" traffic.

## 4. Complementary Modules & Filtering

Operating a transparent proxy at scale usually requires more than just "grabbing" the traffic. You often need these auxiliary modules to make the system functional:

* **DNS Interception:** If you are redirecting port 443, you must also handle DNS. Most transparent setups redirect UDP/53 to a local DNS resolver (like `unbound` or a Rama-based DNS service) to prevent "DNS Leaking",
* **Conntrack (Connection Tracking):** On Linux, the `nf_conntrack` module is vital. It allows your proxy to remember the state of a connection so that return packets from the internet are correctly "de-proxied" back to the client.
* **BPF (Berkeley Packet Filter):** For ultra-high-performance filtering, **eBPF** on Linux can be used to drop or redirect packets before they even reach the standard firewall layers, significantly reducing CPU overhead for high-traffic gateways.

## Fail open Vs Fail closed

**Final Operational Note:** Transparent proxies are the most invasive form of proxying. When operating them, always implement a **"Bypass" or "Fail-Safe"** mechanism. If your Rama service crashes, your firewall rules should ideally be configured to either "fail open" (allowing direct internet) or "fail closed" (blocking all) depending on your security requirements.
