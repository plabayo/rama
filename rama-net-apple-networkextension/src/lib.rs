//! Apple Network Extension support for rama.
//!
//! > **Scope:** this crate has been developed and tested with **macOS System Extensions**
//! > as the primary target. Other use cases — macOS app extensions, iOS app extensions,
//! > and so on — may work but have not been tested and are not a current maintainer
//! > priority. If you have such a use case and run into issues, please
//! > [open a feature request on GitHub](https://github.com/plabayo/rama/issues/new).
//!
//! Official Apple documentation about the
//! Network Extension Framework can be consulted at:
//! <https://developer.apple.com/documentation/networkextension>.
//!
//! ## Tech Notes
//!
//! - [Network Extension Provider Packaging](https://developer.apple.com/forums/thread/800887)
//! - [TN3134: Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
//! - [TN3120: Expected use cases for Network Extension packet tunnel providers](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)
//! - [iOS memory limits](https://developer.apple.com/forums/thread/73148)
//!   - ~ 15 MiB for App/Dns proxy providers on iOS, no limit on MacOS
//! - [Exporting a Developer ID Network Extension](https://developer.apple.com/forums/thread/737894)
//! - [Debugging a Network Extension Provider](https://developer.apple.com/forums/thread/725805)
//!
//! ## NetworkExtension provider ordering
//!
//! When multiple NetworkExtension providers are active on a system, macOS
//! evaluates them in the following order. This is useful for reasoning about
//! how a transparent proxy provider built on top of this crate composes with
//! other on-system middle-boxes (other VPNs, content filters, DNS proxies,
//! etc.):
//!
//! 1. Per-app proxy
//! 2. Content filter
//! 3. Relays
//! 4. Transparent proxy *(this crate)*
//! 5. General VPN
//! 6. DNS proxy
//!
//! This ordering is descriptive — observed system behavior — not a normative
//! guarantee from Apple, and the implications for any specific deployment
//! depend on which provider types are active and what each is configured to
//! do.
//!
//! ### Stacked-provider attribution: the packet-filter blind spot
//!
//! When this crate's transparent proxy intercepts a flow it opens its own
//! egress `NWConnection` from the extension process. The egress packets that
//! `NWConnection` emits then traverse the rest of the on-system NE stack.
//! Two attribution paths exist:
//!
//! - Downstream **`NEAppProxyProvider`** (e.g. an enterprise proxy agent
//!   running on the same Mac): sees the egress flow as a flow object and
//!   reads its `NEFlowMetaData`. This crate stamps the original flow's
//!   metadata onto the egress `NWParameters` via
//!   `NEAppProxyFlow.setMetadata(_:)` (default behaviour, opt out via
//!   [`tproxy::NwEgressParameters::preserve_original_meta_data`]) so a
//!   downstream proxy sees the original app rather than the extension
//!   process.
//!
//! - Downstream **`NEFilterPacketProvider`** (e.g. an enterprise webfilter
//!   running on the same Mac): operates at L3 packets. It sees the
//!   *kernel socket's owning PID*, which is the extension process — there
//!   is no Apple API that propagates `NEFlowMetaData` (or any other
//!   per-flow attribution) to a packet-level filter. Per-process or
//!   per-bundle policy on a downstream packet filter therefore evaluates
//!   against the rama extension, not the original app.
//!
//! The deployment implication: stacked with a packet-level filter that
//! has per-process / per-bundle deny rules, this extension's egress is
//! treated as a single distinct process for that filter's policy. Either
//! allowlist the extension's signing identifier in the upstream filter,
//! or carve out the affected destinations in the rama handler's
//! passthrough policy. There is no rama-side fix; this is a
//! framework-level constraint.
//!
//! Below is relevant information communicated from some of the above sources.
//!
//! ## Terminology
//!
//! As clarified by Quinn "The Eskimo!" from Apple Developer Technical Support:
//!
//! > When talking about extensions on Apple platforms, it's important to get your terminology straight.
//! >
//! > - The application in which the extension is embedded is called the **container application**.
//! > - The **host application** is the application using the extension.
//! >
//! > In this case, the host application isn't actually an application, but rather the system itself.
//!
//! ## Communicating with Extensions
//!
//! With an app extension there are two communication options:
//!
//! - App-provider messages
//! - App groups
//!
//! App-provider messages are supported by NE directly. In the container app,
//! send a message to the provider by calling `sendProviderMessage(_:responseHandler:)`
//! method. In the appex, receive that message by overriding the
//! `handleAppMessage(_:completionHandler:) method.`
//!
//! > For transparent proxy support provided by this crate this is
//! > on the Rust (sysext) side as easy as implementing the
//! > `TransparentProxyHandler::handle_app_message` trait method.
//!
//! An appex can also implement inter-process communication (IPC)
//! using various system IPC primitives. Both the container app and the
//! appex claim access to the app group via the com.apple.security.application-groups entitlement.
//! They can then set up IPC using various APIs, as explain in the documentation for that entitlement.
//!
//! With a system extension the story is very different.
//! App-provider messages are supported, but they are rarely used. Rather,
//! most products use XPC for their communication. In the sysex,
//! publish a named XPC endpoint by setting the NEMachServiceName property in
//! its `Info.plist`. Listen for XPC connections
//! on that endpoint using the XPC API of your choice.
//!
//! Note For more information about the available XPC APIs, see [XPC Resources].
//!
//! In the container app, connect to that named XPC endpoint using the XPC Mach service name API.
//! For example, with NSXPCConnection, initialise the connection with `init(machServiceName:options:)`,
//! passing in the string from `NEMachServiceName`. To maximise security, set the .privileged flag.
//!
//! Note [XPC Resources] has a link to a post that explains why this flag is important.
//!
//! > Rama offers XPC support via the `rama-net-apple-xpc` crate,
//! > which is also available as `rama::net::apple::xpc` when enabling the
//! > `net-apple-xpc` feature on Apple vendor targets.
//!
//! If the container app is sandboxed — necessary if you ship on the Mac App Store —
//! then the endpoint name must be prefixed by an app group ID that’s accessible to that app,
//! lest the App Sandbox deny the connection. See the app groups documentation for the specifics.
//!
//! When implementing an XPC listener in your sysex, keep in mind that:
//!
//! > Your sysex’s named XPC endpoint is registered in the global namespace.
//! > Any process on the system can open a connection to it `[1]`.
//! > Your XPC listener must be prepared for this. If you want to restrict connections
//! > to just your container app, see XPC Resources for a link to a post that explains how to do that.
//! > Even if you restrict access in that way, it’s still possible for multiple
//! > instances of your container app to be running simultaneously,
//! > each with its own connection to your sysex. This happens, for example,
//! > if there are multiple GUI users logged in and different users run your container app.
//! > Design your XPC protocol with this in mind.
//! > Your sysex only gets one named XPC endpoint, and thus one XPC listener.
//! > If your sysex includes multiple NE providers, take that into account when
//! > you design your XPC protocol.
//! >
//! > `[1]` Assuming that connection isn’t blocked by some other mechanism, like the App Sandbox.
//!
//! ### Wiring up XPC for a sysex NE provider in practice
//!
//! The notes above are accurate but skip the practical setup. The recipe below is
//! distilled from the working transparent-proxy example shipped in this repository
//! ([`ffi/apple/examples/transparent_proxy`]) — follow it and you should not need
//! to repeat the trial-and-error we went through.
//!
//! What you need:
//!
//! 1. **An app group ID, shared by the container app and the sysex.** This is the
//!    *prefix* macOS / launchd will accept as a Mach service name from a sandboxed
//!    or NE-style process — without it, `xpc_connection_create_mach_service` (or
//!    `NSXPCConnection`) traffic is silently dropped, and `launchd` will refuse
//!    to register the listener inside the sysex.
//!    - **macOS:** the legacy `<TEAM_ID>.<bundle-id-prefix>` form is enough
//!      (e.g. `ADPG6C355H.org.example.tproxy`). It does not need to start with
//!      `group.` on macOS, and does not have to be created in the Apple Developer
//!      portal for local developer signing — Xcode automatic signing accepts
//!      `<AppIdentifierPrefix><bundle-id>` directly.
//!    - **iOS** (and macOS in distribution / App Store contexts where you cannot
//!      rely on the legacy form): create a real App Group identifier in the
//!      Apple Developer portal under
//!      *Certificates, Identifiers & Profiles → Identifiers → App Groups*. These
//!      identifiers must start with `group.` (e.g. `group.org.example.tproxy`).
//!      Enable the *App Groups* capability on **both** App IDs (container and
//!      provider) and add the identifier to each.
//!
//! 2. **The same app group ID listed in the entitlements of both binaries.**
//!    Both the container app and the sysex must declare it under
//!    `com.apple.security.application-groups`:
//!
//!    ```xml
//!    <key>com.apple.security.application-groups</key>
//!    <array>
//!        <string>$(APP_GROUP_ID)</string>
//!    </array>
//!    ```
//!
//!    If only one side declares it, `launchd` will allow the listener to come up
//!    but the peer will not be able to reach it: the connection appears to
//!    succeed (XPC is lazy) and then fails on the first send.
//!
//! 3. **`NEMachServiceName` declared inside the `NetworkExtension` dict of the
//!    sysex's `Info.plist`, prefixed by the app group ID.** This is the single
//!    name that `sysextd` uses to generate the launchd `MachServices` entry for
//!    the extension. The prefix-must-match-an-app-group rule applies here too —
//!    pick any unique suffix you like, but the value must start with the app
//!    group ID:
//!
//!    ```xml
//!    <key>NetworkExtension</key>
//!    <dict>
//!        <key>NEProviderClasses</key>
//!        <dict>
//!            <key>com.apple.networkextension.app-proxy</key>
//!            <string>YourModule.YourProviderClass</string>
//!        </dict>
//!        <key>NEMachServiceName</key>
//!        <string>$(APP_GROUP_ID).provider</string>
//!    </dict>
//!    ```
//!
//!    The container app should read the **same** value (do not re-derive it from
//!    `Bundle.main.bundleIdentifier`, the two namespaces are different). The
//!    transparent-proxy example exposes it as a `ProviderMachServiceName` key in
//!    the container's own `Info.plist` so both bundles share one source of truth
//!    via the `APP_GROUP_ID` build setting.
//!
//! 4. **A reinstall after any change to `NEMachServiceName`.** `sysextd` only reads
//!    `Info.plist` when the extension is (re)activated, and it only writes the
//!    `MachServices` entry into the generated launchd job at that moment.
//!    Editing `NEMachServiceName` in place and rebuilding is *not* enough; you
//!    must trigger a deactivate + reactivate cycle (in the example this is
//!    `just install-tproxy-dev-reset-profile`). Confirm afterwards with:
//!
//!    ```sh
//!    sudo launchctl print system/<sysex-bundle-id> | grep -A 5 -i machservices
//!    ```
//!
//!    A correctly registered listener shows up as e.g.:
//!
//!    ```text
//!    MachServices = {
//!        ADPG6C355H.org.example.tproxy.provider => 0
//!    }
//!    ```
//!
//!    If the `MachServices` block is empty or missing, the prefix does not match
//!    a declared app group, the entitlements were stripped during signing, or
//!    `sysextd` has a stale registration — see the example's *Troubleshooting*
//!    section for the full decision tree.
//!
//! 5. **A handshake-friendly XPC protocol.** `XpcConnection` on the client side
//!    is lazy, so peer-requirement and prefix mismatches surface as
//!    `XpcConnectionError::PeerRequirementFailed` (or a silent disconnect) on the
//!    first send, *not* at construction. Send something cheap and idempotent
//!    early (a "ping" / `updateSettings` style call) so misconfigurations fail
//!    loudly during development rather than the first time a real workload runs.
//!
//! On the Rust side the only thing you need to know is that the same
//! `NEMachServiceName` string is what you pass to
//! `rama::net::apple::xpc::XpcListenerConfig::new(service_name)` — there is no
//! separate registration step. As long as the launchd `MachServices` entry above
//! exists, `XpcListener::bind(...)` will succeed and the container app's
//! `xpc_connection_create_mach_service(<same name>)` will reach it. The
//! transparent-proxy example carries the service name from the container app to
//! the sysex through `NETunnelProviderProtocol.providerConfiguration`, which is
//! the simplest pattern when you want the sysex to learn its own name without
//! re-reading `Info.plist`.
//!
//! [`ffi/apple/examples/transparent_proxy`]: https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy
//!
//! ## Inter-provider Communication
//!
//! A sysex can include multiple types of NE providers. For example, a single sysex
//! might include a content filter and a DNS proxy provider. In that case the system
//! instantiates all of the NE providers in the same sysex process.
//! These instances can communicate without using IPC, for example,
//! by storing shared state in global variables (with suitable locking, of course).
//!
//! It’s also possible for a single container app to contain multiple sysexen,
//! each including a single NE provider. In that case the system instantiates
//! the NE providers in separate processes, one for each sysex.
//! If these providers need to communicate, they have to use IPC.
//!
//! In the appex case, the system instantiates each provider in its own process.
//! If two providers need to communicate, they have to use IPC.
//!
//! ## Managing Secrets
//!
//! An appex runs in a user context and thus can store secrets, like VPN credentials,
//! in the keychain. On macOS this includes both the data protection keychain
//! and the file-based keychain. It can also use a keychain access group to
//! share secrets with its container app. See Sharing access to keychain items
//! among a collection of apps.
//!
//! Note If you’re not familiar with the different types of keychain available on macOS,
//! see [TN3137 On Mac keychain APIs and implementations][TN3137].
//!
//! A sysex runs in the global context and thus doesn’t have access to user state.
//! It also doesn’t have access to the data protection keychain. It must use the file-based keychain,
//! and specifically the System keychain. That means there’s no good way to share secrets
//! with the container app.
//!
//! Instead, do all your keychain operations in the sysex.
//! If the container app needs to work with a secret, have it pass that request
//! to the sysex via IPC. For example, if the user wants to use a digital
//! identity as a VPN credential, have the container app get the `PKCS#12`
//! data and password and then pass that to the sysex so that it can import
//! the digital identity into the keychain.
//!
//! > This crate offers system keychain support via
//! > the `system_keychain` module (only available on macOS).
//!
//! Some keychain features require the data protection keychain, including:
//!
//! - iCloud Keychain. See the kSecAttrSynchronizable attribute.
//! - Protecting an item with biometrics (Touch ID and Face ID).
//! - Protecting a keychain item with the Secure Enclave.
//!
//! None of these are available to a sysex using the System Keychain.
//!
//! However, a sysex *can* still use the Secure Enclave directly via Apple
//! CryptoKit's `SecureEnclave.P256.KeyAgreement.PrivateKey`, which does not
//! go through the Data Protection Keychain. The
//! `system_keychain::secure_enclave` submodule wraps that path: mint a key
//! with `kSecAttrAccessibleAlways` accessibility (the only class that works
//! before login in a sysex daemon), persist its opaque blob anywhere, and
//! use it to encrypt arbitrary bytes. The Rust API is backed by the
//! `RamaAppleSecureEnclave` Swift product shipped from this repository's
//! `Package.swift`; the consumer's final binary must link it. See
//! <https://developer.apple.com/forums/thread/804612> for the underlying
//! Apple guidance.
//!
//! [XPC Resources]: https://developer.apple.com/forums/thread/708877
//! [TN3137]: https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
//!
//! ## Learn More
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg(target_vendor = "apple")]
#![cfg_attr(test, allow(clippy::float_cmp))]

#[doc(hidden)]
pub mod ffi;

#[doc(hidden)]
#[macro_use]
mod macros;

pub mod process;
pub mod tproxy;

#[cfg(target_os = "macos")]
#[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
pub mod system_keychain;

mod nw_tcp_stream;
mod nw_udp_socket;
mod tcp;
mod udp;

pub use self::{
    nw_tcp_stream::NwTcpStream, nw_udp_socket::NwUdpSocket, tcp::TcpFlow, udp::UdpFlow,
};
pub use crate::__transparent_proxy_ffi as transparent_proxy_ffi;

#[doc(hidden)]
pub mod __private {
    pub use rama_core::bytes::Bytes;
    pub use rama_core::telemetry::tracing;
}
