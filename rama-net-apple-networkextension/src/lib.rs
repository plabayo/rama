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
//! - Protecting a key with the Secure Enclave.
//!
//! None of these are available to a sysex using the System Keychain.
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
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

#[doc(hidden)]
pub mod ffi;

#[doc(hidden)]
#[macro_use]
mod macros;

pub mod process;
pub mod tproxy;

#[cfg(target_os = "macos")]
pub mod system_keychain;

mod tcp;
mod udp;

pub use self::{tcp::TcpFlow, udp::UdpFlow};
pub use crate::__transparent_proxy_ffi as transparent_proxy_ffi;

#[doc(hidden)]
pub use rama_core::bytes::Bytes as __RamaBytes;
#[doc(hidden)]
pub use rama_core::telemetry::tracing as __tracing;
