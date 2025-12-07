# 👤 User Agent

> On the Web, a user agent is a software agent responsible for retrieving and
> facilitating end-user interaction with Web content. This includes all web browsers,
> such as Google Chrome and Safari, some email clients, standalone download managers
> like youtube-dl, and other command-line utilities like cURL.
>
> — [Wikipedia](https://en.wikipedia.org/wiki/User_agent).

Rama offers support to:

* Parse User Agent Header Strings: for the purpose of identifying the User Agent that created the incoming http request
* Emulate User Agents: for the purpose of distoring incoming proxy requests (see [Distortion Proxies](../proxies/distort.md))

More Information:

* ⛰️ The source code for User Agent (UA) support can be found at <https://github.com/plabayo/rama/tree/main/rama-ua/src>;
* 📖 and the edge documentation for it can be found at <https://ramaproxy.org/docs/rama/ua/index.html>.

## Fingerprinting

Modern web stacks have often fingerprinting in place, usually by use of third party services, for the purpose of ad revenue and anti-bot measurements.

These fingerprints are layered and are generated on:

- the network layers: mostly IP, HTTP and TLS;
- the scripting layer: javascript engine + web API interaction;
- the [Web API](https://developer.mozilla.org/en-US/docs/Web/API) surface: compatibility, user agent- and host information.

By use of [upstream proxies](https://ramaproxy.org/docs/rama/proxy/trait.ProxyDB.html) and [distort proxies](../proxies/distort.md) you can effectively emulate the more common User Agents (UA), desired physical location and user profile.

Rama's UA emulation capabilities are powered by [its automated fingerprinting service](https://github.com/plabayo/rama/blob/main/rama-fp/browserstack/main.py) that is publicly available at <https://fp.ramaproxy.org/>. This infrastructure is sponsored by 💖 <https://fly.io/> and 💖 [BrowserStack](https://browserstack.com).

> 🔁 <https://echo.ramaproxy.org/> is another service publicly exposed.
> In contrast to the Fingerprinting Service it is aimed at developers
> and allows you to send any http request you wish in order to get an insight
> on the Tls Info and Http Request Info the server receives
> from you when making that request.
>
> ```bash
> curl -XPOST 'https://echo.ramaproxy.org/foo?bar=baz' \
>   -H 'x-magic: 42' --data 'whatever forever'
> ```
>
> Feel free to make use of while crafting distorted http requests,
> but please do so with moderation. In case you have ideas on how to improve
> the service, please let us know [by opening an issue](https://github.com/plabayo/rama/issues).

## User Agent Emulation

Rama provides comprehensive user-agent emulation capabilities across multiple layers:

### Multi-layer Emulation

1. **HTTP Layer**: Rama can emulate HTTP request headers, including User-Agent strings, Accept headers, and other browser-specific headers that websites use for fingerprinting.

2. **TLS Layer**: The TLS handshake contains significant fingerprinting information. Rama can emulate specific TLS client configurations, including cipher suites, extensions, and other TLS parameters that browsers expose.

3. **JavaScript Layer**: Rama provides basic information that can be used to emulate JavaScript environment properties like `navigator` object values, screen dimensions, and other Web API surface details that websites check.

### Technical Implementation

Rama implements user-agent emulation through a profile-based system:

- [`UserAgentProfile`](https://ramaproxy.org/docs/rama/ua/profile/struct.UserAgentProfile.html) - The main profile container that includes:
  - [`HttpProfile`](https://ramaproxy.org/docs/rama/ua/profile/struct.HttpProfile.html) - HTTP headers and settings for different request types (navigate, form, XHR, fetch)
  - [`TlsProfile`](https://ramaproxy.org/docs/rama/ua/profile/struct.TlsProfile.html) - TLS client configuration including cipher suites and extensions
  - [`JsProfile`](https://ramaproxy.org/docs/rama/ua/profile/struct.JsProfile.html) - JavaScript environment properties

These profiles can be applied to outgoing requests using middleware services:

- [`UserAgentEmulateService`](https://ramaproxy.org/docs/rama/ua/layer/emulate/struct.UserAgentEmulateService.html) - A service that applies the emulation profile to requests;
- [`UserAgentEmulateHttpConnectModifier`](https://ramaproxy.org/docs/rama/ua/layer/emulate/struct.UserAgentEmulateHttpConnectModifier.html) - Provides connector the the Http(s) connector with required emulation context (e.g. tls profile, h2 settings, ...);
- [`UserAgentEmulateHttpRequestModifier`](https://ramaproxy.org/docs/rama/ua/layer/emulate/struct.UserAgentEmulateHttpRequestModifier.html) - Modifies HTTP requests based on the profile, input and asociated dynamic state.

Rama includes a database of pre-configured profiles for common browsers and platforms, making it easy to emulate specific user-agents without manual configuration. These profiles are generated from real browser fingerprints collected through Rama's fingerprinting service.

The emulation can be applied selectively based on the given input, allowing for sophisticated emulation strategies that can adapt to different scenarios or rotate between multiple profiles to avoid detection.

### Embedded Profile Data

Rama includes an `embed-profiles` feature flag that, when enabled, embeds a collection of pre-configured user agent profiles directly into the binary. This eliminates the need for external profile files and ensures that Rama has immediate access to a variety of emulation profiles.

The embedded profiles are stored in the source file at [`rama-ua/src/profile/embed_profiles.json`](https://raw.githubusercontent.com/plabayo/rama/refs/heads/main/rama-ua/src/profile/embed_profiles.json) and include detailed fingerprinting data for various browsers and platforms. This JSON file contains:

- Multiple browser profiles (Chrome, Firefox, Safari, Edge, etc.)
- Different versions of each browser
- Various operating system combinations (Windows, macOS, Linux, Android, iOS)
- Complete HTTP header sets for different request types (navigate, form, XHR, fetch)
- TLS configuration details including cipher suites and extensions
- JavaScript environment properties that match real browser implementations

These embedded profiles correspond directly to the profile structure described above, with each entry containing the full `UserAgentProfile` data including HTTP, TLS, and JavaScript components. The profiles are generated from real browser fingerprints collected through Rama's fingerprinting service, ensuring they accurately reflect actual browser behavior.

Using the `embed-profiles` feature allows applications to immediately start with realistic browser emulation without any additional setup, making it ideal for applications that need to maintain a low profile or operate in environments where external files might be difficult to manage.

To enable this feature, simply include the `embed-profiles` feature when adding Rama to your project.

> 💡 At [Plabayo](https://plabayo.tech), we support the principle that
> [information wants to be free](https://en.wikipedia.org/wiki/Information_wants_to_be_free),
> provided it is pursued ethically and within the bounds of applicable law.
>
> We do not endorse or support any malicious use of our technology.
> We advocate for the programmatic retrieval of publicly available data
> only when conducted responsibly — in a manner that is respectful,
> does not impose an undue burden on servers, and avoids causing
> disruption, harm, or degradation to third-party services.
