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

### Counted capture storage

H2 SETTINGS acknowledgements remain in literal captures but do not define new
structural groups. Older ACK-bearing groups remain readable with their original
counts and sampling identities. Old and new group IDs can coexist until the
older observations leave the 14-day retention window.

## User Agent Emulation

Rama provides comprehensive user-agent emulation capabilities across multiple layers:

### Multi-layer Emulation

1. **HTTP Layer**: Rama can emulate HTTP request headers, including User-Agent strings, Accept headers, and other browser-specific headers that websites use for fingerprinting.

2. **TLS Layer**: The TLS handshake contains significant fingerprinting information. Rama can emulate specific TLS client configurations, including cipher suites, extensions, and other TLS parameters that browsers expose.

3. **JavaScript Layer**: Rama provides basic information that can be used to emulate JavaScript environment properties like `navigator` object values, screen dimensions, and other Web API surface details that websites check.

### Technical Implementation

Rama implements user-agent emulation with profiles recorded from real browsers:

- [`UserAgentProfile`](https://ramaproxy.org/docs/rama/ua/profile/model/ua/struct.UserAgentProfile.html) - One browser identity and the HTTP/1.1, HTTP/2, HTTP/3, TLS and QUIC observations recorded for it, per kind of request (navigation, form, fetch, XHR, WebSocket);
- [`UserAgentDatabase`](https://ramaproxy.org/docs/rama/ua/profile/selection/database/struct.UserAgentDatabase.html) - The profiles to choose from. Files in the older one-row-per-browser format are converted when loaded.

These profiles are applied to outgoing requests using middleware services:

- [`ProfileEmulateLayer`](https://ramaproxy.org/docs/rama/ua/layer/emulate/struct.ProfileEmulateLayer.html) - Picks a profile for each request. It can follow the request's own `User-Agent` header, fall back to a looser match, and let requests through unchanged when nothing matches;
- [`ProfileEmulateHttpConnectModifier`](https://ramaproxy.org/docs/rama/ua/layer/emulate/struct.ProfileEmulateHttpConnectModifier.html) - Prepares the connection (TLS, HTTP/2 and QUIC settings) from the chosen profile;
- [`ProfileEmulateHttpRequestModifier`](https://ramaproxy.org/docs/rama/ua/layer/emulate/struct.ProfileEmulateHttpRequestModifier.html) - Rewrites the request headers in the recorded order. Use [`ProfileEmulateRelayRequestModifier`](https://ramaproxy.org/docs/rama/ua/layer/emulate/struct.ProfileEmulateRelayRequestModifier.html) when the connection was not opened by Rama, such as in a MITM proxy.

Anything that cannot be reproduced exactly is replaced by Rama's normal behaviour and listed in the request's `ProfilePreservationReport`.

Rama includes a database of pre-configured profiles for common browsers and platforms, making it easy to emulate specific user-agents without manual configuration. These profiles are generated from real browser fingerprints collected through Rama's fingerprinting service.

The emulation can be applied selectively based on the given input, allowing for sophisticated emulation strategies that can adapt to different scenarios or rotate between multiple profiles to avoid detection.

### HTTP/3 profile budgets

Browser profiles can advertise larger receive limits than ordinary clients.
Configure the HTTP/3 connector with
`Config::default().with_browser_emulation_limits()` to accept captured Chrome
SETTINGS: a 64 KiB QPACK table, 100 blocked streams and 256 KiB decoded field
sections. The connector rejects profiles above its configured budgets before
connecting; larger profiles require explicit application budgets. Observation
remains disabled unless requested. Reserved SETTINGS entries are generated for
each connection draw while their captured positions are retained.

### Embedded Profile Data

Rama includes an `embed-profiles` feature flag that, when enabled, embeds a collection of pre-configured user agent profiles directly into the binary. This eliminates the need for external profile files and ensures that Rama has immediate access to a variety of emulation profiles.

The embedded profiles are stored at [`rama-ua/src/profile/format/embed_profiles.json.zst`](https://github.com/plabayo/rama/blob/main/rama-ua/src/profile/format/embed_profiles.json.zst): a zstd-compressed, versioned profile archive exported from Rama's fingerprinting service with `rama ua export --embed`. Each entry retains the counted evidence of one profile:

- the browser and platform identity (User-Agent, client, version, platform and device)
- counted HTTP/1.1, HTTP/2 and HTTP/3 header and settings observations per request flow
- counted TLS ClientHellos over TCP and over QUIC
- QUIC transport parameters and first-flight structure, where the browser used HTTP/3

The embedded file only stores the collected observations. Rama recomputes the profiles from them when it loads the file, using the same date range the export was made for, so every load gives the same result. Inspect the data with `rama ua view rama-ua/src/profile/format/embed_profiles.json.zst --authorized`, and refresh it with `just update-embedded-profiles`.

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
