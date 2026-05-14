Installed 5 packages in 7ms
Fetch Standard












[![WHATWG](https://resources.whatwg.org/logo-fetch.svg)](https://whatwg.org/ "https://whatwg.org/")


Fetch
=====

Living Standard — Last Updated 8 May 2026

Participate:: [GitHub whatwg/fetch](https://github.com/whatwg/fetch "https://github.com/whatwg/fetch") ([new issue](https://github.com/whatwg/fetch/issues/new/choose "https://github.com/whatwg/fetch/issues/new/choose"), [open issues](https://github.com/whatwg/fetch/issues "https://github.com/whatwg/fetch/issues")): [Chat on Matrix](https://whatwg.org/chat "https://whatwg.org/chat") Commits:: [GitHub whatwg/fetch/commits](https://github.com/whatwg/fetch/commits "https://github.com/whatwg/fetch/commits"): [Snapshot as of this commit](/commit-snapshots/301650c6d9ee932f126d6598262966242eb3d838/ "/commit-snapshots/301650c6d9ee932f126d6598262966242eb3d838/"): [@fetchstandard](https://twitter.com/fetchstandard "https://twitter.com/fetchstandard") Tests:: [web-platform-tests fetch/](https://github.com/web-platform-tests/wpt/tree/master/fetch "https://github.com/web-platform-tests/wpt/tree/master/fetch") ([ongoing work](https://github.com/web-platform-tests/wpt/labels/fetch "https://github.com/web-platform-tests/wpt/labels/fetch")) Translations (non-normative):: [日本語](https://triple-underscore.github.io/Fetch-ja.html "https://triple-underscore.github.io/Fetch-ja.html"): [简体中文](https://htmlspecs.com/fetch/ "https://htmlspecs.com/fetch/"): [한국어](https://ko.htmlspecs.com/fetch/ "https://ko.htmlspecs.com/fetch/")

Abstract
--------

The Fetch standard defines requests, responses, and the process that binds them: fetching.

Table of Contents
-----------------

1. [Goals](#goals "#goals")- [1 Preface](#preface "#preface")- [2 Infrastructure](#infrastructure "#infrastructure")
       1. [2.1 URL](#url "#url")- [2.2 HTTP](#http "#http")
            1. [2.2.1 Methods](#methods "#methods")- [2.2.2 Headers](#terminology-headers "#terminology-headers")- [2.2.3 Statuses](#statuses "#statuses")- [2.2.4 Bodies](#bodies "#bodies")- [2.2.5 Requests](#requests "#requests")- [2.2.6 Responses](#responses "#responses")- [2.2.7 Miscellaneous](#miscellaneous "#miscellaneous")- [2.3 Authentication entries](#authentication-entries "#authentication-entries")- [2.4 Fetch groups](#fetch-groups "#fetch-groups")- [2.5 Resolving domains](#resolving-domains "#resolving-domains")- [2.6 Connections](#connections "#connections")- [2.7 Network partition keys](#network-partition-keys "#network-partition-keys")- [2.8 HTTP cache partitions](#http-cache-partitions "#http-cache-partitions")- [2.9 Port blocking](#port-blocking "#port-blocking")- [2.10 Should
                            response to request be blocked due to its MIME type?](#should-response-to-request-be-blocked-due-to-mime-type? "#should-response-to-request-be-blocked-due-to-mime-type?")- [3 HTTP extensions](#http-extensions "#http-extensions")
         1. [3.1 Cookies](#cookies "#cookies")
            1. [3.1.1 ``Cookie`` header](#cookie-header "#cookie-header")- [3.1.2 ``Set-Cookie`` header](#set-cookie-header "#set-cookie-header")- [3.1.3 Cookie infrastructure](#cookie-infrastructure "#cookie-infrastructure")- [3.2 ``Origin`` header](#origin-header "#origin-header")- [3.3 CORS protocol](#http-cors-protocol "#http-cors-protocol")
                1. [3.3.1 General](#general "#general")- [3.3.2 HTTP requests](#http-requests "#http-requests")- [3.3.3 HTTP responses](#http-responses "#http-responses")- [3.3.4 HTTP new-header syntax](#http-new-header-syntax "#http-new-header-syntax")- [3.3.5 CORS protocol and credentials](#cors-protocol-and-credentials "#cors-protocol-and-credentials")- [3.3.6 Examples](#cors-protocol-examples "#cors-protocol-examples")- [3.3.7 CORS protocol exceptions](#cors-protocol-exceptions "#cors-protocol-exceptions")- [3.4 ``Content-Length`` header](#content-length-header "#content-length-header")- [3.5 ``Content-Type`` header](#content-type-header "#content-type-header")- [3.6 ``X-Content-Type-Options`` header](#x-content-type-options-header "#x-content-type-options-header")
                      1. [3.6.1 Should
                         response to request be blocked due to nosniff?](#should-response-to-request-be-blocked-due-to-nosniff? "#should-response-to-request-be-blocked-due-to-nosniff?")- [3.7 ``Cross-Origin-Resource-Policy`` header](#cross-origin-resource-policy-header "#cross-origin-resource-policy-header")- [3.8 ``Sec-Purpose`` header](#sec-purpose-header "#sec-purpose-header")- [4 Fetching](#fetching "#fetching")
           1. [4.1 Main fetch](#main-fetch "#main-fetch")- [4.2 Override fetch](#override-fetch "#override-fetch")- [4.3 Scheme fetch](#scheme-fetch "#scheme-fetch")- [4.4 HTTP fetch](#http-fetch "#http-fetch")- [4.5 HTTP-redirect fetch](#http-redirect-fetch "#http-redirect-fetch")- [4.6 HTTP-network-or-cache fetch](#http-network-or-cache-fetch "#http-network-or-cache-fetch")- [4.7 HTTP-network fetch](#http-network-fetch "#http-network-fetch")- [4.8 CORS-preflight fetch](#cors-preflight-fetch "#cors-preflight-fetch")- [4.9 CORS-preflight cache](#cors-preflight-cache "#cors-preflight-cache")- [4.10 CORS check](#cors-check "#cors-check")- [4.11 TAO check](#tao-check "#tao-check")- [4.12 Deferred fetching](#deferred-fetch "#deferred-fetch")
                                    1. [4.12.1 Deferred fetching quota](#deferred-fetch-quota "#deferred-fetch-quota")- [5 Fetch API](#fetch-api "#fetch-api")
             1. [5.1 Headers class](#headers-class "#headers-class")- [5.2 BodyInit unions](#bodyinit-unions "#bodyinit-unions")- [5.3 Body mixin](#body-mixin "#body-mixin")- [5.4 Request class](#request-class "#request-class")- [5.5 Response class](#response-class "#response-class")- [5.6 Fetch methods](#fetch-method "#fetch-method")- [5.7 Garbage collection](#garbage-collection "#garbage-collection")- [6 `data:` URLs](#data-urls "#data-urls")- [Background reading](#background-reading "#background-reading")
                 1. [HTTP header layer division](#http-header-layer-division "#http-header-layer-division")- [Atomic HTTP redirect handling](#atomic-http-redirect-handling "#atomic-http-redirect-handling")- [Basic safe CORS protocol setup](#basic-safe-cors-protocol-setup "#basic-safe-cors-protocol-setup")- [CORS protocol and HTTP caches](#cors-protocol-and-http-caches "#cors-protocol-and-http-caches")- [WebSockets](#websocket-protocol "#websocket-protocol")- [Using fetch in other standards](#fetch-elsewhere "#fetch-elsewhere")
                   1. [Setting up a request](#fetch-elsewhere-request "#fetch-elsewhere-request")- [Invoking fetch and processing responses](#fetch-elsewhere-fetch "#fetch-elsewhere-fetch")- [Manipulating an ongoing fetch](#fetch-elsewhere-ongoing "#fetch-elsewhere-ongoing")- [Acknowledgments](#acknowledgments "#acknowledgments")- [Intellectual property rights](#ipr "#ipr")- [Index](#index "#index")
                         1. [Terms defined by this specification](#index-defined-here "#index-defined-here")- [Terms defined by reference](#index-defined-elsewhere "#index-defined-elsewhere")- [References](#references "#references")
                           1. [Normative References](#normative "#normative")- [Non-Normative References](#informative "#informative")- [IDL Index](#idl-index "#idl-index")


Goals
-----

The goal is to unify fetching across the web platform and provide consistent handling of
everything that involves, including:

* URL schemes* Redirects* Cross-origin semantics* CSP [[CSP]](#biblio-csp "Content Security Policy Level 3")* Fetch Metadata [[FETCH-METADATA]](#biblio-fetch-metadata "Fetch Metadata Request Headers")* Service workers [[SW]](#biblio-sw "Service Workers Nightly")* Mixed Content [[MIX]](#biblio-mix "Mixed Content")* Upgrade Insecure Requests [[UPGRADE-INSECURE-REQUESTS]](#biblio-upgrade-insecure-requests "Upgrade Insecure Requests")* ``Referer`` [[REFERRER]](#biblio-referrer "Referrer Policy")

To do so it also supersedes the HTTP `[`Origin`](#http-origin "#http-origin")` header semantics
originally defined in The Web Origin Concept. [[ORIGIN]](#biblio-origin "The Web Origin Concept")

1. Preface
----------

At a high level, fetching a resource is a fairly simple operation. A request goes in, a
response comes out. The details of that operation are
however quite involved and used to not be written down carefully and differ from one API
to the next.

Numerous APIs provide the ability to fetch a resource, e.g. HTML’s `img` and
`script` element, CSS' `cursor` and `list-style-image`,
the `navigator.sendBeacon()` and `self.importScripts()` JavaScript
APIs. The Fetch Standard provides a unified architecture for these features so they are
all consistent when it comes to various aspects of fetching, such as redirects and the
CORS protocol.

The Fetch Standard also defines the [`fetch()`](#dom-global-fetch "#dom-global-fetch") JavaScript API, which
exposes most of the networking functionality at a fairly low level of abstraction.

2. Infrastructure
-----------------

This specification depends on the Infra Standard. [[INFRA]](#biblio-infra "Infra Standard")

This specification uses terminology from ABNF, Encoding,
HTML, HTTP, MIME Sniffing, Streams,
URL, Web IDL, WebSockets, and WebTransport.
[[ABNF]](#biblio-abnf "Augmented BNF for Syntax Specifications: ABNF")
[[ENCODING]](#biblio-encoding "Encoding Standard")
[[HTML]](#biblio-html "HTML Standard")
[[HTTP]](#biblio-http "HTTP Semantics")
[[MIMESNIFF]](#biblio-mimesniff "MIME Sniffing Standard")
[[STREAMS]](#biblio-streams "Streams Standard")
[[URL]](#biblio-url "URL Standard")
[[WEBIDL]](#biblio-webidl "Web IDL Standard")
[[WEBSOCKETS]](#biblio-websockets "WebSockets Standard")
[[WEBTRANSPORT]](#biblio-webtransport "WebTransport")

ABNF means ABNF as augmented by HTTP (in particular the addition of `#`)
and RFC 7405. [[RFC7405]](#biblio-rfc7405 "Case-Sensitive String Support in ABNF")

---

Credentials are HTTP cookies, TLS client certificates, and [authentication entries](#authentication-entry "#authentication-entry") (for HTTP authentication). [[COOKIES]](#biblio-cookies "Cookies: HTTP State Management Mechanism")
[[TLS]](#biblio-tls "The Transport Layer Security (TLS) Protocol Version 1.3") [[HTTP]](#biblio-http "HTTP Semantics")

---

A fetch params is a [struct](https://infra.spec.whatwg.org/#struct "https://infra.spec.whatwg.org/#struct") used as a bookkeeping detail by the
[fetch](#concept-fetch "#concept-fetch") algorithm. It has the following [items](https://infra.spec.whatwg.org/#struct-item "https://infra.spec.whatwg.org/#struct-item"):

request: A [request](#concept-request "#concept-request"). process request body chunk length (default null) process request end-of-body (default null) process early hints response (default null) process response (default null) process response end-of-body (default null) process response consume body (default null): Null or an algorithm. task destination (default null): Null, a [global object](https://html.spec.whatwg.org/multipage/webappapis.html#global-object "https://html.spec.whatwg.org/multipage/webappapis.html#global-object"), or a [parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue"). cross-origin isolated capability (default false): A boolean. controller (default a new [fetch controller](#fetch-controller "#fetch-controller")): A [fetch controller](#fetch-controller "#fetch-controller"). timing info: A [fetch timing info](#fetch-timing-info "#fetch-timing-info"). preloaded response candidate (default null): Null, "`pending`", or a [response](#concept-response "#concept-response").

A fetch controller is a [struct](https://infra.spec.whatwg.org/#struct "https://infra.spec.whatwg.org/#struct") used to enable callers of
[fetch](#concept-fetch "#concept-fetch") to perform certain operations on it after it has started. It has the following
[items](https://infra.spec.whatwg.org/#struct-item "https://infra.spec.whatwg.org/#struct-item"):

state (default "`ongoing`"): "`ongoing`", "`terminated`", or "`aborted`" full timing info (default null): Null or a [fetch timing info](#fetch-timing-info "#fetch-timing-info"). report timing steps (default null): Null or an algorithm accepting a [global object](https://html.spec.whatwg.org/multipage/webappapis.html#global-object "https://html.spec.whatwg.org/multipage/webappapis.html#global-object"). serialized abort reason (default null): Null or a [Record](https://tc39.es/ecma262/#sec-list-and-record-specification-type "https://tc39.es/ecma262/#sec-list-and-record-specification-type") (result of [StructuredSerialize](https://html.spec.whatwg.org/multipage/structured-data.html#structuredserialize "https://html.spec.whatwg.org/multipage/structured-data.html#structuredserialize")). next manual redirect steps (default null): Null or an algorithm accepting nothing.

To report timing for a
[fetch controller](#fetch-controller "#fetch-controller") controller given a [global object](https://html.spec.whatwg.org/multipage/webappapis.html#global-object "https://html.spec.whatwg.org/multipage/webappapis.html#global-object") global:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): controller’s
   [report timing steps](#fetch-controller-report-timing-steps "#fetch-controller-report-timing-steps") is non-null.

   - Call controller’s [report timing steps](#fetch-controller-report-timing-steps "#fetch-controller-report-timing-steps") with
     global.

To process the next manual redirect for a
[fetch controller](#fetch-controller "#fetch-controller") controller:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): controller’s
   [next manual redirect steps](#fetch-controller-next-manual-redirect-steps "#fetch-controller-next-manual-redirect-steps") is non-null.

   - Call controller’s [next manual redirect steps](#fetch-controller-next-manual-redirect-steps "#fetch-controller-next-manual-redirect-steps").

To
extract full timing info
given a [fetch controller](#fetch-controller "#fetch-controller") controller:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): controller’s [full timing info](#fetch-controller-full-timing-info "#fetch-controller-full-timing-info")
   is non-null.

   - Return controller’s [full timing info](#fetch-controller-full-timing-info "#fetch-controller-full-timing-info").

To abort a [fetch controller](#fetch-controller "#fetch-controller")
controller with an optional error:

1. Set controller’s [state](#fetch-controller-state "#fetch-controller-state") to "`aborted`".

   - Let fallbackError be an "`AbortError`" `DOMException`.

     - Set error to fallbackError if it is not given.

       - Let serializedError be [StructuredSerialize](https://html.spec.whatwg.org/multipage/structured-data.html#structuredserialize "https://html.spec.whatwg.org/multipage/structured-data.html#structuredserialize")(error).
         If that threw an exception, catch it, and let serializedError be
         [StructuredSerialize](https://html.spec.whatwg.org/multipage/structured-data.html#structuredserialize "https://html.spec.whatwg.org/multipage/structured-data.html#structuredserialize")(fallbackError).

         - Set controller’s [serialized abort reason](#fetch-controller-serialized-abort-reason "#fetch-controller-serialized-abort-reason") to
           serializedError.

To deserialize a serialized abort reason, given null or a [Record](https://tc39.es/ecma262/#sec-list-and-record-specification-type "https://tc39.es/ecma262/#sec-list-and-record-specification-type")
abortReason and a [realm](https://tc39.es/ecma262/#realm "https://tc39.es/ecma262/#realm") realm:

1. Let fallbackError be an "`AbortError`" `DOMException`.

   - Let deserializedError be fallbackError.

     - If abortReason is non-null, then set deserializedError to
       [StructuredDeserialize](https://html.spec.whatwg.org/multipage/structured-data.html#structureddeserialize "https://html.spec.whatwg.org/multipage/structured-data.html#structureddeserialize")(abortReason, realm). If that threw an exception or
       returned undefined, then set deserializedError to fallbackError.

       - Return deserializedError.

To terminate a [fetch controller](#fetch-controller "#fetch-controller")
controller, set controller’s [state](#fetch-controller-state "#fetch-controller-state") to
"`terminated`".

A [fetch params](#fetch-params "#fetch-params") fetchParams is aborted if
its [controller](#fetch-params-controller "#fetch-params-controller")’s [state](#fetch-controller-state "#fetch-controller-state") is
"`aborted`".

A [fetch params](#fetch-params "#fetch-params") fetchParams is canceled if
its [controller](#fetch-params-controller "#fetch-params-controller")’s [state](#fetch-controller-state "#fetch-controller-state") is
"`aborted`" or "`terminated`".

A fetch timing info is a [struct](https://infra.spec.whatwg.org/#struct "https://infra.spec.whatwg.org/#struct") used to maintain timing
information needed by Resource Timing and Navigation Timing. It has the
following [items](https://infra.spec.whatwg.org/#struct-item "https://infra.spec.whatwg.org/#struct-item"): [[RESOURCE-TIMING]](#biblio-resource-timing "Resource Timing") [[NAVIGATION-TIMING]](#biblio-navigation-timing "Navigation Timing")

start time (default 0) redirect start time (default 0) redirect end time (default 0) post-redirect start time (default 0) final service worker start time (default 0) final network-request start time (default 0) first interim network-response start time (default 0) final network-response start time (default 0) end time (default 0): A `DOMHighResTimeStamp`. final connection timing info (default null): Null or a [connection timing info](#connection-timing-info "#connection-timing-info"). service worker timing info (default null): Null or a [service worker timing info](https://w3c.github.io/ServiceWorker/#service-worker-timing-info "https://w3c.github.io/ServiceWorker/#service-worker-timing-info"). server-timing headers (default « »): A [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of strings. render-blocking (default false): A boolean.

A response body info is a [struct](https://infra.spec.whatwg.org/#struct "https://infra.spec.whatwg.org/#struct") used to maintain
information needed by Resource Timing and Navigation Timing. It has the
following [items](https://infra.spec.whatwg.org/#struct-item "https://infra.spec.whatwg.org/#struct-item"): [[RESOURCE-TIMING]](#biblio-resource-timing "Resource Timing") [[NAVIGATION-TIMING]](#biblio-navigation-timing "Navigation Timing")

encoded size (default 0) decoded size (default 0): A number. content type (default the empty string): An [ASCII string](https://infra.spec.whatwg.org/#ascii-string "https://infra.spec.whatwg.org/#ascii-string"). content encoding (default the empty string): An [ASCII string](https://infra.spec.whatwg.org/#ascii-string "https://infra.spec.whatwg.org/#ascii-string").

To
create an opaque timing info,
given a [fetch timing info](#fetch-timing-info "#fetch-timing-info") timingInfo, return a new
[fetch timing info](#fetch-timing-info "#fetch-timing-info") whose [start time](#fetch-timing-info-start-time "#fetch-timing-info-start-time") and
[post-redirect start time](#fetch-timing-info-post-redirect-start-time "#fetch-timing-info-post-redirect-start-time") are timingInfo’s
[start time](#fetch-timing-info-start-time "#fetch-timing-info-start-time").

To queue a fetch task, given an algorithm algorithm, a
[global object](https://html.spec.whatwg.org/multipage/webappapis.html#global-object "https://html.spec.whatwg.org/multipage/webappapis.html#global-object") or a [parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue") taskDestination, run these
steps:

1. If taskDestination is a [parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue"), then
   [enqueue](https://html.spec.whatwg.org/multipage/infrastructure.html#enqueue-the-following-steps "https://html.spec.whatwg.org/multipage/infrastructure.html#enqueue-the-following-steps") algorithm to
   taskDestination.

   - Otherwise, [queue a global task](https://html.spec.whatwg.org/multipage/webappapis.html#queue-a-global-task "https://html.spec.whatwg.org/multipage/webappapis.html#queue-a-global-task") on the [networking task source](https://html.spec.whatwg.org/multipage/webappapis.html#networking-task-source "https://html.spec.whatwg.org/multipage/webappapis.html#networking-task-source") with
     taskDestination and algorithm.

To check if the [environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object") environment
is offline:

* If the user agent assumes it does not have internet connectivity, then return true.

  * Return environment’s [WebDriver BiDi network is offline](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-network-is-offline "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-network-is-offline").

---

To serialize an integer, represent it as a string of the shortest possible decimal
number.

This will be replaced by a more descriptive algorithm in Infra. See
[infra/201](https://github.com/whatwg/infra/issues/201 "https://github.com/whatwg/infra/issues/201").

### 2.1. URL

A local scheme is "`about`", "`blob`", or
"`data`".

A [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") is local if its [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is a
[local scheme](#local-scheme "#local-scheme").

This definition is also used by Referrer Policy. [[REFERRER]](#biblio-referrer "Referrer Policy")

An HTTP(S) scheme is "`http`" or
"`https`".

A fetch scheme is "`about`", "`blob`",
"`data`", "`file`", or an [HTTP(S) scheme](#http-scheme "#http-scheme").

[HTTP(S) scheme](#http-scheme "#http-scheme") and [fetch scheme](#fetch-scheme "#fetch-scheme") are also used by HTML.
[[HTML]](#biblio-html "HTML Standard")

### 2.2. HTTP

While [fetching](#concept-fetch "#concept-fetch") encompasses more than just HTTP, it
borrows a number of concepts from HTTP and applies these to resources obtained via other
means (e.g., `data` URLs).

An HTTP tab or space is U+0009 TAB or U+0020 SPACE.

HTTP whitespace is U+000A LF, U+000D CR, or an [HTTP tab or space](#http-tab-or-space "#http-tab-or-space").

[HTTP whitespace](#http-whitespace "#http-whitespace") is only useful for specific constructs that are reused outside
the context of HTTP headers (e.g., [MIME types](https://mimesniff.spec.whatwg.org/#mime-type "https://mimesniff.spec.whatwg.org/#mime-type")). For HTTP header values, using
[HTTP tab or space](#http-tab-or-space "#http-tab-or-space") is preferred, and outside that context [ASCII whitespace](https://infra.spec.whatwg.org/#ascii-whitespace "https://infra.spec.whatwg.org/#ascii-whitespace") is
preferred. Unlike [ASCII whitespace](https://infra.spec.whatwg.org/#ascii-whitespace "https://infra.spec.whatwg.org/#ascii-whitespace") this excludes U+000C FF.

An HTTP newline byte is 0x0A (LF) or 0x0D (CR).

An HTTP tab or space byte is 0x09 (HT) or 0x20 (SP).

An HTTP whitespace byte is an [HTTP newline byte](#http-newline-byte "#http-newline-byte") or
[HTTP tab or space byte](#http-tab-or-space-byte "#http-tab-or-space-byte").

To
collect an HTTP quoted string
from a [string](https://infra.spec.whatwg.org/#string "https://infra.spec.whatwg.org/#string") input, given a [position variable](https://infra.spec.whatwg.org/#string-position-variable "https://infra.spec.whatwg.org/#string-position-variable") position
and an optional boolean extract-value (default false):

1. Let positionStart be position.

   - Let value be the empty string.

     - [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): the [code point](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") at position within input is
       U+0022 (").

       - Advance position by 1.

         - While true:

           1. Append the result of [collecting a sequence of code points](https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points "https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points") that are not U+0022 (")
              or U+005C (\) from input, given position, to value.

              - If position is past the end of input, then
                [break](https://infra.spec.whatwg.org/#iteration-break "https://infra.spec.whatwg.org/#iteration-break").

                - Let quoteOrBackslash be the [code point](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") at position within
                  input.

                  - Advance position by 1.

                    - If quoteOrBackslash is U+005C (\), then:

                      1. If position is past the end of input, then append U+005C (\) to
                         value and [break](https://infra.spec.whatwg.org/#iteration-break "https://infra.spec.whatwg.org/#iteration-break").

                         - Append the [code point](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") at position within input to
                           value.

                           - Advance position by 1.- Otherwise:

                        1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): quoteOrBackslash is U+0022 (").

                           - [Break](https://infra.spec.whatwg.org/#iteration-break "https://infra.spec.whatwg.org/#iteration-break").- If extract-value is true, then return value.

             - Return the [code points](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") from positionStart to position,
               inclusive, within input.

|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Input Output Output with extract-value set to true Final [position variable](https://infra.spec.whatwg.org/#string-position-variable "https://infra.spec.whatwg.org/#string-position-variable") value| "`"\`" "`"\`" "`\`" 2|  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | | "`"Hello" World`" "`"Hello"`" "`Hello`" 7|  |  |  |  | | --- | --- | --- | --- | | "`"Hello \\ World\""`" "`"Hello \\ World\""`" "`Hello \ World"`" 18 | | | | | | | | | | | | | | | |

The [position variable](https://infra.spec.whatwg.org/#string-position-variable "https://infra.spec.whatwg.org/#string-position-variable") always starts at 0 in these examples.

#### 2.2.1. Methods

A method is a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") that matches the
[method](https://httpwg.org/specs/rfc9110.html#method.overview "https://httpwg.org/specs/rfc9110.html#method.overview") token production.

A CORS-safelisted method is a
[method](#concept-method "#concept-method") that is ``GET``,
``HEAD``, or ``POST``.

A forbidden method is a [method](#concept-method "#concept-method") that is a
[byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for ``CONNECT``,
``TRACE``, or ``TRACK``.
[[HTTPVERBSEC1]](#biblio-httpverbsec1 "Multiple vendors' web servers enable HTTP TRACE method by default."), [[HTTPVERBSEC2]](#biblio-httpverbsec2 "Microsoft Internet Information Server (IIS) vulnerable to cross-site scripting via HTTP TRACK method."), [[HTTPVERBSEC3]](#biblio-httpverbsec3 "HTTP proxy default configurations allow arbitrary TCP connections.")

To normalize a
[method](#concept-method "#concept-method"), if it is a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive")
match for ``DELETE``, ``GET``,
``HEAD``, ``OPTIONS``, ``POST``, or
``PUT``, [byte-uppercase](https://infra.spec.whatwg.org/#byte-uppercase "https://infra.spec.whatwg.org/#byte-uppercase") it.

[Normalization](#concept-method-normalize "#concept-method-normalize") is done for backwards compatibility and
consistency across APIs as [methods](#concept-method "#concept-method") are actually "case-sensitive".

Using ``patch`` is highly likely to result in a
``405 Method Not Allowed``. ``PATCH`` is much more likely to
succeed.

There are no restrictions on [methods](#concept-method "#concept-method"). ``CHICKEN`` is perfectly
acceptable (and not a misspelling of ``CHECKIN``). Other than those that are
[normalized](#concept-method-normalize "#concept-method-normalize") there are no casing restrictions either.
``Egg`` or ``eGg`` would be fine, though uppercase is encouraged for
consistency.

#### 2.2.2. Headers

HTTP generally refers to a header as a "field" or "header field". The web platform
uses the more colloquial term "header". [[HTTP]](#biblio-http "HTTP Semantics")

A header list is a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of zero or more
[headers](#concept-header "#concept-header"). It is initially « ».

A [header list](#concept-header-list "#concept-header-list") is essentially a specialized multimap: an ordered list of
key-value pairs with potentially duplicate keys. Since headers other than ``Set-Cookie``
are always combined when exposed to client-side JavaScript, implementations could choose a more
efficient representation, as long as they also support an associated data structure for
``Set-Cookie`` headers.

To
get a structured field value
given a [header name](#header-name "#header-name") name and a string type from a
[header list](#concept-header-list "#concept-header-list") list, run these steps. They return null or a
[structured field value](https://httpwg.org/specs/rfc9651.html#rfc.section.2 "https://httpwg.org/specs/rfc9651.html#rfc.section.2").

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): type is one of "`dictionary`",
   "`list`", or "`item`".

   - Let value be the result of [getting](#concept-header-list-get "#concept-header-list-get") name from
     list.

     - If value is null, then return null.

       - Let result be the result of [parsing structured fields](https://httpwg.org/specs/rfc9651.html#text-parse "https://httpwg.org/specs/rfc9651.html#text-parse") with
         input\_string set to value and header\_type set to
         type.

         - If parsing failed, then return null.

           - Return result.

[Get a structured field value](#concept-header-list-get-structured-header "#concept-header-list-get-structured-header") intentionally does not distinguish between a
[header](#concept-header "#concept-header") not being present and its [value](#concept-header-value "#concept-header-value") failing to parse as a
[structured field value](https://httpwg.org/specs/rfc9651.html#rfc.section.2 "https://httpwg.org/specs/rfc9651.html#rfc.section.2"). This ensures uniform processing across the web platform.

To
set a structured field value
given a [tuple](https://infra.spec.whatwg.org/#tuple "https://infra.spec.whatwg.org/#tuple") ([header name](#header-name "#header-name") name, [structured field value](https://httpwg.org/specs/rfc9651.html#rfc.section.2 "https://httpwg.org/specs/rfc9651.html#rfc.section.2")
structuredValue), in a [header list](#concept-header-list "#concept-header-list") list:

1. Let serializedValue be the result of executing the
   [serializing structured fields](https://httpwg.org/specs/rfc9651.html#text-serialize "https://httpwg.org/specs/rfc9651.html#text-serialize") algorithm on structuredValue.

   - [Set](#concept-header-list-set "#concept-header-list-set") (name, serializedValue) in
     list.

[Structured field values](https://httpwg.org/specs/rfc9651.html#rfc.section.2 "https://httpwg.org/specs/rfc9651.html#rfc.section.2") are defined as objects which HTTP can (eventually)
serialize in interesting and efficient ways. For the moment, Fetch only supports
[header values](#header-value "#header-value") as [byte sequences](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"), which means that these objects can be set in
[header lists](#concept-header-list "#concept-header-list") only via serialization, and they can be obtained from
[header lists](#concept-header-list "#concept-header-list") only by parsing. In the future the fact that they are objects might be
preserved end-to-end. [[RFC9651]](#biblio-rfc9651 "Structured Field Values for HTTP")

---

A [header list](#concept-header-list "#concept-header-list") list
contains a
[header name](#header-name "#header-name") name if list [contains](https://infra.spec.whatwg.org/#list-contain "https://infra.spec.whatwg.org/#list-contain") a
[header](#concept-header "#concept-header") whose [name](#concept-header-name "#concept-header-name") is a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for
name.

To get a [header name](#header-name "#header-name")
name from a [header list](#concept-header-list "#concept-header-list") list, run these steps. They return null
or a [header value](#header-value "#header-value").

1. If list [does not contain](#header-list-contains "#header-list-contains") name, then return
   null.

   - Return the [values](#concept-header-value "#concept-header-value") of all [headers](#concept-header "#concept-header") in list
     whose [name](#concept-header-name "#concept-header-name") is a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for name, separated
     from each other by 0x2C 0x20, in order.

To
get, decode, and split
a [header name](#header-name "#header-name") name from [header list](#concept-header-list "#concept-header-list") list, run these
steps. They return null or a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of [strings](https://infra.spec.whatwg.org/#string "https://infra.spec.whatwg.org/#string").

1. Let value be the result of [getting](#concept-header-list-get "#concept-header-list-get") name from
   list.

   - If value is null, then return null.

     - Return the result of [getting, decoding, and splitting](#header-value-get-decode-and-split "#header-value-get-decode-and-split")
       value.

This is how [get, decode, and split](#concept-header-list-get-decode-split "#concept-header-list-get-decode-split") functions in practice with
``A`` as the name argument:

|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Headers (as on the network) Output|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | ``` A: nosniff, ```   « "`nosniff`", "" »| ``` A: nosniff B: sniff A: ```  | ``` A: B: sniff ```   « "" »|  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | ``` B: sniff ```   null|  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | ``` A: text/html;", x/x ```   « "`text/html;", x/x`" »| ``` A: text/html;" A: x/x ```  | ``` A: x/x;test="hi",y/y ```   « "`x/x;test="hi"`", "`y/y`" »| ``` A: x/x;test="hi" C: **bingo** A: y/y ```  | ``` A: x / x,,,1 ```   « "`x / x`", "", "", "`1`" »| ``` A: x / x A: , A: 1 ```  | ``` A: "1,2", 3 ```   « "`"1,2"`", "`3`" »| ``` A: "1,2" D: 4 A: 3 ``` | | | | | | | | | | | | | | | | | | | | |

To
get, decode, and split
a [header value](#header-value "#header-value") value, run these steps. They return a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of
[strings](https://infra.spec.whatwg.org/#string "https://infra.spec.whatwg.org/#string").

1. Let input be the result of [isomorphic decoding](https://infra.spec.whatwg.org/#isomorphic-decode "https://infra.spec.whatwg.org/#isomorphic-decode") value.

   - Let position be a [position variable](https://infra.spec.whatwg.org/#string-position-variable "https://infra.spec.whatwg.org/#string-position-variable") for input,
     initially pointing at the start of input.

     - Let values be a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of [strings](https://infra.spec.whatwg.org/#string "https://infra.spec.whatwg.org/#string"), initially « ».

       - Let temporaryValue be the empty string.

         - While true:

           1. Append the result of [collecting a sequence of code points](https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points "https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points") that are not U+0022 (") or
              U+002C (,) from input, given position, to temporaryValue.

              The result might be the empty string.

              - If position is not past the end of input and the
                [code point](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") at position within input is U+0022 ("):

                1. Append the result of [collecting an HTTP quoted string](#collect-an-http-quoted-string "#collect-an-http-quoted-string") from input,
                   given position, to temporaryValue.

                   - If position is not past the end of input, then
                     [continue](https://infra.spec.whatwg.org/#iteration-continue "https://infra.spec.whatwg.org/#iteration-continue").- Remove all [HTTP tab or space](#http-tab-or-space "#http-tab-or-space") from the start and end of temporaryValue.

                  - [Append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") temporaryValue to values.

                    - Set temporaryValue to the empty string.

                      - If position is past the end of input, then return values.

                        - [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): the [code point](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") at position within
                          input is U+002C (,).

                          - Advance position by 1.

Except for blessed call sites, the algorithm directly above is not to be invoked
directly. Use [get, decode, and split](#concept-header-list-get-decode-split "#concept-header-list-get-decode-split") instead.

To append a [header](#concept-header "#concept-header")
(name, value) to a [header list](#concept-header-list "#concept-header-list") list:

1. If list [contains](#header-list-contains "#header-list-contains") name, then set name
   to the first such [header](#concept-header "#concept-header")’s [name](#concept-header-name "#concept-header-name").

   This reuses the casing of the [name](#concept-header-name "#concept-header-name") of the [header](#concept-header "#concept-header")
   already in list, if any. If there are multiple matched [headers](#concept-header "#concept-header") their
   [names](#concept-header-name "#concept-header-name") will all be identical.

   - [Append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") (name, value) to list.

To delete a
[header name](#header-name "#header-name") name from a [header list](#concept-header-list "#concept-header-list") list,
[remove](https://infra.spec.whatwg.org/#list-remove "https://infra.spec.whatwg.org/#list-remove") all [headers](#concept-header "#concept-header") whose [name](#concept-header-name "#concept-header-name") is a
[byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for name from list.

To set a [header](#concept-header "#concept-header")
(name, value) in a [header list](#concept-header-list "#concept-header-list") list:

1. If list [contains](#header-list-contains "#header-list-contains") name, then set the
   [value](#concept-header-value "#concept-header-value") of the first such [header](#concept-header "#concept-header") to value and
   [remove](https://infra.spec.whatwg.org/#list-remove "https://infra.spec.whatwg.org/#list-remove") the others.

   - Otherwise, [append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") (name, value) to list.

To combine a
[header](#concept-header "#concept-header") (name, value) in a [header list](#concept-header-list "#concept-header-list")
list:

1. If list [contains](#header-list-contains "#header-list-contains") name, then set the
   [value](#concept-header-value "#concept-header-value") of the first such [header](#concept-header "#concept-header") to its [value](#concept-header-value "#concept-header-value"),
   followed by 0x2C 0x20, followed by value.

   - Otherwise, [append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") (name, value) to list.

[Combine](#concept-header-list-combine "#concept-header-list-combine") is used by `XMLHttpRequest` and the
[WebSocket protocol handshake](https://websockets.spec.whatwg.org/#concept-websocket-establish "https://websockets.spec.whatwg.org/#concept-websocket-establish").

To convert header names to a sorted-lowercase set, given a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of
[names](#concept-header-name "#concept-header-name") headerNames, run these steps. They return an
[ordered set](https://infra.spec.whatwg.org/#ordered-set "https://infra.spec.whatwg.org/#ordered-set") of [header names](#header-name "#header-name").

1. Let headerNamesSet be a new [ordered set](https://infra.spec.whatwg.org/#ordered-set "https://infra.spec.whatwg.org/#ordered-set").

   - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") name of headerNames, [append](https://infra.spec.whatwg.org/#set-append "https://infra.spec.whatwg.org/#set-append")
     the result of [byte-lowercasing](https://infra.spec.whatwg.org/#byte-lowercase "https://infra.spec.whatwg.org/#byte-lowercase") name to
     headerNamesSet.

     - Return the result of [sorting](https://infra.spec.whatwg.org/#list-sort-in-ascending-order "https://infra.spec.whatwg.org/#list-sort-in-ascending-order") headerNamesSet in ascending order
       with [byte less than](https://infra.spec.whatwg.org/#byte-less-than "https://infra.spec.whatwg.org/#byte-less-than").

To sort and combine a
[header list](#concept-header-list "#concept-header-list") list, run these steps. They return a [header list](#concept-header-list "#concept-header-list").

1. Let headers be a [header list](#concept-header-list "#concept-header-list").

   - Let names be the result of
     [convert header names to a sorted-lowercase set](#convert-header-names-to-a-sorted-lowercase-set "#convert-header-names-to-a-sorted-lowercase-set") with all the [names](#concept-header-name "#concept-header-name")
     of the [headers](#concept-header "#concept-header") in list.

     - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") name of names:

       1. If name is ``set-cookie``, then:

          1. Let values be a list of all [values](#concept-header-value "#concept-header-value") of
             [headers](#concept-header "#concept-header") in list whose [name](#concept-header-name "#concept-header-name") is a
             [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for name, in order.

             - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") value of values:

               1. [Append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") (name, value) to headers.- Otherwise:

            1. Let value be the result of [getting](#concept-header-list-get "#concept-header-list-get") name
               from list.

               - [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): value is non-null.

                 - [Append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") (name, value) to headers.- Return headers.

---

A header is a [tuple](https://infra.spec.whatwg.org/#tuple "https://infra.spec.whatwg.org/#tuple") that consists of a
name (a [header name](#header-name "#header-name")) and
value (a [header value](#header-value "#header-value")).

A header name is a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") that matches the
[field-name](https://httpwg.org/specs/rfc9110.html#fields.names "https://httpwg.org/specs/rfc9110.html#fields.names") token production.

A header value is a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") that matches the following
conditions:

* Has no leading or trailing [HTTP tab or space bytes](#http-tab-or-space-byte "#http-tab-or-space-byte").

  * Contains no 0x00 (NUL) or [HTTP newline bytes](#http-newline-byte "#http-newline-byte").

The definition of [header value](#header-value "#header-value") is not defined in terms of the
[field-value](https://httpwg.org/specs/rfc9110.html#fields.values "https://httpwg.org/specs/rfc9110.html#fields.values") token production as it is
[not compatible with deployed content](https://github.com/httpwg/http-core/issues/215 "field-value value space").

To normalize a
[byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") potentialValue, remove any leading and trailing
[HTTP whitespace bytes](#http-whitespace-byte "#http-whitespace-byte") from potentialValue.

---

To determine whether a [header](#concept-header "#concept-header") (name, value)
is a CORS-safelisted request-header, run these steps:

1. If value’s [length](https://infra.spec.whatwg.org/#byte-sequence-length "https://infra.spec.whatwg.org/#byte-sequence-length") is greater than 128, then return
   false.

   - [Byte-lowercase](https://infra.spec.whatwg.org/#byte-lowercase "https://infra.spec.whatwg.org/#byte-lowercase") name and switch on the result:

     ``accept``: If value contains a [CORS-unsafe request-header byte](#cors-unsafe-request-header-byte "#cors-unsafe-request-header-byte"), then return false. ``accept-language`` ``content-language``: If value contains a byte that is not in the range 0x30 (0) to 0x39 (9), inclusive, is not in the range 0x41 (A) to 0x5A (Z), inclusive, is not in the range 0x61 (a) to 0x7A (z), inclusive, and is not 0x20 (SP), 0x2A (\*), 0x2C (,), 0x2D (-), 0x2E (.), 0x3B (;), or 0x3D (=), then return false. ``content-type``: 1. If value contains a [CORS-unsafe request-header byte](#cors-unsafe-request-header-byte "#cors-unsafe-request-header-byte"), then return false. - Let mimeType be the result of [parsing](https://mimesniff.spec.whatwg.org/#parse-a-mime-type "https://mimesniff.spec.whatwg.org/#parse-a-mime-type") the result of [isomorphic decoding](https://infra.spec.whatwg.org/#isomorphic-decode "https://infra.spec.whatwg.org/#isomorphic-decode") value. - If mimeType is failure, then return false. - If mimeType’s [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence "https://mimesniff.spec.whatwg.org/#mime-type-essence") is not "`application/x-www-form-urlencoded`", "`multipart/form-data`", or "`text/plain`", then return false. This intentionally does not use [extract a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type") as that algorithm is rather forgiving and servers are not expected to implement it. If [extract a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type") were used the following request would not result in a CORS preflight and a naïve parser on the server might treat the request body as JSON: ``` fetch("https://victim.example/naïve-endpoint", { method: "POST", headers: [ ["Content-Type", "application/json"], ["Content-Type", "text/plain"] ], credentials: "include", body: JSON.stringify(exerciseForTheReader) }); ``` ``range``: 1. Let rangeValue be the result of [parsing a single range header value](#simple-range-header-value "#simple-range-header-value") given value and false. - If rangeValue is failure, then return false. - If rangeValue[0] is null, then return false. As web browsers have historically not emitted ranges such as ``bytes=-500`` this algorithm does not safelist them. Otherwise: Return false.

     - Return true.

There are limited exceptions to the ``Content-Type`` header safelist, as
documented in [CORS protocol exceptions](#cors-protocol-exceptions "#cors-protocol-exceptions").

A CORS-unsafe request-header byte is a byte byte for which one of the
following is true:

* byte is less than 0x20 and is not 0x09 HT

  * byte is 0x22 ("), 0x28 (left parenthesis), 0x29 (right parenthesis), 0x3A (:),
    0x3C (<), 0x3E (>), 0x3F (?), 0x40 (@), 0x5B ([), 0x5C (\), 0x5D (]), 0x7B ({), 0x7D (}), or
    0x7F DEL.

The CORS-unsafe request-header names, given a [header list](#concept-header-list "#concept-header-list")
headers, are determined as follows:

1. Let unsafeNames be a new [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list").

   - Let potentiallyUnsafeNames be a new [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list").

     - Let safelistValueSize be 0.

       - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") header of headers:

         1. If header is not a [CORS-safelisted request-header](#cors-safelisted-request-header "#cors-safelisted-request-header"), then
            [append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") header’s [name](#concept-header-name "#concept-header-name") to unsafeNames.

            - Otherwise, [append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") header’s [name](#concept-header-name "#concept-header-name") to
              potentiallyUnsafeNames and increase safelistValueSize by
              header’s [value](#concept-header-value "#concept-header-value")’s [length](https://infra.spec.whatwg.org/#byte-sequence-length "https://infra.spec.whatwg.org/#byte-sequence-length").- If safelistValueSize is greater than 1024, then [for each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate")
           name of potentiallyUnsafeNames, [append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") name to
           unsafeNames.

           - Return the result of [convert header names to a sorted-lowercase set](#convert-header-names-to-a-sorted-lowercase-set "#convert-header-names-to-a-sorted-lowercase-set") with
             unsafeNames.

A CORS non-wildcard request-header name is a [header name](#header-name "#header-name") that is a
[byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for ``Authorization``.

A privileged no-CORS request-header name is a [header name](#header-name "#header-name") that is
a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for one of

* ``Range``.

These are headers that can be set by privileged APIs, and will be preserved if their associated
request object is copied, but will be removed if the request is modified by unprivileged APIs.

``Range`` headers are commonly used by [downloads](https://html.spec.whatwg.org/multipage/links.html#downloading-hyperlinks "https://html.spec.whatwg.org/multipage/links.html#downloading-hyperlinks")
and [media fetches](https://html.spec.whatwg.org/multipage/media.html#concept-media-load-resource "https://html.spec.whatwg.org/multipage/media.html#concept-media-load-resource").

A helper is provided to [add a range header](#concept-request-add-range-header "#concept-request-add-range-header") to a particular request.

A CORS-safelisted response-header name, given a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of
[header names](#header-name "#header-name") list, is a [header name](#header-name "#header-name") that is a
[byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for one of

* ``Cache-Control``* ``Content-Language``* ``Content-Length``* ``Content-Type``* ``Expires``* ``Last-Modified``* ``Pragma``* Any [item](https://infra.spec.whatwg.org/#list-item "https://infra.spec.whatwg.org/#list-item") in list that is not a
                [forbidden response-header name](#forbidden-response-header-name "#forbidden-response-header-name").

A no-CORS-safelisted request-header name is a [header name](#header-name "#header-name") that
is a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for one of

* ``Accept``* ``Accept-Language``* ``Content-Language``* ``Content-Type``

To determine whether a [header](#concept-header "#concept-header") (name, value) is a
no-CORS-safelisted request-header, run these steps:

1. If name is not a [no-CORS-safelisted request-header name](#no-cors-safelisted-request-header-name "#no-cors-safelisted-request-header-name"), then return
   false.

   - Return whether (name, value) is a
     [CORS-safelisted request-header](#cors-safelisted-request-header "#cors-safelisted-request-header").

A [header](#concept-header "#concept-header") (name, value) is
forbidden request-header if these steps return true:

1. If name is a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for one of:

   * ``Accept-Charset``* ``Accept-Encoding``* `[`Access-Control-Request-Headers`](#http-access-control-request-headers "#http-access-control-request-headers")`* `[`Access-Control-Request-Method`](#http-access-control-request-method "#http-access-control-request-method")`* ``Connection``* ``Content-Length``* ``Cookie``* ``Cookie2``* ``Date``* ``DNT``* ``Expect``* ``Host``* ``Keep-Alive``* `[`Origin`](#http-origin "#http-origin")`* ``Referer``* ``Set-Cookie``* ``TE``* ``Trailer``* ``Transfer-Encoding``* ``Upgrade``* ``Via``

   then return true.

   - If name when [byte-lowercased](https://infra.spec.whatwg.org/#byte-lowercase "https://infra.spec.whatwg.org/#byte-lowercase") [starts with](https://infra.spec.whatwg.org/#byte-sequence-starts-with "https://infra.spec.whatwg.org/#byte-sequence-starts-with")
     ``proxy-`` or ``sec-``, then return true.

     - If name is a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for one of:

       * ``X-HTTP-Method``* ``X-HTTP-Method-Override``* ``X-Method-Override``

       then:

       1. Let parsedValues be the result of
          [getting, decoding, and splitting](#header-value-get-decode-and-split "#header-value-get-decode-and-split") value.

          - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") method of parsedValues: if the
            [isomorphic encoding](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode") of method is a [forbidden method](#forbidden-method "#forbidden-method"), then return true.- Return false.

These are forbidden so the user agent remains in full control over them.

[Header names](#header-name "#header-name") starting with ``Sec-`` are reserved to allow new
[headers](#concept-header "#concept-header") to be minted that are safe from APIs using [fetch](#concept-fetch "#concept-fetch") that allow
control over [headers](#concept-header "#concept-header") by developers, such as `XMLHttpRequest`. [[XHR]](#biblio-xhr "XMLHttpRequest Standard")

The ``Set-Cookie`` header is semantically a response header, so it is not useful on
requests. Because ``Set-Cookie`` headers cannot be combined, they require more complex
handling in the `Headers` object. It is forbidden here to avoid leaking this complexity into
requests.

A forbidden response-header name is a [header name](#header-name "#header-name") that is a
[byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for one of:

* ``Set-Cookie``* ``Set-Cookie2``

A request-body-header name is a [header name](#header-name "#header-name") that is a
[byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for one of:

* ``Content-Encoding``* ``Content-Language``* ``Content-Location``* ``Content-Type``

---

To extract header values
given a [header](#concept-header "#concept-header") header, run these steps:

1. If parsing header’s [value](#concept-header-value "#concept-header-value"), per the [ABNF](#abnf "#abnf") for
   header’s [name](#concept-header-name "#concept-header-name"), fails, then return failure.

   - Return one or more [values](#concept-header-value "#concept-header-value") resulting from parsing header’s
     [value](#concept-header-value "#concept-header-value"), per the [ABNF](#abnf "#abnf") for header’s [name](#concept-header-name "#concept-header-name").

To
extract header list values
given a [header name](#header-name "#header-name") name and a [header list](#concept-header-list "#concept-header-list") list,
run these steps:

1. If list [does not contain](#header-list-contains "#header-list-contains") name, then return
   null.

   - If the [ABNF](#abnf "#abnf") for name allows a single [header](#concept-header "#concept-header") and list
     [contains](#header-list-contains "#header-list-contains") more than one, then return failure.

     If different error handling is needed, extract the desired [header](#concept-header "#concept-header")
     first.

     - Let values be an empty [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list").

       - For each [header](#concept-header "#concept-header") header list
         [contains](#header-list-contains "#header-list-contains") whose [name](#concept-header-name "#concept-header-name") is name:

         1. Let extract be the result of [extracting header values](#extract-header-values "#extract-header-values") from
            header.

            - If extract is failure, then return failure.

              - Append each [value](#concept-header-value "#concept-header-value") in extract, in order, to values.- Return values.

To build a content range given an integer rangeStart, an integer
rangeEnd, and an integer fullLength, run these steps:

1. Let contentRange be ``bytes` `.

   - Append rangeStart, [serialized](#serialize-an-integer "#serialize-an-integer") and
     [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode"), to contentRange.

     - Append 0x2D (-) to contentRange.

       - Append rangeEnd, [serialized](#serialize-an-integer "#serialize-an-integer") and
         [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode") to contentRange.

         - Append 0x2F (/) to contentRange.

           - Append fullLength, [serialized](#serialize-an-integer "#serialize-an-integer") and
             [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode") to contentRange.

             - Return contentRange.

To parse a single range header value from a
[byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") value and a boolean allowWhitespace, run these steps:

1. Let data be the [isomorphic decoding](https://infra.spec.whatwg.org/#isomorphic-decode "https://infra.spec.whatwg.org/#isomorphic-decode") of value.

   - If data does not [start with](https://infra.spec.whatwg.org/#string-starts-with "https://infra.spec.whatwg.org/#string-starts-with") "`bytes`", then return
     failure.

     - Let position be a [position variable](https://infra.spec.whatwg.org/#string-position-variable "https://infra.spec.whatwg.org/#string-position-variable") for data, initially
       pointing at the 5th [code point](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") of data.

       - If allowWhitespace is true, [collect a sequence of code points](https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points "https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points") that are
         [HTTP tab or space](#http-tab-or-space "#http-tab-or-space"), from data given position.

         - If the [code point](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") at position within data is not U+003D (=),
           then return failure.

           - Advance position by 1.

             - If allowWhitespace is true, [collect a sequence of code points](https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points "https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points") that are
               [HTTP tab or space](#http-tab-or-space "#http-tab-or-space"), from data given position.

               - Let rangeStart be the result of [collecting a sequence of code points](https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points "https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points") that
                 are [ASCII digits](https://infra.spec.whatwg.org/#ascii-digit "https://infra.spec.whatwg.org/#ascii-digit"), from data given position.

                 - Let rangeStartValue be rangeStart, interpreted as decimal number, if
                   rangeStart is not the empty string; otherwise null.

                   - If allowWhitespace is true, [collect a sequence of code points](https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points "https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points") that are
                     [HTTP tab or space](#http-tab-or-space "#http-tab-or-space"), from data given position.

                     - If the [code point](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") at position within data is not U+002D (-),
                       then return failure.

                       - Advance position by 1.

                         - If allowWhitespace is true, [collect a sequence of code points](https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points "https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points") that are
                           [HTTP tab or space](#http-tab-or-space "#http-tab-or-space"), from data given position.

                           - Let rangeEnd be the result of [collecting a sequence of code points](https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points "https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points") that
                             are [ASCII digits](https://infra.spec.whatwg.org/#ascii-digit "https://infra.spec.whatwg.org/#ascii-digit"), from data given position.

                             - Let rangeEndValue be rangeEnd, interpreted as decimal number, if
                               rangeEnd is not the empty string; otherwise null.

                               - If position is not past the end of data, then return failure.

                                 - If rangeEndValue and rangeStartValue are null, then return failure.

                                   - If rangeStartValue and rangeEndValue are numbers, and
                                     rangeStartValue is greater than rangeEndValue, then return failure.

                                     - Return (rangeStartValue, rangeEndValue).

                                       The range end or start can be omitted, e.g., ``bytes=0-`` or
                                       ``bytes=-500`` are valid ranges.

[Parse a single range header value](#simple-range-header-value "#simple-range-header-value") succeeds for a subset of allowed range header
values, but it is the most common form used by user agents when requesting media or resuming
downloads. This format of range header value can be set using [add a range header](#concept-request-add-range-header "#concept-request-add-range-header").

---

A default ``User-Agent`` value is an
[implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") [header value](#header-value "#header-value") for the ``User-Agent``
[header](#concept-header "#concept-header").

For unfortunate web compatibility reasons, web browsers are strongly encouraged to
have this value start with ``Mozilla/5.0 (`` and be generally modeled after other web
browsers.

To get the [environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object") environment’s
environment default ``User-Agent`` value:

1. Let userAgent be the [WebDriver BiDi emulated User-Agent](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-emulated-user-agent "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-emulated-user-agent") for
   environment.

   - If userAgent is non-null, then return userAgent,
     [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode").

     - Return the [default ``User-Agent`` value](#default-user-agent-value "#default-user-agent-value").

The document ``Accept`` header value is
``text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8``.

#### 2.2.3. Statuses

A status is an integer in the range 0 to 999, inclusive.

Various edge cases in mapping HTTP/1’s `status-code` to this concept are
worked on in [issue #1156](https://github.com/whatwg/fetch/issues/1156 "https://github.com/whatwg/fetch/issues/1156").

A null body status is a [status](#concept-status "#concept-status") that is 101, 103, 204, 205, or 304.

An ok status is a [status](#concept-status "#concept-status") in the range 200 to 299, inclusive.

A range status is a [status](#concept-status "#concept-status") that is 206 or 416.

A redirect status is a [status](#concept-status "#concept-status") that is 301, 302, 303, 307, or 308.

#### 2.2.4. Bodies

A body consists of:

* A stream (a `ReadableStream` object).

  * A source (null, a
    [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"), a `Blob` object, or a `FormData` object), initially null.

    * A length (null or an integer),
      initially null.

To clone a
[body](#concept-body "#concept-body") body, run these steps:

1. Let « out1, out2 » be the result of [teeing](https://streams.spec.whatwg.org/#readablestream-tee "https://streams.spec.whatwg.org/#readablestream-tee")
   body’s [stream](#concept-body-stream "#concept-body-stream").

   - Set body’s [stream](#concept-body-stream "#concept-body-stream") to out1.

     - Return a [body](#concept-body "#concept-body") whose
       [stream](#concept-body-stream "#concept-body-stream") is out2 and other members are copied from
       body.

To get a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") bytes
as a body, return the [body](#body-with-type-body "#body-with-type-body") of the
result of [safely extracting](#bodyinit-safely-extract "#bodyinit-safely-extract") bytes.

---

To incrementally read a [body](#concept-body "#concept-body") body, given an
algorithm processBodyChunk, an algorithm processEndOfBody, an algorithm
processBodyError, and an optional null, [parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue"), or
[global object](https://html.spec.whatwg.org/multipage/webappapis.html#global-object "https://html.spec.whatwg.org/multipage/webappapis.html#global-object") taskDestination (default null), run these steps.
processBodyChunk must be an algorithm accepting a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence").
processEndOfBody must be an algorithm accepting no arguments. processBodyError
must be an algorithm accepting an exception.

1. If taskDestination is null, then set taskDestination to the result of
   [starting a new parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#starting-a-new-parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#starting-a-new-parallel-queue").

   - Let reader be the result of [getting a reader](https://streams.spec.whatwg.org/#readablestream-get-a-reader "https://streams.spec.whatwg.org/#readablestream-get-a-reader") for
     body’s [stream](#concept-body-stream "#concept-body-stream").

     This operation will not throw an exception.

     - Perform the [incrementally-read loop](#incrementally-read-loop "#incrementally-read-loop") given reader,
       taskDestination, processBodyChunk, processEndOfBody, and
       processBodyError.

To perform the incrementally-read loop, given a `ReadableStreamDefaultReader` object
reader, [parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue") or [global object](https://html.spec.whatwg.org/multipage/webappapis.html#global-object "https://html.spec.whatwg.org/multipage/webappapis.html#global-object")
taskDestination, algorithm processBodyChunk, algorithm
processEndOfBody, and algorithm processBodyError:

1. Let readRequest be the following [read request](https://streams.spec.whatwg.org/#read-request "https://streams.spec.whatwg.org/#read-request"):

   [chunk steps](https://streams.spec.whatwg.org/#read-request-chunk-steps "https://streams.spec.whatwg.org/#read-request-chunk-steps"), given chunk: 1. Let continueAlgorithm be null. - If chunk is not a `Uint8Array` object, then set continueAlgorithm to this step: run processBodyError given a `TypeError`. - Otherwise: 1. Let bytes be a [copy of](https://webidl.spec.whatwg.org/#dfn-get-buffer-source-copy "https://webidl.spec.whatwg.org/#dfn-get-buffer-source-copy") chunk. Implementations are strongly encouraged to use an implementation strategy that avoids this copy where possible. - Set continueAlgorithm to these steps: 1. Run processBodyChunk given bytes. - Perform the [incrementally-read loop](#incrementally-read-loop "#incrementally-read-loop") given reader, taskDestination, processBodyChunk, processEndOfBody, and processBodyError.- [Queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") given continueAlgorithm and taskDestination. [close steps](https://streams.spec.whatwg.org/#read-request-close-steps "https://streams.spec.whatwg.org/#read-request-close-steps"): 1. [Queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") given processEndOfBody and taskDestination. [error steps](https://streams.spec.whatwg.org/#read-request-error-steps "https://streams.spec.whatwg.org/#read-request-error-steps"), given e: 1. [Queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") to run processBodyError given e, with taskDestination.

   - [Read a chunk](https://streams.spec.whatwg.org/#readablestreamdefaultreader-read-a-chunk "https://streams.spec.whatwg.org/#readablestreamdefaultreader-read-a-chunk") from reader given
     readRequest.

To fully read a [body](#concept-body "#concept-body") body, given an algorithm
processBody, an algorithm processBodyError, and an optional null,
[parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue"), or [global object](https://html.spec.whatwg.org/multipage/webappapis.html#global-object "https://html.spec.whatwg.org/multipage/webappapis.html#global-object") taskDestination (default
null), run these steps. processBody must be an algorithm accepting a
[byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"). processBodyError must be an algorithm optionally accepting an
[exception](https://webidl.spec.whatwg.org/#dfn-exception "https://webidl.spec.whatwg.org/#dfn-exception").

1. If taskDestination is null, then set taskDestination to the result of
   [starting a new parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#starting-a-new-parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#starting-a-new-parallel-queue").

   - Let successSteps given a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") bytes be to
     [queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") to run processBody given bytes, with
     taskDestination.

     - Let errorSteps optionally given an [exception](https://webidl.spec.whatwg.org/#dfn-exception "https://webidl.spec.whatwg.org/#dfn-exception") exception be
       to [queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") to run processBodyError given exception, with
       taskDestination.

       - Let reader be the result of [getting a reader](https://streams.spec.whatwg.org/#readablestream-get-a-reader "https://streams.spec.whatwg.org/#readablestream-get-a-reader") for
         body’s [stream](#concept-body-stream "#concept-body-stream"). If that threw an exception, then run
         errorSteps with that exception and return.

         - [Read all bytes](https://streams.spec.whatwg.org/#readablestreamdefaultreader-read-all-bytes "https://streams.spec.whatwg.org/#readablestreamdefaultreader-read-all-bytes") from
           reader, given successSteps and errorSteps.

---

A body with type is a [tuple](https://infra.spec.whatwg.org/#tuple "https://infra.spec.whatwg.org/#tuple") that consists of a
body (a [body](#concept-body "#concept-body")) and a
type (a [header value](#header-value "#header-value") or null).

---

To handle content codings given codings and bytes, run
these steps:

1. If codings are not supported, then return bytes.

   - Return the result of decoding bytes with codings as explained in HTTP,
     if decoding does not result in an error, and failure otherwise. [[HTTP]](#biblio-http "HTTP Semantics")

#### 2.2.5. Requests

This section documents how requests work in detail. To get started, see
[Setting up a request](#fetch-elsewhere-request "#fetch-elsewhere-request").

The input to [fetch](#concept-fetch "#concept-fetch") is a
request.

A [request](#concept-request "#concept-request") has an associated
method (a
[method](#concept-method "#concept-method")). Unless stated otherwise it is
``GET``.

This can be updated during redirects to ``GET`` as described in
[HTTP fetch](#concept-http-fetch "#concept-http-fetch").

A [request](#concept-request "#concept-request") has an associated URL
(a [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url")).

Implementations are encouraged to make this a pointer to the first [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") in
[request](#concept-request "#concept-request")’s [URL list](#concept-request-url-list "#concept-request-url-list"). It is provided as a distinct field solely for
the convenience of other standards hooking into Fetch.

A [request](#concept-request "#concept-request") has an associated
local-URLs-only flag. Unless stated otherwise it is
unset.

A [request](#concept-request "#concept-request") has an associated
header list (a
[header list](#concept-header-list "#concept-header-list")). Unless stated otherwise it is « ».

A [request](#concept-request "#concept-request") has an associated
unsafe-request flag. Unless stated otherwise it
is unset.

The [unsafe-request flag](#unsafe-request-flag "#unsafe-request-flag") is set by APIs such as
[`fetch()`](#dom-global-fetch "#dom-global-fetch") and `XMLHttpRequest` to ensure a [CORS-preflight fetch](#cors-preflight-fetch-0 "#cors-preflight-fetch-0")
is done based on the supplied [method](#concept-request-method "#concept-request-method") and [header list](#concept-request-header-list "#concept-request-header-list"). It does
not free an API from outlawing [forbidden methods](#forbidden-method "#forbidden-method") and [forbidden request-headers](#forbidden-request-header "#forbidden-request-header").

A [request](#concept-request "#concept-request") has an associated
body (null, a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"), or a
[body](#concept-body "#concept-body")). Unless stated otherwise it is null.

A [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") will be [safely extracted](#bodyinit-safely-extract "#bodyinit-safely-extract") into a
[body](#concept-body "#concept-body") early on in [fetch](#concept-fetch "#concept-fetch"). As part of [HTTP fetch](#concept-http-fetch "#concept-http-fetch") it is possible for
this field to be set to null due to certain redirects.

---

A [request](#concept-request "#concept-request") has an associated
client (null or an
[environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object")).

A [request](#concept-request "#concept-request") has an associated
reserved client
(null, an [environment](https://html.spec.whatwg.org/multipage/webappapis.html#environment "https://html.spec.whatwg.org/multipage/webappapis.html#environment"), or an
[environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object")). Unless stated otherwise it is null.

This is only used by [navigation requests](#navigation-request "#navigation-request") and worker requests, but not service
worker requests. It references an [environment](https://html.spec.whatwg.org/multipage/webappapis.html#environment "https://html.spec.whatwg.org/multipage/webappapis.html#environment") for a [navigation request](#navigation-request "#navigation-request") and an
[environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object") for a worker request.

A [request](#concept-request "#concept-request") has an associated
replaces client id
(a string). Unless stated otherwise it is the empty string.

This is only used by [navigation requests](#navigation-request "#navigation-request"). It is the [id](https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-id "https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-id")
of the [target browsing context](https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-target-browsing-context "https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-target-browsing-context")’s [active document](https://html.spec.whatwg.org/multipage/document-sequences.html#nav-document "https://html.spec.whatwg.org/multipage/document-sequences.html#nav-document")’s
[environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object").

A [request](#concept-request "#concept-request") has an associated
traversable for user prompts, that is
"`no-traversable`", "`client`", or a [traversable navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable").
Unless stated otherwise it is "`client`".

This is used to determine whether and where to show necessary UI for the request, such as
authentication prompts or client certificate dialogs.

"`no-traversable`": No UI is shown; usually the request fails with a [network error](#concept-network-error "#concept-network-error"). "`client`": This value will automatically be changed to either "`no-traversable`" or to a [traversable navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable") derived from the request’s [client](#concept-request-client "#concept-request-client") during [fetching](#concept-fetch "#concept-fetch"). This provides a convenient way for standards to not have to explicitly set a request’s [traversable for user prompts](#concept-request-window "#concept-request-window"). a [traversable navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable"): The UI shown will be associated with the browser interface elements that are displaying that [traversable navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable").

When displaying a user interface associated with a request in that request’s
[traversable for user prompts](#concept-request-window "#concept-request-window"), the user agent should update the address bar to
display something derived from the request’s [current URL](#concept-request-current-url "#concept-request-current-url") (and not, e.g., leave
it at its previous value, derived from the URL of the request’s initiator). Additionally, the user
agent should avoid displaying content from the request’s initiator in the
[traversable for user prompts](#concept-request-window "#concept-request-window"), especially in the case of cross-origin requests.
Displaying a blank page behind such prompts is a good way to fulfill these requirements. Failing to
follow these guidelines can confuse users as to which origin is responsible for the prompt.

A [request](#concept-request "#concept-request") has an associated boolean
keepalive. Unless stated otherwise it is
false.

This can be used to allow the request to outlive the
[environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object"), e.g., `navigator.sendBeacon()` and the HTML
`img` element use this. Requests with this set to true are subject to additional
processing requirements.

A [request](#concept-request "#concept-request") has an associated
initiator type, which is null,
"`audio`",
"`beacon`",
"`body`",
"`css`",
"`early-hints`",
"`embed`",
"`fetch`",
"`font`",
"`frame`",
"`iframe`",
"`image`",
"`img`",
"`input`",
"`link`",
"`object`",
"`ping`",
"`script`",
"`track`",
"`video`",
"`xmlhttprequest`", or
"`other`". Unless stated otherwise it is null. [[RESOURCE-TIMING]](#biblio-resource-timing "Resource Timing")

A [request](#concept-request "#concept-request") has an associated service-workers mode, that
is "`all`" or "`none`". Unless stated otherwise it is "`all`".

This determines which service workers will receive a `fetch` event for this fetch.

"`all`": Relevant service workers will get a `fetch` event for this fetch. "`none`": No service workers will get events for this fetch.

A [request](#concept-request "#concept-request") has an associated
initiator, which is
the empty string,
"`download`",
"`imageset`",
"`manifest`",
"`prefetch`",
"`prerender`", or
"`xslt`". Unless stated otherwise it is the empty string.

A [request](#concept-request "#concept-request")’s [initiator](#concept-request-initiator "#concept-request-initiator") is not particularly granular for
the time being as other specifications do not require it to be. It is primarily a specification
device to assist defining CSP and Mixed Content. It is not exposed to JavaScript. [[CSP]](#biblio-csp "Content Security Policy Level 3") [[MIX]](#biblio-mix "Mixed Content")

A destination type is one of:
the empty string,
"`audio`",
"`audioworklet`",
"`document`",
"`embed`",
"`font`",
"`frame`",
"`iframe`",
"`image`",
"`json`",
"`manifest`",
"`object`",
"`paintworklet`",
"`report`",
"`script`",
"`serviceworker`",
"`sharedworker`",
"`style`",
"`text`",
"`track`",
"`video`",
"`webidentity`",
"`worker`", or
"`xslt`".

A [request](#concept-request "#concept-request") has an associated
destination, which is
[destination type](#destination-type "#destination-type"). Unless stated otherwise it is the empty string.

These are reflected on `RequestDestination` except for "`serviceworker`"
and "`webidentity`" as fetches with those destinations skip service workers.

A [request](#concept-request "#concept-request")’s [destination](#concept-request-destination "#concept-request-destination") is
script-like if it is "`audioworklet`",
"`paintworklet`", "`script`", "`serviceworker`",
"`sharedworker`", or "`worker`".

Algorithms that use [script-like](#request-destination-script-like "#request-destination-script-like") should also consider
"`xslt`" as that too can cause script execution. It is not included in the list as it is
not always relevant and might require different behavior.

The following table illustrates the relationship between a [request](#concept-request "#concept-request")’s
[initiator](#concept-request-initiator "#concept-request-initiator"), [destination](#concept-request-destination "#concept-request-destination"), CSP directives, and features. It is
not exhaustive with respect to features. Features need to have the relevant values defined in their
respective standards.

|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [Initiator](#concept-request-initiator "#concept-request-initiator") [Destination](#concept-request-destination "#concept-request-destination") CSP directive Features|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | "" "`report`" — CSP, NEL reports.|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | "`document`" HTML’s navigate algorithm (top-level only).|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | "`frame`" `child-src` HTML’s `<frame>`| "`iframe`" `child-src` HTML’s `<iframe>`| "" `connect-src` `navigator.sendBeacon()`, `EventSource`, HTML’s `<a ping="">` and `<area ping="">`, [`fetch()`](#dom-global-fetch "#dom-global-fetch"), [`fetchLater()`](#dom-window-fetchlater "#dom-window-fetchlater"), `XMLHttpRequest`, `WebSocket`, `WebTransport`, Cache API| "`object`" `object-src` HTML’s `<object>`| "`embed`" `object-src` HTML’s `<embed>`| "`audio`" `media-src` HTML’s `<audio>`| "`font`" `font-src` CSS' `@font-face`| "`image`" `img-src` HTML’s `<img src>`, `/favicon.ico` resource, SVG’s `<image>`, CSS' `background-image`, CSS' `cursor`, CSS' `list-style-image`, …| "`audioworklet`" `script-src` `audioWorklet.addModule()`| "`paintworklet`" `script-src` `CSS.paintWorklet.addModule()`| "`script`" `script-src` HTML’s `<script>`, `importScripts()`| "`serviceworker`" `child-src`, `script-src`, `worker-src` `navigator.serviceWorker.register()`| "`sharedworker`" `child-src`, `script-src`, `worker-src` `SharedWorker`| "`webidentity`" `connect-src` `Federated Credential Management requests`| "`worker`" `child-src`, `script-src`, `worker-src` `Worker`| "`json`" `connect-src` `import "..." with { type: "json" }`| "`style`" `style-src` HTML’s `<link rel=stylesheet>`, CSS' `@import`, `import "..." with { type: "css" }`| "`text`" `connect-src` `import "..." with { type: "text" }`| "`track`" `media-src` HTML’s `<track>`| "`video`" `media-src` HTML’s `<video>` element| "`download`" "" — HTML’s `download=""`, "Save Link As…" UI| "`imageset`" "`image`" `img-src` HTML’s `<img srcset>` and `<picture>`| "`manifest`" "`manifest`" `manifest-src` HTML’s `<link rel=manifest>`| "`prefetch`" "" `default-src` (no specific directive) HTML’s `<link rel=prefetch>`| "`prerender`" HTML’s `<link rel=prerender>`| "`xslt`" "`xslt`" `script-src` `<?xml-stylesheet>` | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |

CSP’s `form-action` needs to be a hook directly in HTML’s navigate or form
submission algorithm.

CSP will also need to check [request](#concept-request "#concept-request")’s [client](#concept-request-client "#concept-request-client")’s
[global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global")’s [associated `Document`](https://html.spec.whatwg.org/multipage/nav-history-apis.html#concept-document-window "https://html.spec.whatwg.org/multipage/nav-history-apis.html#concept-document-window")’s
[ancestor navigables](https://html.spec.whatwg.org/multipage/document-sequences.html#ancestor-navigables "https://html.spec.whatwg.org/multipage/document-sequences.html#ancestor-navigables") for various CSP directives.

---

A [request](#concept-request "#concept-request") has an associated
priority, which is "`high`", "`low`", or
"`auto`". Unless stated otherwise it is "`auto`".

A [request](#concept-request "#concept-request") has an associated
internal priority (null or an
[implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") object). Unless otherwise stated it is null.

A [request](#concept-request "#concept-request") has an associated
origin, which is
"`client`" or an [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin"). Unless stated otherwise it is
"`client`".

"`client`" is changed to an [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin") during
[fetching](#concept-fetch "#concept-fetch"). It provides a convenient way for standards to not have to set
[request](#concept-request "#concept-request")’s [origin](#concept-request-origin "#concept-request-origin").

A [request](#concept-request "#concept-request") has an associated
top-level navigation initiator origin, which is an [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin")
or null. Unless stated otherwise it is null.

A [request](#concept-request "#concept-request") has an associated
policy container, which is
"`client`" or a [policy container](https://html.spec.whatwg.org/multipage/browsers.html#policy-container "https://html.spec.whatwg.org/multipage/browsers.html#policy-container"). Unless stated otherwise it is
"`client`".

"`client`" is changed to a [policy container](https://html.spec.whatwg.org/multipage/browsers.html#policy-container "https://html.spec.whatwg.org/multipage/browsers.html#policy-container") during
[fetching](#concept-fetch "#concept-fetch"). It provides a convenient way for standards to not have to set
[request](#concept-request "#concept-request")’s [policy container](#concept-request-policy-container "#concept-request-policy-container").

A [request](#concept-request "#concept-request") has an associated
referrer, which is
"`no-referrer`", "`client`", or a [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url"). Unless stated otherwise it
is "`client`".

"`client`" is changed to "`no-referrer`" or a [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url")
during [fetching](#concept-fetch "#concept-fetch"). It provides a convenient way for standards to not have to set
[request](#concept-request "#concept-request")’s [referrer](#concept-request-referrer "#concept-request-referrer").

A [request](#concept-request "#concept-request") has an associated
referrer policy, which is a
[referrer policy](https://w3c.github.io/webappsec-referrer-policy/#referrer-policy "https://w3c.github.io/webappsec-referrer-policy/#referrer-policy"). Unless stated otherwise it is the empty string. [[REFERRER]](#biblio-referrer "Referrer Policy")

This can be used to override the referrer policy to be used for this
[request](#concept-request "#concept-request").

A [request](#concept-request "#concept-request") has an associated
mode, which is
"`same-origin`", "`cors`", "`no-cors`",
"`navigate`", "`websocket`", or "`webtransport`".
Unless stated otherwise, it is "`no-cors`".

"`same-origin`": Used to ensure requests are made to same-origin URLs. [Fetch](#concept-fetch "#concept-fetch") will return a [network error](#concept-network-error "#concept-network-error") if the request is not made to a same-origin URL. "`cors`": For requests whose [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") gets set to "`cors`", makes the request a [CORS request](#cors-request "#cors-request") — in which case, fetch will return a [network error](#concept-network-error "#concept-network-error") if the requested resource does not understand the [CORS protocol](#cors-protocol "#cors-protocol"), or if the requested resource is one that intentionally does not participate in the [CORS protocol](#cors-protocol "#cors-protocol"). "`no-cors`": Restricts requests to using [CORS-safelisted methods](#cors-safelisted-method "#cors-safelisted-method") and [CORS-safelisted request-headers](#cors-safelisted-request-header "#cors-safelisted-request-header"). Upon success, fetch will return an [opaque filtered response](#concept-filtered-response-opaque "#concept-filtered-response-opaque"). "`navigate`": This is a special mode used only when [navigating](https://html.spec.whatwg.org/multipage/nav-history-apis.html#blocking-navigating "https://html.spec.whatwg.org/multipage/nav-history-apis.html#blocking-navigating") between documents. "`websocket`": This is a special mode used only when [establishing a WebSocket connection](https://websockets.spec.whatwg.org/#concept-websocket-establish "https://websockets.spec.whatwg.org/#concept-websocket-establish"). "`webtransport`": This is a special mode used only by `WebTransport(url, options)`.

Even though the default [request](#concept-request "#concept-request") [mode](#concept-request-mode "#concept-request-mode") is "`no-cors`",
standards are highly discouraged from using it for new features. It is rather unsafe.

A [request](#concept-request "#concept-request") has an associated
use-CORS-preflight flag. Unless stated
otherwise, it is unset.

The [use-CORS-preflight flag](#use-cors-preflight-flag "#use-cors-preflight-flag") being set is one of several conditions that results
in a [CORS-preflight request](#cors-preflight-request "#cors-preflight-request"). The [use-CORS-preflight flag](#use-cors-preflight-flag "#use-cors-preflight-flag") is set if either one or more
event listeners are registered on an `XMLHttpRequestUpload` object or if a `ReadableStream`
object is used in a request.

A [request](#concept-request "#concept-request") has an associated
credentials mode,
which is "`omit`", "`same-origin`", or
"`include`". Unless stated otherwise, it is "`same-origin`".

"`omit`": Excludes credentials from this request, and causes any credentials sent back in the response to be ignored. "`same-origin`": Include credentials with requests made to same-origin URLs, and use any credentials sent back in responses from same-origin URLs. "`include`": Always includes credentials with this request, and always use any credentials sent back in the response.

[Request](#concept-request "#concept-request")’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") controls the flow of
[credentials](#credentials "#credentials") during a [fetch](#concept-fetch "#concept-fetch"). When [request](#concept-request "#concept-request")’s
[mode](#concept-request-mode "#concept-request-mode") is "`navigate`", its [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is
assumed to be "`include`" and [fetch](#concept-fetch "#concept-fetch") does not currently account for other
values. If HTML changes here, this standard will need corresponding changes.

A [request](#concept-request "#concept-request") has an associated
use-URL-credentials flag.
Unless stated otherwise, it is unset.

When this flag is set, when a [request](#concept-request "#concept-request")’s
[URL](#concept-request-url "#concept-request-url") has a [username](https://url.spec.whatwg.org/#concept-url-username "https://url.spec.whatwg.org/#concept-url-username") and [password](https://url.spec.whatwg.org/#concept-url-password "https://url.spec.whatwg.org/#concept-url-password"), and there is an
available [authentication entry](#authentication-entry "#authentication-entry") for the [request](#concept-request "#concept-request"), then the [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url")’s
credentials are preferred over that of the [authentication entry](#authentication-entry "#authentication-entry"). Modern specifications avoid
setting this flag, since putting credentials in [URLs](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") is discouraged, but some older
features set it for compatibility reasons.

A [request](#concept-request "#concept-request") has an associated
cache mode, which is
"`default`", "`no-store`", "`reload`",
"`no-cache`", "`force-cache`", or
"`only-if-cached`". Unless stated otherwise, it is "`default`".

"`default`": [Fetch](#concept-fetch "#concept-fetch") will inspect the HTTP cache on the way to the network. If the HTTP cache contains a matching [fresh response](#concept-fresh-response "#concept-fresh-response") it will be returned. If the HTTP cache contains a matching [stale-while-revalidate response](#concept-stale-while-revalidate-response "#concept-stale-while-revalidate-response") it will be returned, and a conditional network fetch will be made to update the entry in the HTTP cache. If the HTTP cache contains a matching [stale response](#concept-stale-response "#concept-stale-response"), a conditional network fetch will be returned to update the entry in the HTTP cache. Otherwise, a non-conditional network fetch will be returned to update the entry in the HTTP cache. [[HTTP]](#biblio-http "HTTP Semantics") [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching") [[STALE-WHILE-REVALIDATE]](#biblio-stale-while-revalidate "HTTP Cache-Control Extensions for Stale Content") "`no-store`": Fetch behaves as if there is no HTTP cache at all. "`reload`": Fetch behaves as if there is no HTTP cache on the way to the network. Ergo, it creates a normal request and updates the HTTP cache with the response. "`no-cache`": Fetch creates a conditional request if there is a response in the HTTP cache and a normal request otherwise. It then updates the HTTP cache with the response. "`force-cache`": Fetch uses any response in the HTTP cache matching the request, not paying attention to staleness. If there was no response, it creates a normal request and updates the HTTP cache with the response. "`only-if-cached`": Fetch uses any response in the HTTP cache matching the request, not paying attention to staleness. If there was no response, it returns a network error. (Can only be used when [request](#concept-request "#concept-request")’s [mode](#concept-request-mode "#concept-request-mode") is "`same-origin`". Any cached redirects will be followed assuming [request](#concept-request "#concept-request")’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") is "`follow`" and the redirects do not violate [request](#concept-request "#concept-request")’s [mode](#concept-request-mode "#concept-request-mode").)

If [header list](#concept-request-header-list "#concept-request-header-list") [contains](#header-list-contains "#header-list-contains")
``If-Modified-Since``,
``If-None-Match``,
``If-Unmodified-Since``,
``If-Match``, or
``If-Range``,
[fetch](#concept-fetch "#concept-fetch") will set
[cache mode](#concept-request-cache-mode "#concept-request-cache-mode") to "`no-store`" if it is
"`default`".

A [request](#concept-request "#concept-request") has an associated
redirect mode, which is
"`follow`", "`error`", or "`manual`".
Unless stated otherwise, it is "`follow`".

"`follow`": Follow all redirects incurred when fetching a resource. "`error`": Return a [network error](#concept-network-error "#concept-network-error") when a request is met with a redirect. "`manual`": Retrieves an [opaque-redirect filtered response](#concept-filtered-response-opaque-redirect "#concept-filtered-response-opaque-redirect") when a request is met with a redirect, to allow a service worker to replay the redirect offline. The response is otherwise indistinguishable from a [network error](#concept-network-error "#concept-network-error"), to not violate [atomic HTTP redirect handling](#atomic-http-redirect-handling "#atomic-http-redirect-handling").

A [request](#concept-request "#concept-request") has associated
integrity metadata
(a string). Unless stated otherwise, it is the empty string.

A [request](#concept-request "#concept-request") has associated
cryptographic nonce metadata
(a string). Unless stated otherwise, it is the empty string.

A [request](#concept-request "#concept-request") has associated
parser metadata
which is the empty string, "`parser-inserted`", or
"`not-parser-inserted`". Unless otherwise stated, it is the empty string.

A [request](#concept-request "#concept-request")’s [cryptographic nonce metadata](#concept-request-nonce-metadata "#concept-request-nonce-metadata") and
[parser metadata](#concept-request-parser-metadata "#concept-request-parser-metadata") are generally populated from attributes and flags on the HTML
element responsible for creating a [request](#concept-request "#concept-request"). They are used by various algorithms in
Content Security Policy to determine whether requests or responses are to be blocked in
a given context. [[CSP]](#biblio-csp "Content Security Policy Level 3")

A [request](#concept-request "#concept-request") has an associated
reload-navigation flag.
Unless stated otherwise, it is unset.

This flag is for exclusive use by HTML’s navigate algorithm. [[HTML]](#biblio-html "HTML Standard")

A [request](#concept-request "#concept-request") has an associated
history-navigation flag.
Unless stated otherwise, it is unset.

This flag is for exclusive use by HTML’s navigate algorithm. [[HTML]](#biblio-html "HTML Standard")

A [request](#concept-request "#concept-request") has an associated boolean user-activation.
Unless stated otherwise, it is false.

This is for exclusive use by HTML’s navigate algorithm. [[HTML]](#biblio-html "HTML Standard")

A [request](#concept-request "#concept-request") has an associated WebDriver navigation id
(null or a string). Unless stated otherwise, it is null.

This is for exclusive use by HTML’s navigate algorithm. [[HTML]](#biblio-html "HTML Standard")

A [request](#concept-request "#concept-request") has an associated boolean render-blocking.
Unless stated otherwise, it is false.

This flag is for exclusive use by HTML’s render-blocking mechanism. [[HTML]](#biblio-html "HTML Standard")

A [request](#concept-request "#concept-request") has an associated WebTransport-hash list (a
[WebTransport-hash list](#webtransport-hash-list "#webtransport-hash-list")). Unless stated otherwise it is « ».

A WebTransport-hash list is a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of zero or more
[WebTransport-hashes](#concept-WebTransport-hash "#concept-WebTransport-hash").

A WebTransport-hash is a [tuple](https://infra.spec.whatwg.org/#tuple "https://infra.spec.whatwg.org/#tuple")
consisting of an algorithm (a [string](https://infra.spec.whatwg.org/#string "https://infra.spec.whatwg.org/#string")) and a
value (a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence")).

This list is for exclusive use by `WebTransport(url, options)` when
options contains `serverCertificateHashes`.

---

A [request](#concept-request "#concept-request") has an associated
URL list (a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of one or
more [URLs](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url")). Unless stated otherwise, it is a list containing a copy of
[request](#concept-request "#concept-request")’s [URL](#concept-request-url "#concept-request-url").

A [request](#concept-request "#concept-request") has an associated
current URL. It is a pointer to the
last [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") in [request](#concept-request "#concept-request")’s [URL list](#concept-request-url-list "#concept-request-url-list").

A [request](#concept-request "#concept-request") has an associated
redirect count.
Unless stated otherwise, it is zero.

A [request](#concept-request "#concept-request") has an associated
response tainting,
which is "`basic`", "`cors`", or "`opaque`".
Unless stated otherwise, it is "`basic`".

A [request](#concept-request "#concept-request") has an associated
prevent no-cache cache-control header modification flag.
Unless stated otherwise, it is unset.

A [request](#concept-request "#concept-request") has an associated done flag.
Unless stated otherwise, it is unset.

A [request](#concept-request "#concept-request") has an associated
timing allow failed flag. Unless stated
otherwise, it is unset.

A [request](#concept-request "#concept-request")’s [URL list](#concept-request-url-list "#concept-request-url-list"), [current URL](#concept-request-current-url "#concept-request-current-url"),
[redirect count](#concept-request-redirect-count "#concept-request-redirect-count"), [response tainting](#concept-request-response-tainting "#concept-request-response-tainting"),
[done flag](#done-flag "#done-flag"), and [timing allow failed flag](#timing-allow-failed "#timing-allow-failed") are used as
bookkeeping details by the [fetch](#concept-fetch "#concept-fetch") algorithm.

A [request](#concept-request "#concept-request") has an associated
WebDriver id
which is the result of [generating a random UUID](https://w3c.github.io/webcrypto/#dfn-generate-a-random-uuid "https://w3c.github.io/webcrypto/#dfn-generate-a-random-uuid"), set when the [request](#concept-request "#concept-request") is
created. [[WEBCRYPTO]](#biblio-webcrypto "Web Cryptography Level 2")

The [WebDriver id](#concept-webdriver-id "#concept-webdriver-id") is used by WebDriver-BiDi. It remains constant
across redirects, authentication attempts, and CORS-preflight fetches of an initial request.
When a request is [cloned](#concept-request-clone "#concept-request-clone"), the created request gets a unique
[WebDriver id](#concept-webdriver-id "#concept-webdriver-id"). [[WEBDRIVER-BIDI]](#biblio-webdriver-bidi "WebDriver BiDi")

---

A subresource request is a [request](#concept-request "#concept-request")
whose [destination](#concept-request-destination "#concept-request-destination") is "`audio`", "`audioworklet`",
"`font`", "`image`", "`json`", "`manifest`",
"`paintworklet`", "`script`", "`style`", "`text`",
"`track`", "`video`", "`xslt`", or the empty string.

A non-subresource request is a [request](#concept-request "#concept-request")
whose [destination](#concept-request-destination "#concept-request-destination") is "`document`", "`embed`",
"`frame`", "`iframe`", "`object`", "`report`",
"`serviceworker`", "`sharedworker`", or "`worker`".

A navigation request is a [request](#concept-request "#concept-request") whose
[destination](#concept-request-destination "#concept-request-destination") is
"`document`", "`embed`", "`frame`", "`iframe`",
or "`object`".

See [handle fetch](https://w3c.github.io/ServiceWorker/#handle-fetch "https://w3c.github.io/ServiceWorker/#handle-fetch") for usage of these terms.
[[SW]](#biblio-sw "Service Workers Nightly")

---

To compute the redirect-taint of a
[request](#concept-request "#concept-request") request, perform the following steps. They return
"`same-origin`", "`same-site`", or "`cross-site`".

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [origin](#concept-request-origin "#concept-request-origin") is not
   "`client`".

   - Let lastURL be null.

     - Let taint be "`same-origin`".

       - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") url of request’s [URL list](#concept-request-url-list "#concept-request-url-list"):

         1. If lastURL is null, then set lastURL to url and
            [continue](https://infra.spec.whatwg.org/#iteration-continue "https://infra.spec.whatwg.org/#iteration-continue").

            - If url’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") is not [same site](https://html.spec.whatwg.org/multipage/browsers.html#same-site "https://html.spec.whatwg.org/multipage/browsers.html#same-site") with
              lastURL’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") and request’s [origin](#concept-request-origin "#concept-request-origin") is
              not [same site](https://html.spec.whatwg.org/multipage/browsers.html#same-site "https://html.spec.whatwg.org/multipage/browsers.html#same-site") with lastURL’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin"), then return
              "`cross-site`".

              - If url’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") is not [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with
                lastURL’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") and request’s [origin](#concept-request-origin "#concept-request-origin") is
                not [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with lastURL’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin"), then set
                taint to "`same-site`".

                - Set lastURL to url.- Return taint.

Serializing a request origin, given a [request](#concept-request "#concept-request") request, is to
run these steps:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [origin](#concept-request-origin "#concept-request-origin") is not
   "`client`".

   - If request’s [redirect-taint](#concept-request-tainted-origin "#concept-request-tainted-origin") is not "`same-origin`",
     then return "`null`".

     - Return request’s [origin](#concept-request-origin "#concept-request-origin"),
       [serialized](https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin "https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin").

Byte-serializing a request origin, given a [request](#concept-request "#concept-request") request,
is to return the result of [serializing a request origin](#serializing-a-request-origin "#serializing-a-request-origin") with request,
[isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode").

---

To clone a
[request](#concept-request "#concept-request") request, run these steps:

1. Let newRequest be a copy of request, except for its
   [body](#concept-request-body "#concept-request-body") and [WebDriver id](#concept-webdriver-id "#concept-webdriver-id").

   - Set newRequest’s [WebDriver id](#concept-webdriver-id "#concept-webdriver-id") to the result of
     [generating a random UUID](https://w3c.github.io/webcrypto/#dfn-generate-a-random-uuid "https://w3c.github.io/webcrypto/#dfn-generate-a-random-uuid"). [[WEBCRYPTO]](#biblio-webcrypto "Web Cryptography Level 2")

     - If request’s [body](#concept-request-body "#concept-request-body") is non-null, set newRequest’s
       [body](#concept-request-body "#concept-request-body") to the result of [cloning](#concept-body-clone "#concept-body-clone") request’s
       [body](#concept-request-body "#concept-request-body").

       - Return newRequest.

---

To add a range header to a
[request](#concept-request "#concept-request") request, with an integer first, and an optional integer
last, run these steps:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): last is not given, or first is less than or equal
   to last.

   - Let rangeValue be ``bytes=``.

     - [Serialize](#serialize-an-integer "#serialize-an-integer") and [isomorphic encode](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode") first,
       and append the result to rangeValue.

       - Append 0x2D (-) to rangeValue.

         - If last is given, then [serialize](#serialize-an-integer "#serialize-an-integer") and
           [isomorphic encode](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode") it, and append the result to rangeValue.

           - [Append](#concept-header-list-append "#concept-header-list-append") (``Range``, rangeValue) to
             request’s [header list](#concept-request-header-list "#concept-request-header-list").

A range header denotes an inclusive byte range. There a range header where
first is 0 and last is 500, is a range of 501 bytes.

Features that combine multiple responses into one logical resource are historically a
source of security bugs. Please seek security review for features that deal with partial responses.

---

To serialize a response URL for reporting, given a [response](#concept-response "#concept-response")
response, run these steps:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): response’s [URL list](#concept-response-url-list "#concept-response-url-list")
   [is not empty](https://infra.spec.whatwg.org/#list-is-empty "https://infra.spec.whatwg.org/#list-is-empty").

   - Let url be a copy of response’s [URL list](#concept-response-url-list "#concept-response-url-list")[0].

     This is not response’s [URL](#concept-response-url "#concept-response-url") in order to avoid
     leaking information about redirect targets (see
     [similar considerations for CSP reporting](https://w3c.github.io/webappsec-csp/#security-violation-reports "https://w3c.github.io/webappsec-csp/#security-violation-reports")
     too). [[CSP]](#biblio-csp "Content Security Policy Level 3")

     - [Set the username](https://url.spec.whatwg.org/#set-the-username "https://url.spec.whatwg.org/#set-the-username") given url and the empty string.

       - [Set the password](https://url.spec.whatwg.org/#set-the-password "https://url.spec.whatwg.org/#set-the-password") given url and the empty string.

         - Return the [serialization](https://url.spec.whatwg.org/#concept-url-serializer "https://url.spec.whatwg.org/#concept-url-serializer") of url with
           [*exclude fragment*](https://url.spec.whatwg.org/#url-serializer-exclude-fragment "https://url.spec.whatwg.org/#url-serializer-exclude-fragment") set to true.

To check if Cross-Origin-Embedder-Policy allows credentials, given a
[request](#concept-request "#concept-request") request, run these steps:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [origin](#concept-request-origin "#concept-request-origin") is not
   "`client`".

   - If request’s [mode](#concept-request-mode "#concept-request-mode") is not "`no-cors`", then return
     true.

     - If request’s [client](#concept-request-client "#concept-request-client") is null, then return true.

       - If request’s [client](#concept-request-client "#concept-request-client")’s
         [policy container](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container")’s
         [embedder policy](https://html.spec.whatwg.org/multipage/browsers.html#policy-container-embedder-policy "https://html.spec.whatwg.org/multipage/browsers.html#policy-container-embedder-policy")’s [value](https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-value-2 "https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-value-2") is not
         "[`credentialless`](https://html.spec.whatwg.org/multipage/browsers.html#coep-credentialless "https://html.spec.whatwg.org/multipage/browsers.html#coep-credentialless")", then return true.

         - If request’s [origin](#concept-request-origin "#concept-request-origin") is [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with
           request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") and request’s
           [redirect-taint](#concept-request-tainted-origin "#concept-request-tainted-origin") is not "`same-origin`", then return true.

           - Return false.

#### 2.2.6. Responses

The result of [fetch](#concept-fetch "#concept-fetch") is a
response. A [response](#concept-response "#concept-response")
evolves over time. That is, not all its fields are available straight away.

A [response](#concept-response "#concept-response") has an associated
type which is
"`basic`",
"`cors`",
"`default`",
"`error`",
"`opaque`", or
"`opaqueredirect`".
Unless stated otherwise, it is "`default`".

A [response](#concept-response "#concept-response") can have an associated
aborted flag, which is initially unset.

This indicates that the request was intentionally aborted by the developer or
end-user.

A [response](#concept-response "#concept-response") has an associated
URL. It is a pointer to the last
[URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") in [response](#concept-response "#concept-response")’s [URL list](#concept-response-url-list "#concept-response-url-list") and null if
[response](#concept-response "#concept-response")’s [URL list](#concept-response-url-list "#concept-response-url-list") [is empty](https://infra.spec.whatwg.org/#list-is-empty "https://infra.spec.whatwg.org/#list-is-empty").

A [response](#concept-response "#concept-response") has an associated
URL list (a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of zero or
more [URLs](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url")). Unless stated otherwise, it is « ».

Except for the first and last [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url"), if any, a [response](#concept-response "#concept-response")’s
[URL list](#concept-response-url-list "#concept-response-url-list") is not directly exposed to script as that would violate
[atomic HTTP redirect handling](#atomic-http-redirect-handling "#atomic-http-redirect-handling").

A [response](#concept-response "#concept-response") has an associated
status, which is a [status](#concept-status "#concept-status").
Unless stated otherwise it is 200.

A [response](#concept-response "#concept-response") has an associated
status message. Unless stated
otherwise it is the empty byte sequence.

Responses over an HTTP/2 connection will always have the empty byte sequence as status
message as HTTP/2 does not support them.

A [response](#concept-response "#concept-response") has an associated
header list (a
[header list](#concept-header-list "#concept-header-list")). Unless stated otherwise it is « ».

A [response](#concept-response "#concept-response") has an associated
body (null or a
[body](#concept-body "#concept-body")). Unless stated otherwise it is null.

The [source](#concept-body-source "#concept-body-source") and [length](#concept-body-total-bytes "#concept-body-total-bytes") concepts of a network’s
[response](#concept-response "#concept-response")’s [body](#concept-response-body "#concept-response-body") are always null.

A [response](#concept-response "#concept-response") has an associated
cache state (the empty string,
"`local`", or "`validated`"). Unless stated otherwise, it is the empty
string.

This is intended for usage by Service Workers and
Resource Timing. [[SW]](#biblio-sw "Service Workers Nightly") [[RESOURCE-TIMING]](#biblio-resource-timing "Resource Timing")

A [response](#concept-response "#concept-response") has an associated
CORS-exposed header-name list
(a list of zero or more [header](#concept-header "#concept-header")
[names](#concept-header-name "#concept-header-name")). The list is empty unless otherwise specified.

A [response](#concept-response "#concept-response") will typically get its
[CORS-exposed header-name list](#concept-response-cors-exposed-header-name-list "#concept-response-cors-exposed-header-name-list") set by [extracting header values](#extract-header-values "#extract-header-values") from the
`[`Access-Control-Expose-Headers`](#http-access-control-expose-headers "#http-access-control-expose-headers")` header. This list is used by a
[CORS filtered response](#concept-filtered-response-cors "#concept-filtered-response-cors") to determine which headers to expose.

A [response](#concept-response "#concept-response") has an associated
range-requested flag, which is
initially unset.

This is used to prevent a partial response from an earlier ranged request being
provided to an API that didn’t make a range request. See the flag’s usage for a detailed description
of the attack.

A [response](#concept-response "#concept-response") has an associated request-includes-credentials
(a boolean), which is initially true.

A [response](#concept-response "#concept-response") has an associated
timing allow passed flag, which is
initially unset.

This is used so that the caller to a fetch can determine if sensitive timing data is
allowed on the resource fetched by looking at the flag of the response returned. Because the flag on
the response of a redirect has to be set if it was set for previous responses in the redirect chain,
this is also tracked internally using the request’s [timing allow failed flag](#timing-allow-failed "#timing-allow-failed").

A [response](#concept-response "#concept-response") has an associated
body info
(a [response body info](#response-body-info "#response-body-info")). Unless stated otherwise, it is a new
[response body info](#response-body-info "#response-body-info").

A [response](#concept-response "#concept-response") has an associated
service worker timing info (null or a
[service worker timing info](https://w3c.github.io/ServiceWorker/#service-worker-timing-info "https://w3c.github.io/ServiceWorker/#service-worker-timing-info")), which is initially null.

A [response](#concept-response "#concept-response") has an associated redirect taint
("`same-origin`", "`same-site`", or "`cross-site`"), which is
initially "`same-origin`".

---

A network error is a [response](#concept-response "#concept-response") whose
[type](#concept-response-type "#concept-response-type") is "`error`", [status](#concept-response-status "#concept-response-status") is 0,
[status message](#concept-response-status-message "#concept-response-status-message") is the empty byte sequence,
[header list](#concept-response-header-list "#concept-response-header-list") is « », [body](#concept-response-body "#concept-response-body") is null, and
[body info](#concept-response-body-info "#concept-response-body-info") is a new [response body info](#response-body-info "#response-body-info").

An aborted network error is a
[network error](#concept-network-error "#concept-network-error") whose [aborted flag](#concept-response-aborted "#concept-response-aborted") is set.

To create the appropriate network error given [fetch params](#fetch-params "#fetch-params")
fetchParams:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): fetchParams is [canceled](#fetch-params-canceled "#fetch-params-canceled").

   - Return an [aborted network error](#concept-aborted-network-error "#concept-aborted-network-error") if fetchParams is
     [aborted](#fetch-params-aborted "#fetch-params-aborted"); otherwise return a [network error](#concept-network-error "#concept-network-error").

---

A filtered response is a [response](#concept-response "#concept-response")
that offers a limited view on an associated [response](#concept-response "#concept-response"). This associated
[response](#concept-response "#concept-response") can be accessed through [filtered response](#concept-filtered-response "#concept-filtered-response")’s
internal response (a
[response](#concept-response "#concept-response") that is neither a [network error](#concept-network-error "#concept-network-error") nor a
[filtered response](#concept-filtered-response "#concept-filtered-response")).

Unless stated otherwise a [filtered response](#concept-filtered-response "#concept-filtered-response")’s associated concepts (such as its
[body](#concept-response-body "#concept-response-body")) refer to the associated concepts of its
[internal response](#concept-internal-response "#concept-internal-response"). (The exceptions to this are listed below as part
of defining the concrete types of [filtered responses](#concept-filtered-response "#concept-filtered-response").)

The [fetch](#concept-fetch "#concept-fetch") algorithm by way of [*processResponse*](#process-response "#process-response") and
equivalent parameters exposes [filtered responses](#concept-filtered-response "#concept-filtered-response") to callers to ensure they do not
accidentally leak information. If the information needs to be revealed for legacy reasons, e.g., to
feed image data to a decoder, the associated [internal response](#concept-internal-response "#concept-internal-response") can
be used by specification algorithms.

New specifications ought not to build further on [opaque filtered responses](#concept-filtered-response-opaque "#concept-filtered-response-opaque") or
[opaque-redirect filtered responses](#concept-filtered-response-opaque-redirect "#concept-filtered-response-opaque-redirect"). Those are legacy constructs and cannot always be
adequately protected given contemporary computer architecture.

A basic filtered response is a
[filtered response](#concept-filtered-response "#concept-filtered-response") whose
[type](#concept-response-type "#concept-response-type") is "`basic`" and
[header list](#concept-response-header-list "#concept-response-header-list") excludes any
[headers](#concept-header "#concept-header") in
[internal response](#concept-internal-response "#concept-internal-response")’s
[header list](#concept-response-header-list "#concept-response-header-list") whose
[name](#concept-header-name "#concept-header-name") is a
[forbidden response-header name](#forbidden-response-header-name "#forbidden-response-header-name").

A CORS filtered response is a
[filtered response](#concept-filtered-response "#concept-filtered-response") whose
[type](#concept-response-type "#concept-response-type") is "`cors`" and
[header list](#concept-response-header-list "#concept-response-header-list") excludes any
[headers](#concept-header "#concept-header") in
[internal response](#concept-internal-response "#concept-internal-response")’s
[header list](#concept-response-header-list "#concept-response-header-list") whose
[name](#concept-header-name "#concept-header-name") is *not* a
[CORS-safelisted response-header name](#cors-safelisted-response-header-name "#cors-safelisted-response-header-name"), given
[internal response](#concept-internal-response "#concept-internal-response")’s
[CORS-exposed header-name list](#concept-response-cors-exposed-header-name-list "#concept-response-cors-exposed-header-name-list").

An opaque filtered response is a
[filtered response](#concept-filtered-response "#concept-filtered-response") whose
[type](#concept-response-type "#concept-response-type") is "`opaque`",
[URL list](#concept-response-url-list "#concept-response-url-list") is « »,
[status](#concept-response-status "#concept-response-status") is 0,
[status message](#concept-response-status-message "#concept-response-status-message") is the empty byte sequence,
[header list](#concept-response-header-list "#concept-response-header-list") is « »,
[body](#concept-response-body "#concept-response-body") is null, and
[body info](#concept-response-body-info "#concept-response-body-info") is a new [response body info](#response-body-info "#response-body-info").

An
opaque-redirect filtered response
is a [filtered response](#concept-filtered-response "#concept-filtered-response") whose
[type](#concept-response-type "#concept-response-type") is "`opaqueredirect`",
[status](#concept-response-status "#concept-response-status") is 0,
[status message](#concept-response-status-message "#concept-response-status-message") is the empty byte sequence,
[header list](#concept-response-header-list "#concept-response-header-list") is « »,
[body](#concept-response-body "#concept-response-body") is null, and
[body info](#concept-response-body-info "#concept-response-body-info") is a new [response body info](#response-body-info "#response-body-info").

Exposing the [URL list](#concept-response-url-list "#concept-response-url-list") for
[opaque-redirect filtered responses](#concept-filtered-response-opaque-redirect "#concept-filtered-response-opaque-redirect") is harmless since
no redirects are followed.

In other words, an [opaque filtered response](#concept-filtered-response-opaque "#concept-filtered-response-opaque") and an
[opaque-redirect filtered response](#concept-filtered-response-opaque-redirect "#concept-filtered-response-opaque-redirect") are nearly indistinguishable from a [network error](#concept-network-error "#concept-network-error").
When introducing new APIs, do not use the [internal response](#concept-internal-response "#concept-internal-response") for
internal specification algorithms as that will leak information.

This also means that JavaScript APIs, such as
[`response.ok`](#dom-response-ok "#dom-response-ok"), will return rather useless results.

The [type](#concept-response-type "#concept-response-type") of a [response](#concept-response "#concept-response") is exposed to script through the
`type` getter:

```
console.log(new Response().type); // "default"

console.log((await fetch("/")).type); // "basic"

console.log((await fetch("https://api.example/status")).type); // "cors"

console.log((await fetch("https://crossorigin.example/image", { mode: "no-cors" })).type); // "opaque"

console.log((await fetch("/surprise-me", { redirect: "manual" })).type); // "opaqueredirect"
```

(This assumes that the various resources exist, `https://api.example/status` has the
appropriate CORS headers, and `/surprise-me` uses a [redirect status](#redirect-status "#redirect-status").)

---

To clone a
[response](#concept-response "#concept-response") response, run these steps:

1. If response is a [filtered response](#concept-filtered-response "#concept-filtered-response"), then return a new identical
   [filtered response](#concept-filtered-response "#concept-filtered-response") whose [internal response](#concept-internal-response "#concept-internal-response") is a
   [clone](#concept-response-clone "#concept-response-clone") of response’s
   [internal response](#concept-internal-response "#concept-internal-response").

   - Let newResponse be a copy of response, except for its
     [body](#concept-response-body "#concept-response-body").

     - If response’s [body](#concept-response-body "#concept-response-body") is non-null, then set
       newResponse’s [body](#concept-response-body "#concept-response-body") to the result of [cloning](#concept-body-clone "#concept-body-clone")
       response’s [body](#concept-response-body "#concept-response-body").

       - Return newResponse.

---

A fresh response is a [response](#concept-response "#concept-response") whose
[current age](https://httpwg.org/specs/rfc9111.html#age.calculations "https://httpwg.org/specs/rfc9111.html#age.calculations") is within its [freshness lifetime](https://httpwg.org/specs/rfc9111.html#calculating.freshness.lifetime "https://httpwg.org/specs/rfc9111.html#calculating.freshness.lifetime").

A stale-while-revalidate response is a
[response](#concept-response "#concept-response") that is not a [fresh response](#concept-fresh-response "#concept-fresh-response") and whose [current age](https://httpwg.org/specs/rfc9111.html#age.calculations "https://httpwg.org/specs/rfc9111.html#age.calculations") is within the
[stale-while-revalidate lifetime](https://httpwg.org/specs/rfc5861.html#n-the-stale-while-revalidate-cache-control-extension "https://httpwg.org/specs/rfc5861.html#n-the-stale-while-revalidate-cache-control-extension"). [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching") [[STALE-WHILE-REVALIDATE]](#biblio-stale-while-revalidate "HTTP Cache-Control Extensions for Stale Content")

A stale response is a [response](#concept-response "#concept-response") that is
not a [fresh response](#concept-fresh-response "#concept-fresh-response") or a [stale-while-revalidate response](#concept-stale-while-revalidate-response "#concept-stale-while-revalidate-response").

---

The location URL of a
[response](#concept-response "#concept-response") response, given null or an [ASCII string](https://infra.spec.whatwg.org/#ascii-string "https://infra.spec.whatwg.org/#ascii-string")
requestFragment, is the value returned by the following steps. They return null, failure,
or a [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url").

1. If response’s [status](#concept-response-status "#concept-response-status") is not a [redirect status](#redirect-status "#redirect-status"), then
   return null.

   - Let location be the result of [extracting header list values](#extract-header-list-values "#extract-header-list-values") given
     ``Location`` and response’s [header list](#concept-response-header-list "#concept-response-header-list").

     - If location is a [header value](#header-value "#header-value"), then set location to the
       result of [parsing](https://url.spec.whatwg.org/#concept-url-parser "https://url.spec.whatwg.org/#concept-url-parser") location with response’s
       [URL](#concept-response-url "#concept-response-url").

       If response was constructed through the `Response` constructor,
       response’s [URL](#concept-response-url "#concept-response-url") will be null, meaning that location will
       only parse successfully if it is an [absolute-URL-with-fragment string](https://url.spec.whatwg.org/#absolute-url-with-fragment-string "https://url.spec.whatwg.org/#absolute-url-with-fragment-string").

       - If location is a [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") whose [fragment](https://url.spec.whatwg.org/#concept-url-fragment "https://url.spec.whatwg.org/#concept-url-fragment") is null, then set
         location’s [fragment](https://url.spec.whatwg.org/#concept-url-fragment "https://url.spec.whatwg.org/#concept-url-fragment") to requestFragment.

         This ensures that synthetic (indeed, all) responses follow the processing model for
         redirects defined by HTTP. [[HTTP]](#biblio-http "HTTP Semantics")

         - Return location.

The [location URL](#concept-response-location-url "#concept-response-location-url") algorithm is exclusively used for redirect
handling in this standard and in HTML’s navigate algorithm which handles redirects
manually. [[HTML]](#biblio-html "HTML Standard")

#### 2.2.7. Miscellaneous

A potential destination is
"`fetch`" or a [destination](#concept-request-destination "#concept-request-destination") which is not the empty string.

To translate a
[potential destination](#concept-potential-destination "#concept-potential-destination") potentialDestination, run these steps:

1. If potentialDestination is "`fetch`", then return the empty string.

   - [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): potentialDestination is a [destination](#concept-request-destination "#concept-request-destination").

     - Return potentialDestination.

### 2.3. Authentication entries

An authentication entry and a proxy-authentication entry are
tuples of username, password, and realm, used for HTTP authentication and HTTP proxy authentication,
and associated with one or more [requests](#concept-request "#concept-request").

User agents should allow both to be cleared together with HTTP cookies and similar tracking
functionality.

Further details are defined by HTTP. [[HTTP]](#biblio-http "HTTP Semantics") [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

### 2.4. Fetch groups

Each [environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object") has an associated
fetch group, which holds a [fetch group](#concept-fetch-group "#concept-fetch-group").

A fetch group holds information about fetches.

A [fetch group](#concept-fetch-group "#concept-fetch-group") has associated:

fetch records: A [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of [fetch records](#fetch-record "#fetch-record"). deferred fetch records: A [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of [deferred fetch records](#deferred-fetch-record "#deferred-fetch-record").

A fetch record is a [struct](https://infra.spec.whatwg.org/#struct "https://infra.spec.whatwg.org/#struct") with the following
[items](https://infra.spec.whatwg.org/#struct-item "https://infra.spec.whatwg.org/#struct-item"):

request: A [request](#concept-request "#concept-request"). controller: A [fetch controller](#fetch-controller "#fetch-controller") or null.

---

A deferred fetch record is a [struct](https://infra.spec.whatwg.org/#struct "https://infra.spec.whatwg.org/#struct") used to maintain state needed to
invoke a fetch at a later time, e.g., when a document is unloaded or becomes not
[fully active](https://html.spec.whatwg.org/multipage/document-sequences.html#fully-active "https://html.spec.whatwg.org/multipage/document-sequences.html#fully-active"). It has the following [items](https://infra.spec.whatwg.org/#struct-item "https://infra.spec.whatwg.org/#struct-item"):

request: A [request](#concept-request "#concept-request"). notify invoked: An algorithm accepting no arguments. invoke state (default "`pending`"): "`pending`", "`sent`", or "`aborted`".

---

When a [fetch group](#concept-fetch-group "#concept-fetch-group") fetchGroup is
terminated:

1. [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") [fetch record](#concept-fetch-record "#concept-fetch-record") record of
   fetchGroup’s [fetch records](#concept-fetch-record "#concept-fetch-record"), if record’s
   [controller](#concept-fetch-record-fetch "#concept-fetch-record-fetch") is non-null and record’s
   [request](#concept-fetch-record-request "#concept-fetch-record-request")’s [done flag](#done-flag "#done-flag") is unset and [keepalive](#request-keepalive-flag "#request-keepalive-flag") is
   false, [terminate](#fetch-controller-terminate "#fetch-controller-terminate") record’s
   [controller](#concept-fetch-record-fetch "#concept-fetch-record-fetch").

   - [Process deferred fetches](#process-deferred-fetches "#process-deferred-fetches") for fetchGroup.

### 2.5. Resolving domains

[![(This is a tracking vector.)](https://resources.whatwg.org/tracking-vector.svg "There is a tracking vector here.")](https://infra.spec.whatwg.org/#tracking-vector "https://infra.spec.whatwg.org/#tracking-vector") To
resolve an origin, given a
[network partition key](#network-partition-key "#network-partition-key") key and an [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin") origin:

1. If origin’s [host](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-host "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-host") is an [IP address](https://url.spec.whatwg.org/#ip-address "https://url.spec.whatwg.org/#ip-address"), then return
   « origin’s [host](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-host "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-host") ».

   - If origin’s [host](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-host "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-host")’s [public suffix](https://url.spec.whatwg.org/#host-public-suffix "https://url.spec.whatwg.org/#host-public-suffix") is
     "`localhost`" or "`localhost.`", then return « `::1`,
     `127.0.0.1` ».

     - Perform an [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") operation to turn origin into a
       [set](https://infra.spec.whatwg.org/#ordered-set "https://infra.spec.whatwg.org/#ordered-set") of one or more [IP addresses](https://url.spec.whatwg.org/#ip-address "https://url.spec.whatwg.org/#ip-address").

       It is also [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") whether other operations might be performed to get
       connection information beyond just [IP addresses](https://url.spec.whatwg.org/#ip-address "https://url.spec.whatwg.org/#ip-address"). For example, if origin’s
       [scheme](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-scheme "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-scheme") is an [HTTP(S) scheme](#http-scheme "#http-scheme"), the implementation might perform a DNS query
       for HTTPS RRs. [[SVCB]](#biblio-svcb "Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)")

       If this operation succeeds, return the [set](https://infra.spec.whatwg.org/#ordered-set "https://infra.spec.whatwg.org/#ordered-set") of [IP addresses](https://url.spec.whatwg.org/#ip-address "https://url.spec.whatwg.org/#ip-address") and any
       additional [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") information.

       - Return failure.

The results of [resolve an origin](#resolve-an-origin "#resolve-an-origin") may be cached. If they are cached, key should
be used as part of the cache key.

Typically this operation would involve DNS and as such caching can happen on DNS servers without
key being taken into account. Depending on the implementation it might also not be
possible to take key into account locally. [[RFC1035]](#biblio-rfc1035 "Domain names - implementation and specification")

The order of the [IP addresses](https://url.spec.whatwg.org/#ip-address "https://url.spec.whatwg.org/#ip-address") that the [resolve an origin](#resolve-an-origin "#resolve-an-origin") algorithm can return
can differ between invocations.

The particulars (apart from the cache key) are not tied down as they are not pertinent to the
system the Fetch Standard establishes. Other documents ought not to build on this primitive without
having a considered discussion with the Fetch Standard community first.

### 2.6. Connections

A user agent has an associated connection pool. A
[connection pool](#concept-connection-pool "#concept-connection-pool") is an [ordered set](https://infra.spec.whatwg.org/#ordered-set "https://infra.spec.whatwg.org/#ordered-set") of zero or more
connections. Each [connection](#concept-connection "#concept-connection") is
identified by an associated key (a [network partition key](#network-partition-key "#network-partition-key")),
origin (an [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin")), and credentials
(a boolean).

Each [connection](#concept-connection "#concept-connection") has an associated
timing info (a
[connection timing info](#connection-timing-info "#connection-timing-info")).

A connection timing info is a [struct](https://infra.spec.whatwg.org/#struct "https://infra.spec.whatwg.org/#struct") used to maintain timing
information pertaining to the process of obtaining a connection. It has the following
[items](https://infra.spec.whatwg.org/#struct-item "https://infra.spec.whatwg.org/#struct-item"):

domain lookup start time (default 0) domain lookup end time (default 0) connection start time (default 0) connection end time (default 0) secure connection start time (default 0): A `DOMHighResTimeStamp`. ALPN negotiated protocol (default the empty [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence")): A [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence").

To clamp and coarsen connection timing info, given a
[connection timing info](#connection-timing-info "#connection-timing-info") timingInfo, a `DOMHighResTimeStamp`
defaultStartTime, and a boolean crossOriginIsolatedCapability, run these
steps:

1. If timingInfo’s [connection start time](#connection-timing-info-connection-start-time "#connection-timing-info-connection-start-time") is
   less than defaultStartTime, then return a new [connection timing info](#connection-timing-info "#connection-timing-info") whose
   [domain lookup start time](#connection-timing-info-domain-lookup-start-time "#connection-timing-info-domain-lookup-start-time") is defaultStartTime,
   [domain lookup end time](#connection-timing-info-domain-lookup-end-time "#connection-timing-info-domain-lookup-end-time") is defaultStartTime,
   [connection start time](#connection-timing-info-connection-start-time "#connection-timing-info-connection-start-time") is defaultStartTime,
   [connection end time](#connection-timing-info-connection-end-time "#connection-timing-info-connection-end-time") is defaultStartTime,
   [secure connection start time](#connection-timing-info-secure-connection-start-time "#connection-timing-info-secure-connection-start-time") is defaultStartTime,
   and [ALPN negotiated protocol](#connection-timing-info-alpn-negotiated-protocol "#connection-timing-info-alpn-negotiated-protocol") is timingInfo’s
   [ALPN negotiated protocol](#connection-timing-info-alpn-negotiated-protocol "#connection-timing-info-alpn-negotiated-protocol").

   - Return a new [connection timing info](#connection-timing-info "#connection-timing-info") whose
     [domain lookup start time](#connection-timing-info-domain-lookup-start-time "#connection-timing-info-domain-lookup-start-time") is the result of [coarsen time](https://w3c.github.io/hr-time/#dfn-coarsen-time "https://w3c.github.io/hr-time/#dfn-coarsen-time")
     given timingInfo’s [domain lookup start time](#connection-timing-info-domain-lookup-start-time "#connection-timing-info-domain-lookup-start-time") and
     crossOriginIsolatedCapability,
     [domain lookup end time](#connection-timing-info-domain-lookup-end-time "#connection-timing-info-domain-lookup-end-time") is the result of [coarsen time](https://w3c.github.io/hr-time/#dfn-coarsen-time "https://w3c.github.io/hr-time/#dfn-coarsen-time")
     given timingInfo’s [domain lookup end time](#connection-timing-info-domain-lookup-end-time "#connection-timing-info-domain-lookup-end-time") and
     crossOriginIsolatedCapability, [connection start time](#connection-timing-info-connection-start-time "#connection-timing-info-connection-start-time")
     is the result of [coarsen time](https://w3c.github.io/hr-time/#dfn-coarsen-time "https://w3c.github.io/hr-time/#dfn-coarsen-time") given timingInfo’s
     [connection start time](#connection-timing-info-connection-start-time "#connection-timing-info-connection-start-time") and
     crossOriginIsolatedCapability, [connection end time](#connection-timing-info-connection-end-time "#connection-timing-info-connection-end-time")
     is the result of [coarsen time](https://w3c.github.io/hr-time/#dfn-coarsen-time "https://w3c.github.io/hr-time/#dfn-coarsen-time") given timingInfo’s
     [connection end time](#connection-timing-info-connection-end-time "#connection-timing-info-connection-end-time") and
     crossOriginIsolatedCapability,
     [secure connection start time](#connection-timing-info-secure-connection-start-time "#connection-timing-info-secure-connection-start-time") is the result of
     [coarsen time](https://w3c.github.io/hr-time/#dfn-coarsen-time "https://w3c.github.io/hr-time/#dfn-coarsen-time") given timingInfo’s
     [connection end time](#connection-timing-info-connection-end-time "#connection-timing-info-connection-end-time") and
     crossOriginIsolatedCapability, and
     [ALPN negotiated protocol](#connection-timing-info-alpn-negotiated-protocol "#connection-timing-info-alpn-negotiated-protocol") is timingInfo’s
     [ALPN negotiated protocol](#connection-timing-info-alpn-negotiated-protocol "#connection-timing-info-alpn-negotiated-protocol").

---

A new connection setting is "`no`", "`yes`", or
"`yes-and-dedicated`".

To obtain a connection, given a
[network partition key](#network-partition-key "#network-partition-key") key, [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") url, boolean
credentials, an optional [new connection setting](#new-connection-setting "#new-connection-setting") new (default
"`no`"), an optional boolean
requireUnreliable (default false), and an
optional [WebTransport-hash list](#webtransport-hash-list "#webtransport-hash-list")
webTransportHashes (default « »):

1. If new is "`no`":

   1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): webTransportHashes [is empty](https://infra.spec.whatwg.org/#list-is-empty "https://infra.spec.whatwg.org/#list-is-empty").

      - Let connections be a set of [connections](#concept-connection "#concept-connection") in the user agent’s
        [connection pool](#concept-connection-pool "#concept-connection-pool") whose [key](#connection-key "#connection-key") is key,
        [origin](#connection-origin "#connection-origin") is url’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin"), and
        [credentials](#connection-credentials "#connection-credentials") is credentials.

        - If connections is not empty and requireUnreliable is false, then
          return one of connections.

          - If there is a [connection](#concept-connection "#concept-connection") capable of supporting unreliable transport in
            connections, e.g., HTTP/3, then return that [connection](#concept-connection "#concept-connection").- Let proxies be the result of finding proxies for url in an
     [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") manner. If there are no proxies, let proxies be
     « "`DIRECT`" ».

     This is where non-standard technology such as
     [Web Proxy Auto-Discovery Protocol (WPAD)](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol "https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol")
     and [proxy auto-config (PAC)](https://en.wikipedia.org/wiki/Proxy_auto-config "https://en.wikipedia.org/wiki/Proxy_auto-config") come
     into play. The "`DIRECT`" value means to not use a proxy for this particular
     url.

     - Let timingInfo be a new [connection timing info](#connection-timing-info "#connection-timing-info").

       - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") proxy of proxies:

         1. Set timingInfo’s [domain lookup start time](#connection-timing-info-domain-lookup-start-time "#connection-timing-info-domain-lookup-start-time")
            to the [unsafe shared current time](https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time "https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time").

            - Let hosts be « url’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin")’s
              [host](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-host "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-host") ».

              - If proxy is "`DIRECT`", then set hosts to the result of
                running [resolve an origin](#resolve-an-origin "#resolve-an-origin") given key and url’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin").

                - If hosts is failure, then [continue](https://infra.spec.whatwg.org/#iteration-continue "https://infra.spec.whatwg.org/#iteration-continue").

                  - Set timingInfo’s [domain lookup end time](#connection-timing-info-domain-lookup-end-time "#connection-timing-info-domain-lookup-end-time") to
                    the [unsafe shared current time](https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time "https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time").

                    - Let connection be the result of running this step: run [create a connection](#create-a-connection "#create-a-connection")
                      given key, url’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin"), credentials,
                      proxy, an [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") [host](https://url.spec.whatwg.org/#concept-host "https://url.spec.whatwg.org/#concept-host") from hosts,
                      timingInfo, requireUnreliable, and webTransportHashes an
                      [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") number of times, [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel") from each other, and wait for
                      at least 1 to return a value. In an [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") manner, select a value to
                      return from the returned values and return it. Any other returned values that are
                      [connections](#concept-connection "#concept-connection") may be closed.

                      Essentially this allows an implementation to pick one or more
                      [IP addresses](https://url.spec.whatwg.org/#ip-address "https://url.spec.whatwg.org/#ip-address") from the return value of [resolve an origin](#resolve-an-origin "#resolve-an-origin") (assuming
                      proxy is "`DIRECT`") and race them against each other, favor
                      [IPv6 addresses](https://url.spec.whatwg.org/#concept-ipv6 "https://url.spec.whatwg.org/#concept-ipv6"), retry in case of a timeout, etc.

                      - If connection is failure, then [continue](https://infra.spec.whatwg.org/#iteration-continue "https://infra.spec.whatwg.org/#iteration-continue").

                        - If new is not "`yes-and-dedicated`", then [append](https://infra.spec.whatwg.org/#set-append "https://infra.spec.whatwg.org/#set-append")
                          connection to the user agent’s [connection pool](#concept-connection-pool "#concept-connection-pool").

                          - Return connection.- Return failure.

This is intentionally a little vague as there are a lot of nuances to connection
management that are best left to the discretion of implementers. Describing this helps explain the
`<link rel=preconnect>` feature and clearly stipulates that [connections](#concept-connection "#concept-connection") are
keyed on [credentials](#credentials "#credentials"). The latter clarifies that, e.g., TLS session identifiers are not
reused across [connections](#concept-connection "#concept-connection") whose [credentials](#connection-credentials "#connection-credentials") are false with
[connections](#concept-connection "#concept-connection") whose [credentials](#connection-credentials "#connection-credentials") are true.

---

To create a connection, given a [network partition key](#network-partition-key "#network-partition-key") key,
[origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin") origin, boolean credentials, string proxy,
[host](https://url.spec.whatwg.org/#concept-host "https://url.spec.whatwg.org/#concept-host") host, [connection timing info](#connection-timing-info "#connection-timing-info") timingInfo,
boolean requireUnreliable, and a [WebTransport-hash list](#webtransport-hash-list "#webtransport-hash-list")
webTransportHashes:

1. Set timingInfo’s [connection start time](#connection-timing-info-connection-start-time "#connection-timing-info-connection-start-time") to the
   [unsafe shared current time](https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time "https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time").

   - Let connection be a new [connection](#concept-connection "#concept-connection") whose [key](#connection-key "#connection-key") is
     key, [origin](#connection-origin "#connection-origin") is origin,
     [credentials](#connection-credentials "#connection-credentials") is credentials, and [timing info](#concept-connection-timing-info "#concept-connection-timing-info")
     is timingInfo. [Record connection timing info](#record-connection-timing-info "#record-connection-timing-info") given connection
     and use connection to establish an HTTP connection to host, taking
     proxy and origin into account, with the following caveats: [[HTTP]](#biblio-http "HTTP Semantics")
     [[HTTP1]](#biblio-http1 "HTTP/1.1") [[TLS]](#biblio-tls "The Transport Layer Security (TLS) Protocol Version 1.3")

     * If requireUnreliable is true, then establish a connection capable of unreliable
       transport, e.g., an HTTP/3 connection. [[HTTP3]](#biblio-http3 "HTTP/3")

       * When establishing a connection capable of unreliable transport, enable options that are
         necessary for WebTransport. For HTTP/3, this means including
         `SETTINGS_ENABLE_WEBTRANSPORT` with a value of `1` and
         `H3_DATAGRAM` with a value of `1` in the initial `SETTINGS`
         frame. [[WEBTRANSPORT-HTTP3]](#biblio-webtransport-http3 "WebTransport over HTTP/3") [[HTTP3-DATAGRAM]](#biblio-http3-datagram "HTTP Datagrams and the Capsule Protocol")

         * If credentials is false, then do not send a TLS client certificate.

           * If webTransportHashes [is not empty](https://infra.spec.whatwg.org/#list-is-empty "https://infra.spec.whatwg.org/#list-is-empty"), instead of using the default
             certificate verification algorithm, consider the server certificate valid if it meets the
             [custom certificate requirements](https://w3c.github.io/webtransport/#custom-certificate-requirements "https://w3c.github.io/webtransport/#custom-certificate-requirements") and if
             [verifying the certificate hash](https://w3c.github.io/webtransport/#verify-a-certificate-hash "https://w3c.github.io/webtransport/#verify-a-certificate-hash") against webTransportHashes returns
             true. If either condition is not met, then return failure.

             * If establishing a connection does not succeed (e.g., a UDP, TCP, or TLS error), then
               return failure.- Set timingInfo’s [ALPN negotiated protocol](#connection-timing-info-alpn-negotiated-protocol "#connection-timing-info-alpn-negotiated-protocol") to
       connection’s ALPN Protocol ID, with the following caveats: [[RFC7301]](#biblio-rfc7301 "Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension")

       * When a proxy is configured, if a tunnel connection is established then this must be the
         ALPN Protocol ID of the tunneled protocol, otherwise it must be the ALPN Protocol ID of the first
         hop to the proxy.

         * In case the user agent is using an experimental, non-registered protocol, the user agent must
           use the used ALPN Protocol ID, if any. If ALPN was not used for protocol negotiations, the user
           agent may use another descriptive string.

           timingInfo’s
           [ALPN negotiated protocol](#connection-timing-info-alpn-negotiated-protocol "#connection-timing-info-alpn-negotiated-protocol") is intended to identify the network
           protocol in use regardless of how it was actually negotiated; that is, even if ALPN is not used
           to negotiate the network protocol, this is the ALPN Protocol IDs that indicates the protocol in
           use.

       IANA maintains a
       [list of ALPN Protocol IDs](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids "https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids").

       - Return connection.

---

To record connection timing info given a [connection](#concept-connection "#concept-connection")
connection, let timingInfo be connection’s
[timing info](#concept-connection-timing-info "#concept-connection-timing-info") and observe these requirements:

* timingInfo’s [connection end time](#connection-timing-info-connection-end-time "#connection-timing-info-connection-end-time") should be the
  [unsafe shared current time](https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time "https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time") immediately after establishing the connection to the
  server or proxy, as follows:

  + The returned time must include the time interval to establish the transport connection, as
    well as other time intervals such as SOCKS authentication. It must include the time interval to
    complete enough of the TLS handshake to request the resource.

    + If the user agent used TLS False Start for this connection, this interval must not include
      the time needed to receive the server’s Finished message. [[RFC7918]](#biblio-rfc7918 "Transport Layer Security (TLS) False Start")

      + If the user agent sends the request with early data without waiting for the full handshake
        to complete, this interval must not include the time needed to receive the server’s ServerHello
        message. [[RFC8470]](#biblio-rfc8470 "Using Early Data in HTTP")

        + If the user agent waits for full handshake completion to send the request, this interval
          includes the full TLS handshake even if other requests were sent using early data on
          connection.

  Suppose the user agent establishes an HTTP/2
  connection over TLS 1.3 to send a `GET` request and a `POST` request. It
  sends the ClientHello at time t1 and then sends the `GET` request with early
  data. The `POST` request is not safe ([[HTTP]](#biblio-http "HTTP Semantics"), section 9.2.1), so the user
  agent waits to complete the handshake at time t2 before sending it. Although both
  requests used the same connection, the `GET` request reports a connection end time of
  t1, while the `POST` request reports t2.

  * If a secure transport is used, timingInfo’s
    [secure connection start time](#connection-timing-info-secure-connection-start-time "#connection-timing-info-secure-connection-start-time") should be the result of calling
    [unsafe shared current time](https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time "https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time") immediately before starting the handshake process to
    secure connection. [[TLS]](#biblio-tls "The Transport Layer Security (TLS) Protocol Version 1.3")

    * If connection is an HTTP/3 connection, timingInfo’s
      [connection start time](#connection-timing-info-connection-start-time "#connection-timing-info-connection-start-time") and timingInfo’s
      [secure connection start time](#connection-timing-info-secure-connection-start-time "#connection-timing-info-secure-connection-start-time") must be equal. (In HTTP/3
      the secure transport handshake process is performed as part of the initial connection setup.)
      [[HTTP3]](#biblio-http3 "HTTP/3")

The [clamp and coarsen connection timing info](#clamp-and-coarsen-connection-timing-info "#clamp-and-coarsen-connection-timing-info") algorithm ensures that
details of reused connections are not exposed and time values are coarsened.

### 2.7. Network partition keys

A network partition key is a tuple consisting of a [site](https://html.spec.whatwg.org/multipage/browsers.html#site "https://html.spec.whatwg.org/multipage/browsers.html#site") and null
or an [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") value.

To determine the network partition key, given an
[environment](https://html.spec.whatwg.org/multipage/webappapis.html#environment "https://html.spec.whatwg.org/multipage/webappapis.html#environment") environment:

1. Let topLevelOrigin be environment’s
   [top-level origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-origin "https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-origin").

   - If topLevelOrigin is null, then set topLevelOrigin to
     environment’s [top-level creation URL](https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-creation-url "https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-creation-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin").

     - [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): topLevelOrigin is an [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin").

       - Let topLevelSite be the result of [obtaining a site](https://html.spec.whatwg.org/multipage/browsers.html#obtain-a-site "https://html.spec.whatwg.org/multipage/browsers.html#obtain-a-site"),
         given topLevelOrigin.

         - Let secondKey be null or an [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") value.

           The second key is intentionally a little vague as the finer points are still
           evolving. See [issue #1035](https://github.com/whatwg/fetch/issues/1035 "https://github.com/whatwg/fetch/issues/1035").

           - Return (topLevelSite, secondKey).

To determine the network partition key, given a [request](#concept-request "#concept-request")
request:

1. If request’s [reserved client](#concept-request-reserved-client "#concept-request-reserved-client") is non-null, then return the
   result of [determining the network partition key](#determine-the-network-partition-key "#determine-the-network-partition-key") given request’s
   [reserved client](#concept-request-reserved-client "#concept-request-reserved-client").

   - If request’s [client](#concept-request-client "#concept-request-client") is non-null, then return the
     result of [determining the network partition key](#determine-the-network-partition-key "#determine-the-network-partition-key") given request’s
     [client](#concept-request-client "#concept-request-client").

     - Return null.

### 2.8. HTTP cache partitions

To determine the HTTP cache partition, given a [request](#concept-request "#concept-request") request:

1. Let key be the result of [determining the network partition key](#request-determine-the-network-partition-key "#request-determine-the-network-partition-key")
   given request.

   - If key is null, then return null.

     - Return the unique HTTP cache associated with key. [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

### 2.9. Port blocking

New protocols can avoid the need for blocking ports by negotiating the protocol
through TLS using ALPN. The protocol cannot be spoofed through HTTP requests in that case.
[[RFC7301]](#biblio-rfc7301 "Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension")

To determine whether fetching a [request](#concept-request "#concept-request") request
should be blocked due to a bad port:

1. Let url be request’s [current URL](#concept-request-current-url "#concept-request-current-url").

   - If url’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is an [HTTP(S) scheme](#http-scheme "#http-scheme") and url’s
     [port](https://url.spec.whatwg.org/#concept-url-port "https://url.spec.whatwg.org/#concept-url-port") is a [bad port](#bad-port "#bad-port"), then return **blocked**.

     - Return **allowed**.

A [port](https://url.spec.whatwg.org/#concept-url-port "https://url.spec.whatwg.org/#concept-url-port") is a
bad port if it is listed in the first column of the following table.

|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Port Typical service|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 0 —​|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 1 tcpmux|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 7 echo|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 9 discard|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 11 systat|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 13 daytime|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 15 netstat|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 17 qotd|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 19 chargen|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 20 ftp-data|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 21 ftp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 22 ssh|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 23 telnet|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 25 smtp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 37 time|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 42 name|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 43 nicname|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 53 domain|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 69 tftp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 77 —​|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 79 finger|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 87 —​|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 95 supdup|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 101 hostname|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 102 iso-tsap|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 103 gppitnp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 104 acr-nema|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 109 pop2|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 110 pop3|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 111 sunrpc|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 113 auth|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 115 sftp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 117 uucp-path|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 119 nntp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 123 ntp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 135 epmap|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 137 netbios-ns|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 139 netbios-ssn|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 143 imap|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 161 snmp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 179 bgp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 389 ldap|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 427 svrloc|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 465 submissions|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 512 exec|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 513 login|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 514 shell|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 515 printer|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 526 tempo|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 530 courier|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 531 chat|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 532 netnews|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 540 uucp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 548 afp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 554 rtsp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 556 remotefs|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 563 nntps|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 587 submission|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 601 syslog-conn|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 636 ldaps|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 989 ftps-data|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 990 ftps|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 993 imaps|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 995 pop3s|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 1719 h323gatestat|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 1720 h323hostcall|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 1723 pptp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 2049 nfs|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 3659 apple-sasl|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 4045 npp|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 4190 sieve|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 5060 sip|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 5061 sips|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 6000 x11|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 6566 sane-port|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 6665 ircu|  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 6666 ircu|  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 6667 ircu|  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | 6668 ircu|  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | | 6669 ircu|  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | | 6679 osaut|  |  |  |  | | --- | --- | --- | --- | | 6697 ircs-u|  |  | | --- | --- | | 10080 amanda | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |

### 2.10. Should response to request be blocked due to its MIME type?

Run these steps:

1. Let mimeType be the result of [extracting a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type")
   from response’s [header list](#concept-response-header-list "#concept-response-header-list").

   - If mimeType is failure, then return **allowed**.

     - Let destination be request’s [destination](#concept-request-destination "#concept-request-destination").

       - If destination is [script-like](#request-destination-script-like "#request-destination-script-like") and one of the
         following is true, then return **blocked**:

         * mimeType’s [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence "https://mimesniff.spec.whatwg.org/#mime-type-essence") [starts with](https://infra.spec.whatwg.org/#string-starts-with "https://infra.spec.whatwg.org/#string-starts-with")
           "`audio/`", "`image/`", or "`video/`".* mimeType’s [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence "https://mimesniff.spec.whatwg.org/#mime-type-essence") is "`text/csv`".- Return **allowed**.

3. HTTP extensions
------------------

### 3.1. Cookies

The ``Cookie`` request header and ``Set-Cookie`` response headers are
largely defined in their own specifications. We define additional infrastructure to be able to use
them conveniently here. [[COOKIES]](#biblio-cookies "Cookies: HTTP State Management Mechanism").

#### 3.1.1. ``Cookie`` header

To append a request ``Cookie`` header, given a [request](#concept-request "#concept-request")
request:

1. If the user agent is configured to disable cookies for request, then it should
   return.

   - Let sameSite be the result of [determining the same-site mode](#determine-the-same-site-mode "#determine-the-same-site-mode") for request.

     - Let isSecure be true if request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s
       [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is "`https`"; otherwise false.

       - Let httpOnlyAllowed be true.

         True follows from this being invoked from [fetch](#concept-fetch "#concept-fetch"), as opposed to the
         `document.cookie` getter steps for instance.

         - Let cookies be the result of running [retrieve cookies](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-retrieve-cookies "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-retrieve-cookies") given isSecure,
           request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [host](https://url.spec.whatwg.org/#concept-url-host "https://url.spec.whatwg.org/#concept-url-host"), request’s
           [current URL](#concept-request-current-url "#concept-request-current-url")’s [path](https://url.spec.whatwg.org/#concept-url-path "https://url.spec.whatwg.org/#concept-url-path"), httpOnlyAllowed, and sameSite.

           The cookie store returns an ordered list of cookies

           - If cookies [is empty](https://infra.spec.whatwg.org/#list-is-empty "https://infra.spec.whatwg.org/#list-is-empty"), then return.

             - Let value be the result of running [serialize cookies](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-serialize-cookies "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-serialize-cookies") given cookies.

               - [Append](#concept-header-list-append "#concept-header-list-append") (``Cookie``, value) to
                 request’s [header list](#concept-request-header-list "#concept-request-header-list").

#### 3.1.2. ``Set-Cookie`` header

To parse and store response ``Set-Cookie`` headers, given a
[request](#concept-request "#concept-request") request and a [response](#concept-response "#concept-response") response:

1. If the user agent is configured to disable cookies for request, then it should
   return.

   - Let allowNonHostOnlyCookieForPublicSuffix be false.

     - Let isSecure be true if request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s
       [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is "`https`"; otherwise false.

       - Let httpOnlyAllowed be true.

         True follows from this being invoked from [fetch](#concept-fetch "#concept-fetch"), as opposed to the
         `document.cookie` getter steps for instance.

         - Let sameSiteStrictOrLaxAllowed be true if the result of [determine the same-site mode](#determine-the-same-site-mode "#determine-the-same-site-mode")
           for request is "`strict-or-less`"; otherwise false.

           - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") header of response’s
             [header list](#concept-response-header-list "#concept-response-header-list"):

             1. If header’s [name](#concept-header-name "#concept-header-name") is not a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match
                for ``Set-Cookie``, then [continue](https://infra.spec.whatwg.org/#iteration-continue "https://infra.spec.whatwg.org/#iteration-continue").

                - [Parse and store a cookie](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-parse-and-store-a-cookie "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-parse-and-store-a-cookie") given header’s [value](#concept-header-value "#concept-header-value"),
                  isSecure, request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [host](https://url.spec.whatwg.org/#concept-url-host "https://url.spec.whatwg.org/#concept-url-host"),
                  request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [path](https://url.spec.whatwg.org/#concept-url-path "https://url.spec.whatwg.org/#concept-url-path"), httpOnlyAllowed,
                  allowNonHostOnlyCookieForPublicSuffix, and sameSiteStrictOrLaxAllowed.

                  - [Garbage collect cookies](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-garbage-collect-cookies "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-garbage-collect-cookies") given request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s
                    [host](https://url.spec.whatwg.org/#concept-url-host "https://url.spec.whatwg.org/#concept-url-host").

             As noted elsewhere the ``Set-Cookie`` header cannot be combined and
             therefore each occurrence is processed independently. This is not allowed for any other header.

#### 3.1.3. Cookie infrastructure

To determine the same-site mode for a given [request](#concept-request "#concept-request") request:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [method](#concept-request-method "#concept-request-method") is "`GET`"
   or "`POST`".

   - If request’s [top-level navigation initiator origin](#request-top-level-navigation-initiator-origin "#request-top-level-navigation-initiator-origin") is not
     null and is not [same site](https://html.spec.whatwg.org/multipage/browsers.html#same-site "https://html.spec.whatwg.org/multipage/browsers.html#same-site") with request’s [URL](#concept-request-url "#concept-request-url")’s
     [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin"), then return "`unset-or-less`".

     - If request’s [method](#concept-request-method "#concept-request-method") is "`GET`" and
       request’s [destination](#concept-request-destination "#concept-request-destination") is "document", then return
       "`lax-or-less`".

       - If request’s [client](#concept-request-client "#concept-request-client")’s
         [has cross-site ancestor](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-has-cross-site-ancestor "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-has-cross-site-ancestor") is true, then return
         "`unset-or-less`".

         - If request’s [redirect-taint](#concept-request-tainted-origin "#concept-request-tainted-origin") is "`cross-site`", then
           return "`unset-or-less`".

           - Return "`strict-or-less`".

To obtain a serialized cookie default path given a [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url")
url:

1. Let cloneURL be a clone of url.

   - Set cloneURL’s [path](https://url.spec.whatwg.org/#concept-url-path "https://url.spec.whatwg.org/#concept-url-path") to the [cookie default path](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-cookie-default-path "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies#name-cookie-default-path") of
     cloneURL’s [path](https://url.spec.whatwg.org/#concept-url-path "https://url.spec.whatwg.org/#concept-url-path").

     - Return the [URL path serialization](https://url.spec.whatwg.org/#url-path-serializer "https://url.spec.whatwg.org/#url-path-serializer") of cloneURL.

### 3.2. ``Origin`` header

The ``Origin``
request [header](#concept-header "#concept-header") indicates where a
[fetch](#concept-fetch "#concept-fetch") originates from.

The `[`Origin`](#http-origin "#http-origin")` header is a version of the
``Referer`` [sic] header that does not reveal a [path](https://url.spec.whatwg.org/#concept-url-path "https://url.spec.whatwg.org/#concept-url-path"). It is used for all
[HTTP fetches](#concept-http-fetch "#concept-http-fetch") whose [request](#concept-request "#concept-request")’s
[response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is "`cors`", as well as those where
[request](#concept-request "#concept-request")’s [method](#concept-request-method "#concept-request-method") is neither ``GET`` nor
``HEAD``. Due to compatibility constraints it is not included in all
[fetches](#concept-fetch "#concept-fetch").

Its possible [values](#concept-header-value "#concept-header-value") are all the return values of
[byte-serializing a request origin](#byte-serializing-a-request-origin "#byte-serializing-a-request-origin"), given a [request](#concept-request "#concept-request"). These are represented by
the following [ABNF](#abnf "#abnf"):

```
serialized-ipv4   = dec-octet "." dec-octet "." dec-octet "." dec-octet
dec-octet         = DIGIT                 ; 0-9
                  / %x31-39 DIGIT         ; 10-99
                  / "1" 2DIGIT            ; 100-199
                  / "2" %x30-34 DIGIT     ; 200-249
                  / "25" %x30-35          ; 250-255

serialized-ipv6   =                            7( h16 ":" ) h16
                  /                       "::" 5( h16 ":" ) h16
                  / [               h16 ] "::" 4( h16 ":" ) h16
                  / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) h16
                  / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) h16
                  / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   h16
                  / [ *4( h16 ":" ) h16 ] "::"              h16
                  / [ *5( h16 ":" ) h16 ] "::"
h16               = "0" / ( non-zero-hex 0*3hex )
non-zero-hex      = %x31-39 / %x61-66 ; '1'-'9' or lowercase 'a'-'f'
hex               = %x30-39 / %x61-66 ; '0'-'9' or lowercase 'a'-'f

lower-alpha       = %x61-7A
lower-alphanum    = lower-alpha / DIGIT
domain-label      = lower-alphanum / ( lower-alphanum *( lower-alphanum / "-" ) lower-alphanum )
serialized-domain = *( domain-label "." ) domain-label

serialized-scheme = lower-alpha *( lower-alphanum / "+" / "-" / "." )
serialized-host   = serialized-ipv4 / "[" serialized-ipv6 "]" / serialized-domain
serialized-port   = 1*5DIGIT

serialized-origin = serialized-scheme "://" serialized-host [ ":" serialized-port ]
origin-or-null    = serialized-origin / %s"null" ; case-sensitive

Origin = origin-or-null
```

This supplants the definition in The Web Origin Concept. [[ORIGIN]](#biblio-origin "The Web Origin Concept")

The origin serialization defined here is more constrained than [[RFC3986]](#biblio-rfc3986 "Uniform Resource Identifier (URI): Generic Syntax")’s grammar in two
substantial ways. First, scheme and domains serializations are all lower case ASCII, without
percent encoding. Second, following the recommendations of [URL § 3.6 Host serializing](https://url.spec.whatwg.org/#host-serializing "https://url.spec.whatwg.org/#host-serializing") and [[RFC5952]](#biblio-rfc5952 "A Recommendation for IPv6 Address Text Representation"),
IPv6 addresses are limited as follows:

* The least-significant digits cannot be represented as an IPv4 address.* Leading zeros are forbidden.* All hex characters are lowercase.* "::" can’t elide only a single "0" block, so we allow at most 6 blocks when "::" is present.

---

To append a request ``Origin`` header,
given a [request](#concept-request "#concept-request") request, run these steps:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [origin](#concept-request-origin "#concept-request-origin") is not
   "`client`".

   - Let serializedOrigin be the result of [byte-serializing a request origin](#byte-serializing-a-request-origin "#byte-serializing-a-request-origin")
     with request.

     - If request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is "`cors`" or
       request’s [mode](#concept-request-mode "#concept-request-mode") is either "`websocket`" or "`webtransport`", then
       [append](#concept-header-list-append "#concept-header-list-append") (``Origin``, serializedOrigin) to
       request’s [header list](#concept-request-header-list "#concept-request-header-list").

       - Otherwise, if request’s [method](#concept-request-method "#concept-request-method") is neither ``GET`` nor
         ``HEAD``, then:

         1. If request’s [mode](#concept-request-mode "#concept-request-mode") is not "`cors`",
            then switch on request’s [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy"):

            "`no-referrer`": Set serializedOrigin to ``null``. "`no-referrer-when-downgrade`" "`strict-origin`" "`strict-origin-when-cross-origin`": If request’s [origin](#concept-request-origin "#concept-request-origin") is a [tuple origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-tuple "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-tuple"), its scheme is "`https`", and request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s scheme is not "`https`", then set serializedOrigin to ``null``. "`same-origin`": If request’s [origin](#concept-request-origin "#concept-request-origin") is not [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin"), then set serializedOrigin to ``null``. Otherwise: Do nothing.

            - [Append](#concept-header-list-append "#concept-header-list-append") (``Origin``, serializedOrigin) to
              request’s [header list](#concept-request-header-list "#concept-request-header-list").

A [request](#concept-request "#concept-request")’s [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy") is taken into account for
all fetches where the fetcher did not explicitly opt into sharing their [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin") with the
server, e.g., via using the [CORS protocol](#cors-protocol "#cors-protocol").

### 3.3. CORS protocol

To allow sharing responses cross-origin and allow for more versatile
[fetches](#concept-fetch "#concept-fetch") than possible with HTML’s
`form` element, the CORS protocol exists. It
is layered on top of HTTP and allows responses to declare they can be shared with other
[origins](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin").

It needs to be an opt-in mechanism to prevent leaking data from responses behind a
firewall (intranets). Additionally, for [requests](#concept-request "#concept-request") including
[credentials](#credentials "#credentials") it needs to be opt-in to prevent leaking potentially-sensitive data.

This section explains the [CORS protocol](#cors-protocol "#cors-protocol") as it pertains to server developers.
Requirements for user agents are part of the [fetch](#concept-fetch "#concept-fetch") algorithm,
except for the [new HTTP header syntax](#http-new-header-syntax "#http-new-header-syntax").

#### 3.3.1. General

The [CORS protocol](#cors-protocol "#cors-protocol") consists of a set of headers that indicates whether a response can
be shared cross-origin.

For [requests](#concept-request "#concept-request") that are more involved than what is possible with HTML’s `form`
element, a [CORS-preflight request](#cors-preflight-request "#cors-preflight-request") is performed, to ensure [request](#concept-request "#concept-request")’s
[current URL](#concept-request-current-url "#concept-request-current-url") supports the [CORS protocol](#cors-protocol "#cors-protocol").

#### 3.3.2. HTTP requests

A CORS request is an HTTP request that includes an
`[`Origin`](#http-origin "#http-origin")` header. It cannot be reliably identified as participating
in the [CORS protocol](#cors-protocol "#cors-protocol") as the `[`Origin`](#http-origin "#http-origin")` header is also included
for all [requests](#concept-request "#concept-request") whose [method](#concept-request-method "#concept-request-method") is neither ``GET`` nor
``HEAD``.

A CORS-preflight request is a [CORS request](#cors-request "#cors-request")
that checks to see if the [CORS protocol](#cors-protocol "#cors-protocol") is understood. It uses ``OPTIONS`` as
[method](#concept-method "#concept-method") and includes the following [header](#concept-header "#concept-header"):

``Access-Control-Request-Method``: Indicates which [method](#concept-method "#concept-method") a future [CORS request](#cors-request "#cors-request") to the same resource might use.

A [CORS-preflight request](#cors-preflight-request "#cors-preflight-request") can also include the following [header](#concept-header "#concept-header"):

``Access-Control-Request-Headers``: Indicates which [headers](#concept-header "#concept-header") a future [CORS request](#cors-request "#cors-request") to the same resource might use.

#### 3.3.3. HTTP responses

An HTTP response to a [CORS request](#cors-request "#cors-request") can include the following
[headers](#concept-header "#concept-header"):

``Access-Control-Allow-Origin``: Indicates whether the response can be shared, via returning the literal [value](#concept-header-value "#concept-header-value") of the `[`Origin`](#http-origin "#http-origin")` request [header](#concept-header "#concept-header") (which can be ``null``) or ``*`` in a response. ``Access-Control-Allow-Credentials``: Indicates whether the response can be shared when [request](#concept-request "#concept-request")’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is "`include`". For a [CORS-preflight request](#cors-preflight-request "#cors-preflight-request"), [request](#concept-request "#concept-request")’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is always "`same-origin`", i.e., it excludes credentials, but for any subsequent [CORS requests](#cors-request "#cors-request") it might not be. Support therefore needs to be indicated as part of the HTTP response to the [CORS-preflight request](#cors-preflight-request "#cors-preflight-request") as well.

An HTTP response to a [CORS-preflight request](#cors-preflight-request "#cors-preflight-request") can include the following
[headers](#concept-header "#concept-header"):

``Access-Control-Allow-Methods``: Indicates which [methods](#concept-method "#concept-method") are supported by the [response](#concept-response "#concept-response")’s [URL](#concept-response-url "#concept-response-url") for the purposes of the [CORS protocol](#cors-protocol "#cors-protocol"). The ``Allow`` [header](#concept-header "#concept-header") is not relevant for the purposes of the [CORS protocol](#cors-protocol "#cors-protocol"). ``Access-Control-Allow-Headers``: Indicates which [headers](#concept-header "#concept-header") are supported by the [response](#concept-response "#concept-response")’s [URL](#concept-response-url "#concept-response-url") for the purposes of the [CORS protocol](#cors-protocol "#cors-protocol"). ``Access-Control-Max-Age``: Indicates the number of seconds (5 by default) the information provided by the `[`Access-Control-Allow-Methods`](#http-access-control-allow-methods "#http-access-control-allow-methods")` and `[`Access-Control-Allow-Headers`](#http-access-control-allow-headers "#http-access-control-allow-headers")` [headers](#concept-header "#concept-header") can be cached.

An HTTP response to a [CORS request](#cors-request "#cors-request") that is not a
[CORS-preflight request](#cors-preflight-request "#cors-preflight-request") can also include the following
[header](#concept-header "#concept-header"):

``Access-Control-Expose-Headers``: Indicates which [headers](#concept-header "#concept-header") can be exposed as part of the response by listing their [names](#concept-header-name "#concept-header-name").

---

A successful HTTP response, i.e., one where the server developer intends to share it, to a
[CORS request](#cors-request "#cors-request") can use any [status](#concept-status "#concept-status"), as long as it includes the [headers](#concept-header "#concept-header")
stated above with [values](#concept-header-value "#concept-header-value") matching up with the request.

A successful HTTP response to a [CORS-preflight request](#cors-preflight-request "#cors-preflight-request") is similar, except it is restricted
to an [ok status](#ok-status "#ok-status"), e.g., 200 or 204.

Any other kind of HTTP response is not successful and will either end up not being shared or fail
the [CORS-preflight request](#cors-preflight-request "#cors-preflight-request"). Be aware that any work the server performs might nonetheless leak
through side channels, such as timing. If server developers wish to denote this explicitly, the 403
[status](#concept-status "#concept-status") can be used, coupled with omitting the relevant [headers](#concept-header "#concept-header").

If desired, “failure” could also be shared, but that would make it a successful HTTP
response. That is why for a successful HTTP response to a [CORS request](#cors-request "#cors-request") that is not a
[CORS-preflight request](#cors-preflight-request "#cors-preflight-request") the [status](#concept-status "#concept-status") can be anything, including 403.

Ultimately server developers have a lot of freedom in how they handle HTTP responses and these
tactics can differ between the response to the [CORS-preflight request](#cors-preflight-request "#cors-preflight-request") and the
[CORS request](#cors-request "#cors-request") that follows it:

* They can provide a static response. This can be helpful when working with caching
  intermediaries. A static response can both be successful and not successful depending on the
  [CORS request](#cors-request "#cors-request"). This is okay.

  * They can provide a dynamic response, tuned to [CORS request](#cors-request "#cors-request"). This can be helpful when
    the response body is to be tailored to a specific origin or a response needs to have credentials
    and be successful for a set of origins.

#### 3.3.4. HTTP new-header syntax

[ABNF](#abnf "#abnf") for the [values](#concept-header-value "#concept-header-value") of the
[headers](#concept-header "#concept-header") used by the [CORS protocol](#cors-protocol "#cors-protocol"):

```
Access-Control-Request-Method    = method
Access-Control-Request-Headers   = 1#field-name

wildcard                         = "*"
Access-Control-Allow-Origin      = origin-or-null / wildcard

Access-Control-Allow-Credentials = %s"true" ; case-sensitive
Access-Control-Expose-Headers    = #field-name
Access-Control-Max-Age           = delta-seconds
Access-Control-Allow-Methods     = #method
Access-Control-Allow-Headers     = #field-name
```

For ``Access-Control-Expose-Headers``,
``Access-Control-Allow-Methods``, and ``Access-Control-Allow-Headers``
response [headers](#concept-header "#concept-header"), the [value](#concept-header-value "#concept-header-value") ``*`` counts as a wildcard for
[requests](#concept-request "#concept-request") without [credentials](#credentials "#credentials"). For such [requests](#concept-request "#concept-request") there is no
way to solely match a [header name](#header-name "#header-name") or [method](#concept-method "#concept-method") that is ``*``.

#### 3.3.5. CORS protocol and credentials

When [request](#concept-request "#concept-request")’s
[credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is "`include`" it
has an impact on the functioning of the [CORS protocol](#cors-protocol "#cors-protocol") other than including
[credentials](#credentials "#credentials") in the [fetch](#concept-fetch "#concept-fetch").

In the old days, `XMLHttpRequest` could be used to set
[request](#concept-request "#concept-request")’s
[credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") to "`include`":

```
var client = new XMLHttpRequest()
client.open("GET", "./")
client.withCredentials = true
/* … */
```

Nowadays, `fetch("./", { credentials:"include" }).then(/* … */)`
suffices.

A [request](#concept-request "#concept-request")’s
[credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is not necessarily observable
on the server; only when [credentials](#credentials "#credentials") exist for a
[request](#concept-request "#concept-request") can it be observed by virtue of the
[credentials](#credentials "#credentials") being included. Note that even so, a [CORS-preflight request](#cors-preflight-request "#cors-preflight-request")
never includes [credentials](#credentials "#credentials").

The server developer therefore needs to decide whether or not responses "tainted" with
[credentials](#credentials "#credentials") can be shared. And also needs to decide if
[requests](#concept-request "#concept-request") necessitating a [CORS-preflight request](#cors-preflight-request "#cors-preflight-request") can
include [credentials](#credentials "#credentials"). Generally speaking, both sharing responses and allowing requests
with [credentials](#credentials "#credentials") is rather unsafe, and extreme care has to be taken to avoid the
[confused deputy problem](https://en.wikipedia.org/wiki/Confused_deputy_problem "https://en.wikipedia.org/wiki/Confused_deputy_problem").

To share responses with [credentials](#credentials "#credentials"), the
`[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` and
`[`Access-Control-Allow-Credentials`](#http-access-control-allow-credentials "#http-access-control-allow-credentials")` [headers](#concept-header "#concept-header") are
important. The following table serves to illustrate the various legal and illegal combinations for a
request to `https://rabbit.invalid/`:

|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Request’s credentials mode `[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` `[`Access-Control-Allow-Credentials`](#http-access-control-allow-credentials "#http-access-control-allow-credentials")` Shared? Notes|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | "`omit`" ``*`` Omitted ✅ —​|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | "`omit`" ``*`` ``true`` ✅ If credentials mode is not "`include`", then `[`Access-Control-Allow-Credentials`](#http-access-control-allow-credentials "#http-access-control-allow-credentials")` is ignored.| "`omit`" ``https://rabbit.invalid/`` Omitted ❌ A [serialized](https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin "https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin") origin has no trailing slash.| "`omit`" ``https://rabbit.invalid`` Omitted ✅ —​|  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | | "`include`" ``*`` ``true`` ❌ If credentials mode is "`include`", then `[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` cannot be ``*``.| "`include`" ``https://rabbit.invalid`` ``true`` ✅ —​|  |  |  |  |  | | --- | --- | --- | --- | --- | | "`include`" ``https://rabbit.invalid`` ``True`` ❌ ``true`` is (byte) case-sensitive. | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |

Similarly, `[`Access-Control-Expose-Headers`](#http-access-control-expose-headers "#http-access-control-expose-headers")`,
`[`Access-Control-Allow-Methods`](#http-access-control-allow-methods "#http-access-control-allow-methods")`, and
`[`Access-Control-Allow-Headers`](#http-access-control-allow-headers "#http-access-control-allow-headers")` response headers can only use
``*`` as value when [request](#concept-request "#concept-request")’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is not
"`include`".

#### 3.3.6. Examples

A script at `https://foo.invalid/` wants to fetch some data from
`https://bar.invalid/`. (Neither [credentials](#credentials "#credentials") nor response header access is
important.)

```
var url = "https://bar.invalid/api?key=730d67a37d7f3d802e96396d00280768773813fbe726d116944d814422fc1a45&data=about:unicorn";
fetch(url).then(success, failure)
```

This will use the [CORS protocol](#cors-protocol "#cors-protocol"), though this is entirely transparent to the
developer from `foo.invalid`. As part of the [CORS protocol](#cors-protocol "#cors-protocol"), the user agent
will include the `[`Origin`](#http-origin "#http-origin")` header in the request:

```
Origin: https://foo.invalid
```

Upon receiving a response from `bar.invalid`, the user agent will verify the
`[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` response header. If its value is
either ``https://foo.invalid`` or ``*``, the user agent will invoke the
`success` callback. If it has any other value, or is missing, the user agent will invoke
the `failure` callback.

The developer of `foo.invalid` is back, and now wants to fetch some data from
`bar.invalid` while also accessing a response header.

```
fetch(url).then(response => {
  var hsts = response.headers.get("strict-transport-security"),
      csp = response.headers.get("content-security-policy")
  log(hsts, csp)
})
```

`bar.invalid` provides a correct
`[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` response header per the earlier
example. The values of `hsts` and `csp` will depend on the
`[`Access-Control-Expose-Headers`](#http-access-control-expose-headers "#http-access-control-expose-headers")` response header. For example, if
the response included the following headers

```
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
Access-Control-Expose-Headers: Content-Security-Policy
```

then `hsts` would be null and `csp` would be
"`default-src 'self'`", even though the response did include both headers. This is
because `bar.invalid` needs to explicitly share each header by listing their names in
the `[`Access-Control-Expose-Headers`](#http-access-control-expose-headers "#http-access-control-expose-headers")` response header.

Alternatively, if `bar.invalid` wanted to share all its response headers, for
requests that do not include [credentials](#credentials "#credentials"), it could use ``*`` as value for
the `[`Access-Control-Expose-Headers`](#http-access-control-expose-headers "#http-access-control-expose-headers")` response header. If the request
would have included [credentials](#credentials "#credentials"), the response header names would have to be listed
explicitly and ``*`` could not be used.

The developer of `foo.invalid` returns, now fetching some data from
`bar.invalid` while including [credentials](#credentials "#credentials"). This time around the
[CORS protocol](#cors-protocol "#cors-protocol") is no longer transparent to the developer as [credentials](#credentials "#credentials")
require an explicit opt-in:

```
fetch(url, { credentials:"include" }).then(success, failure)
```

This also makes any ``Set-Cookie`` response headers `bar.invalid`
includes fully functional (they are ignored otherwise).

The user agent will make sure to include any relevant [credentials](#credentials "#credentials") in the request.
It will also put stricter requirements on the response. Not only will `bar.invalid` need
to list ``https://foo.invalid`` as value for the
`[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` header (``*`` is not
allowed when [credentials](#credentials "#credentials") are involved), the
`[`Access-Control-Allow-Credentials`](#http-access-control-allow-credentials "#http-access-control-allow-credentials")` header has to be present too:

```
Access-Control-Allow-Origin: https://foo.invalid
Access-Control-Allow-Credentials: true
```

If the response does not include those two headers with those values, the `failure`
callback will be invoked. However, any ``Set-Cookie`` response headers will be
respected.

#### 3.3.7. CORS protocol exceptions

Specifications have allowed limited exceptions to the CORS safelist for non-safelisted
``Content-Type`` header values. These exceptions are made for requests that can be
triggered by web content but whose headers and bodies can be only minimally controlled by the web
content. Therefore, servers should expect cross-origin web content to be allowed to trigger
non-preflighted requests with the following non-safelisted ``Content-Type`` header
values:

* ``application/csp-report`` [[CSP]](#biblio-csp "Content Security Policy Level 3")* ``application/expect-ct-report+json`` [[RFC9163]](#biblio-rfc9163 "Expect-CT Extension for HTTP")* ``application/xss-auditor-report``* ``application/ocsp-request`` [[RFC6960]](#biblio-rfc6960 "X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP")

Specifications should avoid introducing new exceptions and should only do so with careful
consideration for the security consequences. New exceptions can be proposed by
[filing an issue](https://github.com/whatwg/fetch/issues/new "https://github.com/whatwg/fetch/issues/new").

### 3.4. ``Content-Length`` header

The ``Content-Length`` header is largely defined in HTTP. Its processing model is
defined here as the model defined in HTTP is not compatible with web content. [[HTTP]](#biblio-http "HTTP Semantics")

To extract a length
from a [header list](#concept-header-list "#concept-header-list") headers, run these steps:

1. Let values be the result of
   [getting, decoding, and splitting](#concept-header-list-get-decode-split "#concept-header-list-get-decode-split") ``Content-Length`` from
   headers.

   - If values is null, then return null.

     - Let candidateValue be null.

       - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") value of values:

         1. If candidateValue is null, then set candidateValue to
            value.

            - Otherwise, if value is not candidateValue, return failure.- If candidateValue is the empty string or has a [code point](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") that is
           not an [ASCII digit](https://infra.spec.whatwg.org/#ascii-digit "https://infra.spec.whatwg.org/#ascii-digit"), then return null.

           - Return candidateValue, interpreted as decimal number.

### 3.5. ``Content-Type`` header

The ``Content-Type`` header is largely defined in HTTP. Its processing model is
defined here as the model defined in HTTP is not compatible with web content. [[HTTP]](#biblio-http "HTTP Semantics")

To
extract a MIME type
from a [header list](#concept-header-list "#concept-header-list") headers, run these steps. They return failure or a
[MIME type](https://mimesniff.spec.whatwg.org/#mime-type "https://mimesniff.spec.whatwg.org/#mime-type").

1. Let charset be null.

   - Let essence be null.

     - Let mimeType be null.

       - Let values be the result of
         [getting, decoding, and splitting](#concept-header-list-get-decode-split "#concept-header-list-get-decode-split") ``Content-Type`` from
         headers.

         - If values is null, then return failure.

           - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") value of values:

             1. Let temporaryMimeType be the result of [parsing](https://mimesniff.spec.whatwg.org/#parse-a-mime-type "https://mimesniff.spec.whatwg.org/#parse-a-mime-type")
                value.

                - If temporaryMimeType is failure or its [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence "https://mimesniff.spec.whatwg.org/#mime-type-essence") is
                  "`*/*`", then [continue](https://infra.spec.whatwg.org/#iteration-continue "https://infra.spec.whatwg.org/#iteration-continue").

                  - Set mimeType to temporaryMimeType.

                    - If mimeType’s [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence "https://mimesniff.spec.whatwg.org/#mime-type-essence") is not essence, then:

                      1. Set charset to null.

                         - If mimeType’s [parameters](https://mimesniff.spec.whatwg.org/#parameters "https://mimesniff.spec.whatwg.org/#parameters")["`charset`"]
                           [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set charset to mimeType’s
                           [parameters](https://mimesniff.spec.whatwg.org/#parameters "https://mimesniff.spec.whatwg.org/#parameters")["`charset`"].

                           - Set essence to mimeType’s [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence "https://mimesniff.spec.whatwg.org/#mime-type-essence").- Otherwise, if mimeType’s
                        [parameters](https://mimesniff.spec.whatwg.org/#parameters "https://mimesniff.spec.whatwg.org/#parameters")["`charset`"] does not [exist](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), and
                        charset is non-null, set mimeType’s
                        [parameters](https://mimesniff.spec.whatwg.org/#parameters "https://mimesniff.spec.whatwg.org/#parameters")["`charset`"] to charset.- If mimeType is null, then return failure.

               - Return mimeType.

When [extract a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type") returns failure or a [MIME type](https://mimesniff.spec.whatwg.org/#mime-type "https://mimesniff.spec.whatwg.org/#mime-type") whose
[essence](https://mimesniff.spec.whatwg.org/#mime-type-essence "https://mimesniff.spec.whatwg.org/#mime-type-essence") is incorrect for a given format, treat this as a fatal error.
Existing web platform features have not always followed this pattern, which has been a major source
of security vulnerabilities in those features over the years. In contrast, a
[MIME type](https://mimesniff.spec.whatwg.org/#mime-type "https://mimesniff.spec.whatwg.org/#mime-type")’s [parameters](https://mimesniff.spec.whatwg.org/#parameters "https://mimesniff.spec.whatwg.org/#parameters") can typically be safely ignored.

This is how [extract a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type") functions in practice:

|  |  |  |  |  |  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Headers (as on the network) Output ([serialized](https://mimesniff.spec.whatwg.org/#serialize-a-mime-type "https://mimesniff.spec.whatwg.org/#serialize-a-mime-type"))| ``` Content-Type: text/plain;charset=gbk, text/html ```   `text/html`| ``` Content-Type: text/html;charset=gbk;a=b, text/html;x=y ```   `text/html;x=y;charset=gbk`| ``` Content-Type: text/html;charset=gbk;a=b Content-Type: text/html;x=y ```  | ``` Content-Type: text/html;charset=gbk Content-Type: x/x Content-Type: text/html;x=y ```   `text/html;x=y`| ``` Content-Type: text/html Content-Type: cannot-parse ```   `text/html`| ``` Content-Type: text/html Content-Type: */* ```  | ``` Content-Type: text/html Content-Type: ``` | | | | | | | | | | | | |

To legacy extract an encoding given failure or a [MIME type](https://mimesniff.spec.whatwg.org/#mime-type "https://mimesniff.spec.whatwg.org/#mime-type")
mimeType and an [encoding](https://encoding.spec.whatwg.org/#encoding "https://encoding.spec.whatwg.org/#encoding") fallbackEncoding, run these steps:

1. If mimeType is failure, then return fallbackEncoding.

   - If mimeType["`charset`"] does not [exist](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then return
     fallbackEncoding.

     - Let tentativeEncoding be the result of [getting an encoding](https://encoding.spec.whatwg.org/#concept-encoding-get "https://encoding.spec.whatwg.org/#concept-encoding-get") from
       mimeType["`charset`"].

       - If tentativeEncoding is failure, then return fallbackEncoding.

         - Return tentativeEncoding.

This algorithm allows mimeType to be failure so it can be more easily combined with
[extract a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type").

It is denoted as legacy as modern formats are to exclusively use [UTF-8](https://encoding.spec.whatwg.org/#utf-8 "https://encoding.spec.whatwg.org/#utf-8").

### 3.6. ``X-Content-Type-Options`` header

The
``X-Content-Type-Options``
response [header](#concept-header "#concept-header") can be used to require checking of a [response](#concept-response "#concept-response")’s
``Content-Type`` [header](#concept-header "#concept-header") against the [destination](#concept-request-destination "#concept-request-destination") of a
[request](#concept-request "#concept-request").

To determine nosniff, given a [header list](#concept-header-list "#concept-header-list") list, run
these steps:

1. Let values be the result of
   [getting, decoding, and splitting](#concept-header-list-get-decode-split "#concept-header-list-get-decode-split")
   `[`X-Content-Type-Options`](#http-x-content-type-options "#http-x-content-type-options")` from list.

   - If values is null, then return false.

     - If values[0] is an [ASCII case-insensitive](https://infra.spec.whatwg.org/#ascii-case-insensitive "https://infra.spec.whatwg.org/#ascii-case-insensitive") match for
       "`nosniff`", then return true.

       - Return false.

Web developers and conformance checkers must use the following [value](#concept-header-value "#concept-header-value")
[ABNF](#abnf "#abnf") for `[`X-Content-Type-Options`](#http-x-content-type-options "#http-x-content-type-options")`:

```
X-Content-Type-Options           = "nosniff" ; case-insensitive
```

#### 3.6.1. Should response to request be blocked due to nosniff?

Run these steps:

1. If [determine nosniff](#determine-nosniff "#determine-nosniff") with response’s [header list](#concept-response-header-list "#concept-response-header-list") is
   false, then return **allowed**.

   - Let mimeType be the result of [extracting a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type")
     from response’s [header list](#concept-response-header-list "#concept-response-header-list").

     - Let destination be request’s [destination](#concept-request-destination "#concept-request-destination").

       - If destination is [script-like](#request-destination-script-like "#request-destination-script-like") and
         mimeType is failure or is not a [JavaScript MIME type](https://mimesniff.spec.whatwg.org/#javascript-mime-type "https://mimesniff.spec.whatwg.org/#javascript-mime-type"), then return **blocked**.

         - If destination is "`style`" and mimeType is failure or its
           [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence "https://mimesniff.spec.whatwg.org/#mime-type-essence") is not "`text/css`", then return **blocked**.

           - Return **allowed**.

Only [request](#concept-request "#concept-request") [destinations](#concept-request-destination "#concept-request-destination") that are
[script-like](#request-destination-script-like "#request-destination-script-like") or "`style`" are considered as any exploits
pertain to them. Also, considering "`image`" was not compatible with deployed content.

### 3.7. ``Cross-Origin-Resource-Policy`` header

The
``Cross-Origin-Resource-Policy``
response [header](#concept-header "#concept-header") can be used to require checking a [request](#concept-request "#concept-request")’s
[current URL](#concept-request-current-url "#concept-request-current-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") against a [request](#concept-request "#concept-request")’s
[origin](#concept-request-origin "#concept-request-origin") when [request](#concept-request "#concept-request")’s [mode](#concept-request-mode "#concept-request-mode") is
"`no-cors`".

Its [value](#concept-header-value "#concept-header-value") [ABNF](#abnf "#abnf"):

```
Cross-Origin-Resource-Policy     = %s"same-origin" / %s"same-site" / %s"cross-origin" ; case-sensitive
```

To perform a cross-origin resource policy check, given an [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin")
origin, an [environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object") settingsObject, a string
destination, a [response](#concept-response "#concept-response") response, and an optional boolean
forNavigation, run these steps:

1. Set forNavigation to false if it is not given.

   - Let embedderPolicy be settingsObject’s
     [policy container](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container")’s
     [embedder policy](https://html.spec.whatwg.org/multipage/browsers.html#policy-container-embedder-policy "https://html.spec.whatwg.org/multipage/browsers.html#policy-container-embedder-policy").

     - If the [cross-origin resource policy internal check](#cross-origin-resource-policy-internal-check "#cross-origin-resource-policy-internal-check") with origin,
       "[`unsafe-none`](https://html.spec.whatwg.org/multipage/browsers.html#coep-unsafe-none "https://html.spec.whatwg.org/multipage/browsers.html#coep-unsafe-none")", response, and
       forNavigation returns **blocked**, then return **blocked**.

       This step is needed because we don’t want to report violations not related to
       Cross-Origin Embedder Policy below.

       - If the [cross-origin resource policy internal check](#cross-origin-resource-policy-internal-check "#cross-origin-resource-policy-internal-check") with origin,
         embedderPolicy’s [report only value](https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-report-only-value "https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-report-only-value"), response,
         and forNavigation returns **blocked**, then
         [queue a cross-origin embedder policy CORP violation report](#queue-a-cross-origin-embedder-policy-corp-violation-report "#queue-a-cross-origin-embedder-policy-corp-violation-report") with response,
         settingsObject, destination, and true.

         - If the [cross-origin resource policy internal check](#cross-origin-resource-policy-internal-check "#cross-origin-resource-policy-internal-check") with origin,
           embedderPolicy’s [value](https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-value-2 "https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-value-2"), response, and
           forNavigation returns **allowed**, then return **allowed**.

           - [Queue a cross-origin embedder policy CORP violation report](#queue-a-cross-origin-embedder-policy-corp-violation-report "#queue-a-cross-origin-embedder-policy-corp-violation-report") with response,
             settingsObject, destination, and false.

             - Return **blocked**.

Only HTML’s navigate algorithm uses this check with forNavigation set to
true, and it’s always for nested navigations. Otherwise, response is either the
[internal response](#concept-internal-response "#concept-internal-response") of an [opaque filtered response](#concept-filtered-response-opaque "#concept-filtered-response-opaque") or a
[response](#concept-response "#concept-response") which will be the [internal response](#concept-internal-response "#concept-internal-response") of an
[opaque filtered response](#concept-filtered-response-opaque "#concept-filtered-response-opaque"). [[HTML]](#biblio-html "HTML Standard")

To perform a cross-origin resource policy internal check, given an
[origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") origin, an [embedder policy value](https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-value "https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-value")
embedderPolicyValue, a [response](#concept-response "#concept-response") response, and a boolean
forNavigation, run these steps:

1. If forNavigation is true and embedderPolicyValue is
   "[`unsafe-none`](https://html.spec.whatwg.org/multipage/browsers.html#coep-unsafe-none "https://html.spec.whatwg.org/multipage/browsers.html#coep-unsafe-none")", then return **allowed**.

   - Let policy be the result of [getting](#concept-header-list-get "#concept-header-list-get")
     `[`Cross-Origin-Resource-Policy`](#http-cross-origin-resource-policy "#http-cross-origin-resource-policy")` from response’s
     [header list](#concept-response-header-list "#concept-response-header-list").

     This means that ``Cross-Origin-Resource-Policy: same-site, same-origin``
     ends up as **allowed** below as it will never match anything, as long as
     embedderPolicyValue is "[`unsafe-none`](https://html.spec.whatwg.org/multipage/browsers.html#coep-unsafe-none "https://html.spec.whatwg.org/multipage/browsers.html#coep-unsafe-none")".
     Two or more `[`Cross-Origin-Resource-Policy`](#http-cross-origin-resource-policy "#http-cross-origin-resource-policy")` headers will have the
     same effect.

     - If policy is neither ``same-origin``, ``same-site``, nor
       ``cross-origin``, then set policy to null.

       - If policy is null, then switch on embedderPolicyValue:

         "[`unsafe-none`](https://html.spec.whatwg.org/multipage/browsers.html#coep-unsafe-none "https://html.spec.whatwg.org/multipage/browsers.html#coep-unsafe-none")": Do nothing. "[`credentialless`](https://html.spec.whatwg.org/multipage/browsers.html#coep-credentialless "https://html.spec.whatwg.org/multipage/browsers.html#coep-credentialless")": Set policy to ``same-origin`` if: * response’s [request-includes-credentials](#response-request-includes-credentials "#response-request-includes-credentials") is true, or* forNavigation is true. "[`require-corp`](https://html.spec.whatwg.org/multipage/browsers.html#coep-require-corp "https://html.spec.whatwg.org/multipage/browsers.html#coep-require-corp")": Set policy to ``same-origin``.

         - Switch on policy:

           null ``cross-origin``: Return **allowed**. ``same-origin``: If origin is [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with response’s [URL](#concept-response-url "#concept-response-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin"), then return **allowed**. Otherwise, return **blocked**. ``same-site``: If all of the following are true * origin is [schemelessly same site](https://html.spec.whatwg.org/multipage/browsers.html#schemelessly-same-site "https://html.spec.whatwg.org/multipage/browsers.html#schemelessly-same-site") with response’s [URL](#concept-response-url "#concept-response-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") * origin’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is "`https`" or response’s [URL](#concept-response-url "#concept-response-url")’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is not "`https`" then return **allowed**. Otherwise, return **blocked**. ``Cross-Origin-Resource-Policy: same-site`` does not consider a response delivered via a secure transport to match a non-secure requesting origin, even if their hosts are otherwise same site. Securely-transported responses will only match a securely-transported initiator.

To queue a cross-origin embedder policy CORP violation report, given a
[response](#concept-response "#concept-response") response, an [environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object")
settingsObject, a string destination, and a boolean reportOnly,
run these steps:

1. Let endpoint be settingsObject’s
   [policy container](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container")’s
   [embedder policy](https://html.spec.whatwg.org/multipage/browsers.html#policy-container-embedder-policy "https://html.spec.whatwg.org/multipage/browsers.html#policy-container-embedder-policy")’s
   [report only reporting endpoint](https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-report-only-reporting-endpoint "https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-report-only-reporting-endpoint") if reportOnly is true and
   settingsObject’s [policy container](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container")’s
   [embedder policy](https://html.spec.whatwg.org/multipage/browsers.html#policy-container-embedder-policy "https://html.spec.whatwg.org/multipage/browsers.html#policy-container-embedder-policy")’s
   [reporting endpoint](https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-reporting-endpoint "https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-reporting-endpoint") otherwise.

   - Let serializedURL be the result of
     [serializing a response URL for reporting](#serialize-a-response-url-for-reporting "#serialize-a-response-url-for-reporting") with
     response.

     - Let disposition be "`reporting`" if reportOnly is true;
       otherwise "`enforce`".

       - Let body be a new object containing the following properties:

         |  |  |  |  |  |  |  |  |  |  |
         | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
         | key value|  |  |  |  |  |  |  |  | | --- | --- | --- | --- | --- | --- | --- | --- | | "`type`" "`corp`"| "`blockedURL`" serializedURL| "`destination`" destination| "`disposition`" disposition | | | | | | | | | |

         - [Generate and queue a report](https://w3c.github.io/reporting/#generate-and-queue-a-report "https://w3c.github.io/reporting/#generate-and-queue-a-report") for settingsObject’s
           [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global") given the
           ["`coep`" report type](https://html.spec.whatwg.org/multipage/browsers.html#coep-report-type "https://html.spec.whatwg.org/multipage/browsers.html#coep-report-type"), endpoint, and body. [[REPORTING]](#biblio-reporting "Reporting API")

### 3.8. ``Sec-Purpose`` header

The ``Sec-Purpose`` HTTP request
header specifies that the request serves one or more purposes other than requesting the resource for
immediate use by the user.

The `[`Sec-Purpose`](#http-sec-purpose "#http-sec-purpose")` header field is a [structured header](https://httpwg.org/specs/rfc9651.html# "https://httpwg.org/specs/rfc9651.html#")
whose value must be a [token](https://httpwg.org/specs/rfc9651.html#token "https://httpwg.org/specs/rfc9651.html#token").

The sole [token](https://httpwg.org/specs/rfc9651.html#token "https://httpwg.org/specs/rfc9651.html#token") defined is `prefetch`. It
indicates the request’s purpose is to fetch a resource that is anticipated to be needed shortly.

The server can use this to adjust the caching expiry for prefetches, to disallow the
prefetch, or to treat it differently when counting page visits.

4. Fetching
-----------

The algorithm below defines [fetching](#concept-fetch "#concept-fetch"). In broad strokes, it takes
a [request](#concept-request "#concept-request") and one or more algorithms to run at various points during the operation. A
[response](#concept-response "#concept-response") is passed to the last two algorithms listed below. The first two algorithms
can be used to capture uploads.

To fetch, given a [request](#concept-request "#concept-request") request, an
optional algorithm
processRequestBodyChunkLength, an
optional algorithm
processRequestEndOfBody,
an optional algorithm processEarlyHintsResponse, an optional
algorithm processResponse, an optional
algorithm processResponseEndOfBody, an optional algorithm
processResponseConsumeBody,
and an optional boolean useParallelQueue (default false), run
the steps below. If given, processRequestBodyChunkLength must be an algorithm accepting
an integer representing the number of bytes transmitted. If given,
processRequestEndOfBody must be an algorithm accepting no arguments. If given,
processEarlyHintsResponse must be an algorithm accepting a [response](#concept-response "#concept-response"). If
given, processResponse must be an algorithm accepting a [response](#concept-response "#concept-response"). If given,
processResponseEndOfBody must be an algorithm accepting a [response](#concept-response "#concept-response"). If
given, processResponseConsumeBody must be an algorithm accepting a [response](#concept-response "#concept-response")
and null, failure, or a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence").

The user agent may be asked to
suspend the ongoing fetch.
The user agent may either accept or ignore the suspension request. The suspended fetch can be
resumed. The user agent should
ignore the suspension request if the ongoing fetch is updating the response in the HTTP cache for
the request.

The user agent does not update the entry in the HTTP cache for a [request](#concept-request "#concept-request")
if request’s cache mode is "no-store" or a ``Cache-Control: no-store`` header appears in
the response. [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [mode](#concept-request-mode "#concept-request-mode") is "`navigate`" or
   processEarlyHintsResponse is null.

   Processing of early hints ([responses](#concept-response "#concept-response") whose [status](#concept-response-status "#concept-response-status")
   is 103) is only vetted for navigations.

   - Let taskDestination be null.

     - Let crossOriginIsolatedCapability be false.

       - [Populate request from client](#populate-request-from-client "#populate-request-from-client") given request.

         - If request’s [client](#concept-request-client "#concept-request-client") is non-null, then:

           1. Set taskDestination to request’s [client](#concept-request-client "#concept-request-client")’s
              [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global").

              - Set crossOriginIsolatedCapability to request’s
                [client](#concept-request-client "#concept-request-client")’s
                [cross-origin isolated capability](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-cross-origin-isolated-capability "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-cross-origin-isolated-capability").- If useParallelQueue is true, then set taskDestination to the result of
             [starting a new parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#starting-a-new-parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#starting-a-new-parallel-queue").

             - Let timingInfo be a new [fetch timing info](#fetch-timing-info "#fetch-timing-info") whose
               [start time](#fetch-timing-info-start-time "#fetch-timing-info-start-time") and
               [post-redirect start time](#fetch-timing-info-post-redirect-start-time "#fetch-timing-info-post-redirect-start-time") are the
               [coarsened shared current time](https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time "https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time") given crossOriginIsolatedCapability, and
               [render-blocking](#fetch-timing-info-render-blocking "#fetch-timing-info-render-blocking") is set to request’s
               [render-blocking](#request-render-blocking "#request-render-blocking").

               - Let fetchParams be a new [fetch params](#fetch-params "#fetch-params") whose
                 [request](#fetch-params-request "#fetch-params-request") is request,
                 [timing info](#fetch-params-timing-info "#fetch-params-timing-info") is timingInfo,
                 [process request body chunk length](#fetch-params-process-request-body "#fetch-params-process-request-body") is
                 processRequestBodyChunkLength,
                 [process request end-of-body](#fetch-params-process-request-end-of-body "#fetch-params-process-request-end-of-body") is processRequestEndOfBody,
                 [process early hints response](#fetch-params-process-early-hints-response "#fetch-params-process-early-hints-response") is processEarlyHintsResponse,
                 [process response](#fetch-params-process-response "#fetch-params-process-response") is processResponse,
                 [process response consume body](#fetch-params-process-response-consume-body "#fetch-params-process-response-consume-body") is processResponseConsumeBody,
                 [process response end-of-body](#fetch-params-process-response-end-of-body "#fetch-params-process-response-end-of-body") is processResponseEndOfBody,
                 [task destination](#fetch-params-task-destination "#fetch-params-task-destination") is taskDestination, and
                 [cross-origin isolated capability](#fetch-params-cross-origin-isolated-capability "#fetch-params-cross-origin-isolated-capability") is
                 crossOriginIsolatedCapability.

                 - If request’s [body](#concept-request-body "#concept-request-body") is a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"), then set
                   request’s [body](#concept-request-body "#concept-request-body") to request’s [body](#concept-request-body "#concept-request-body")
                   [as a body](#byte-sequence-as-a-body "#byte-sequence-as-a-body").

                   - Run the [WebDriver BiDi clone network request body](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-clone-network-request-body "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-clone-network-request-body") steps with request.

                     - If all of the following conditions are true:

                       * request’s [URL](#concept-request-url "#concept-request-url")’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is an
                         [HTTP(S) scheme](#http-scheme "#http-scheme")

                         * request’s [mode](#concept-request-mode "#concept-request-mode") is "`same-origin`",
                           "`cors`", or "`no-cors`"

                           * request’s [client](#concept-request-client "#concept-request-client") is not null, and request’s
                             [client](#concept-request-client "#concept-request-client")’s [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global") is a
                             `Window` object

                             * request’s [method](#concept-request-method "#concept-request-method") is ``GET``

                               * request’s [unsafe-request flag](#unsafe-request-flag "#unsafe-request-flag") is not set or
                                 request’s [header list](#concept-request-header-list "#concept-request-header-list") [is empty](https://infra.spec.whatwg.org/#list-is-empty "https://infra.spec.whatwg.org/#list-is-empty")

                       then:

                       1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [origin](#concept-request-origin "#concept-request-origin") is [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin")
                          with request’s [client](#concept-request-client "#concept-request-client")’s
                          [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin").

                          - Let onPreloadedResponseAvailable be an algorithm that runs the following
                            step given a [response](#concept-response "#concept-response") response: set fetchParams’s
                            [preloaded response candidate](#fetch-params-preloaded-response-candidate "#fetch-params-preloaded-response-candidate") to response.

                            - Let foundPreloadedResource be the result of invoking
                              [consume a preloaded resource](https://html.spec.whatwg.org/multipage/links.html#consume-a-preloaded-resource "https://html.spec.whatwg.org/multipage/links.html#consume-a-preloaded-resource") for request’s [client](#concept-request-client "#concept-request-client"), given
                              request’s [URL](#concept-request-url "#concept-request-url"), request’s [destination](#concept-request-destination "#concept-request-destination"),
                              request’s [mode](#concept-request-mode "#concept-request-mode"), request’s
                              [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode"), request’s [integrity metadata](#concept-request-integrity-metadata "#concept-request-integrity-metadata"),
                              and onPreloadedResponseAvailable.

                              - If foundPreloadedResource is true and fetchParams’s
                                [preloaded response candidate](#fetch-params-preloaded-response-candidate "#fetch-params-preloaded-response-candidate") is null, then set fetchParams’s
                                [preloaded response candidate](#fetch-params-preloaded-response-candidate "#fetch-params-preloaded-response-candidate") to "`pending`".- If request’s [header list](#concept-request-header-list "#concept-request-header-list")
                         [does not contain](#header-list-contains "#header-list-contains") ``Accept``, then:

                         1. Let value be ``*/*``.

                            - If request’s [initiator](#concept-request-initiator "#concept-request-initiator") is "`prefetch`", then set
                              value to the [document ``Accept`` header value](#document-accept-header-value "#document-accept-header-value").

                              - Otherwise, the user agent should set value to the first matching statement, if
                                any, switching on request’s [destination](#concept-request-destination "#concept-request-destination"):

                                "`document`" "`frame`" "`iframe`": the [document ``Accept`` header value](#document-accept-header-value "#document-accept-header-value") "`image`": ``image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5`` "`json`": ``application/json,*/*;q=0.5`` "`style`": ``text/css,*/*;q=0.1`` "`text`": ``text/plain,*/*;q=0.5``

                                - [Append](#concept-header-list-append "#concept-header-list-append") (``Accept``, value) to
                                  request’s [header list](#concept-request-header-list "#concept-request-header-list").- If request’s [header list](#concept-request-header-list "#concept-request-header-list")
                           [does not contain](#header-list-contains "#header-list-contains") ``Accept-Language`` and request’s
                           [client](#concept-request-client "#concept-request-client") is non-null:

                           1. Let emulatedLanguage be the [WebDriver BiDi emulated language](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-emulated-language "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-emulated-language") for
                              request’s [client](#concept-request-client "#concept-request-client").

                              - If emulatedLanguage is non-null:

                                1. Let encodedEmulatedLanguage be emulatedLanguage,
                                   [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode").

                                   - [Append](#concept-header-list-append "#concept-header-list-append")
                                     (``Accept-Language``, encodedEmulatedLanguage) to request’s
                                     [header list](#concept-request-header-list "#concept-request-header-list").- If request’s [header list](#concept-request-header-list "#concept-request-header-list")
                             [does not contain](#header-list-contains "#header-list-contains") ``Accept-Language``, then user agents should
                             [append](#concept-header-list-append "#concept-header-list-append") (``Accept-Language`, an appropriate
                             [header value](#header-value "#header-value")) to request’s [header list](#concept-request-header-list "#concept-request-header-list").

                             - If request’s [internal priority](#request-internal-priority "#request-internal-priority") is null, then use
                               request’s [priority](#request-priority "#request-priority"), [initiator](#concept-request-initiator "#concept-request-initiator"),
                               [destination](#concept-request-destination "#concept-request-destination"), and [render-blocking](#request-render-blocking "#request-render-blocking") in an
                               [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") manner to set request’s
                               [internal priority](#request-internal-priority "#request-internal-priority") to an [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") object.

                               The [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") object could encompass stream weight and
                               dependency for HTTP/2, priorities used in Extensible Prioritization Scheme for HTTP
                               for transports where it applies (including HTTP/3), and equivalent information used to prioritize
                               dispatch and processing of HTTP/1 fetches. [[RFC9218]](#biblio-rfc9218 "Extensible Prioritization Scheme for HTTP")

                               - If request is a [subresource request](#subresource-request "#subresource-request"):

                                 1. Let record be a new [fetch record](#concept-fetch-record "#concept-fetch-record") whose
                                    [request](#concept-fetch-record-request "#concept-fetch-record-request") is request and [controller](#concept-fetch-record-fetch "#concept-fetch-record-fetch")
                                    is fetchParams’s [controller](#fetch-params-controller "#fetch-params-controller").

                                    - [Append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") record to request’s
                                      [client](#concept-request-client "#concept-request-client")’s [fetch group](#environment-settings-object-fetch-group "#environment-settings-object-fetch-group")’s
                                      [fetch records](#concept-fetch-record "#concept-fetch-record").- Run [main fetch](#concept-main-fetch "#concept-main-fetch") given fetchParams.

                                   - Return fetchParams’s [controller](#fetch-params-controller "#fetch-params-controller").

To populate request from client given a [request](#concept-request "#concept-request") request:

1. If request’s [traversable for user prompts](#concept-request-window "#concept-request-window") is "`client`":

   1. Set request’s [traversable for user prompts](#concept-request-window "#concept-request-window") to
      "`no-traversable`".

      - If request’s [client](#concept-request-client "#concept-request-client") is non-null:

        1. Let global be request’s [client](#concept-request-client "#concept-request-client")’s
           [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global").

           - If global is a `Window` object and global’s
             [navigable](https://html.spec.whatwg.org/multipage/nav-history-apis.html#window-navigable "https://html.spec.whatwg.org/multipage/nav-history-apis.html#window-navigable") is not null, then set request’s
             [traversable for user prompts](#concept-request-window "#concept-request-window") to global’s
             [navigable](https://html.spec.whatwg.org/multipage/nav-history-apis.html#window-navigable "https://html.spec.whatwg.org/multipage/nav-history-apis.html#window-navigable")’s [traversable navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#nav-traversable "https://html.spec.whatwg.org/multipage/document-sequences.html#nav-traversable").- If request’s [origin](#concept-request-origin "#concept-request-origin") is "`client`":

     1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [client](#concept-request-client "#concept-request-client") is non-null.

        - Set request’s [origin](#concept-request-origin "#concept-request-origin") to request’s
          [client](#concept-request-client "#concept-request-client")’s [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin").- If request’s [policy container](#concept-request-policy-container "#concept-request-policy-container") is "`client`":

       1. If request’s [client](#concept-request-client "#concept-request-client") is non-null, then set
          request’s [policy container](#concept-request-policy-container "#concept-request-policy-container") to a
          [clone](https://html.spec.whatwg.org/multipage/browsers.html#clone-a-policy-container "https://html.spec.whatwg.org/multipage/browsers.html#clone-a-policy-container") of request’s [client](#concept-request-client "#concept-request-client")’s
          [policy container](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-policy-container"). [[HTML]](#biblio-html "HTML Standard")

          - Otherwise, set request’s [policy container](#concept-request-policy-container "#concept-request-policy-container") to a new
            [policy container](https://html.spec.whatwg.org/multipage/browsers.html#policy-container "https://html.spec.whatwg.org/multipage/browsers.html#policy-container").

### 4.1. Main fetch

To main fetch, given a [fetch params](#fetch-params "#fetch-params")
fetchParams and an optional boolean recursive (default false), run these
steps:

1. Let request be fetchParams’s [request](#fetch-params-request "#fetch-params-request").

   - Let response be null.

     - If request’s [local-URLs-only flag](#local-urls-only-flag "#local-urls-only-flag") is set and request’s
       [current URL](#concept-request-current-url "#concept-request-current-url") is not [local](#is-local "#is-local"), then set response to a
       [network error](#concept-network-error "#concept-network-error").

       - Run [report Content Security Policy violations for request](https://w3c.github.io/webappsec-csp/#report-for-request "https://w3c.github.io/webappsec-csp/#report-for-request").

         - [Upgrade request to a potentially trustworthy URL, if appropriate](https://w3c.github.io/webappsec-upgrade-insecure-requests/#upgrade-request "https://w3c.github.io/webappsec-upgrade-insecure-requests/#upgrade-request").

           - [Upgrade a mixed content request to a potentially trustworthy URL, if appropriate](https://w3c.github.io/webappsec-mixed-content/#upgrade-algorithm "https://w3c.github.io/webappsec-mixed-content/#upgrade-algorithm").

             - If [should request be blocked due to a bad port](#block-bad-port "#block-bad-port"),
               [should fetching request be blocked as mixed content](https://w3c.github.io/webappsec-mixed-content/#should-block-fetch "https://w3c.github.io/webappsec-mixed-content/#should-block-fetch"),
               [should request be blocked by Content Security Policy](https://w3c.github.io/webappsec-csp/#should-block-request "https://w3c.github.io/webappsec-csp/#should-block-request"), or
               [should request be blocked by Integrity Policy Policy](https://w3c.github.io/webappsec-subresource-integrity/#should-request-be-blocked-by-integrity-policy "https://w3c.github.io/webappsec-subresource-integrity/#should-request-be-blocked-by-integrity-policy")
               returns **blocked**, then set response to a [network error](#concept-network-error "#concept-network-error").

               - If request’s [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy") is the empty string, then set
                 request’s [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy") to request’s
                 [policy container](#concept-request-policy-container "#concept-request-policy-container")’s [referrer policy](https://html.spec.whatwg.org/multipage/browsers.html#policy-container-referrer-policy "https://html.spec.whatwg.org/multipage/browsers.html#policy-container-referrer-policy").

                 - If request’s [referrer](#concept-request-referrer "#concept-request-referrer") is not "`no-referrer`", then set
                   request’s [referrer](#concept-request-referrer "#concept-request-referrer") to the result of invoking
                   [determine request’s referrer](https://w3c.github.io/webappsec-referrer-policy/#determine-requests-referrer "https://w3c.github.io/webappsec-referrer-policy/#determine-requests-referrer"). [[REFERRER]](#biblio-referrer "Referrer Policy")

                   As stated in Referrer Policy, user agents can provide the end user with
                   options to override request’s [referrer](#concept-request-referrer "#concept-request-referrer") to "`no-referrer`"
                   or have it expose less sensitive information.

                   - Set request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") to
                     "`https`" if all of the following conditions are true:

                     * request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is
                       "`http`"* request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [host](https://url.spec.whatwg.org/#concept-url-host "https://url.spec.whatwg.org/#concept-url-host") is a
                         [domain](https://url.spec.whatwg.org/#concept-domain "https://url.spec.whatwg.org/#concept-domain")* request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [host](https://url.spec.whatwg.org/#concept-url-host "https://url.spec.whatwg.org/#concept-url-host")’s
                           [public suffix](https://url.spec.whatwg.org/#host-public-suffix "https://url.spec.whatwg.org/#host-public-suffix") is not "`localhost`" or "`localhost.`"* Matching request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [host](https://url.spec.whatwg.org/#concept-url-host "https://url.spec.whatwg.org/#concept-url-host") per
                             [Known HSTS Host Domain Name Matching](https://www.rfc-editor.org/rfc/rfc6797.html#section-8.2 "https://www.rfc-editor.org/rfc/rfc6797.html#section-8.2")
                             results in either a superdomain match with an asserted `includeSubDomains` directive
                             or a congruent match (with or without an asserted `includeSubDomains` directive) [[HSTS]](#biblio-hsts "HTTP Strict Transport Security (HSTS)"); or
                             DNS resolution for the request finds a matching HTTPS RR per
                             [section 9.5](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https#section-9.5 "https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https#section-9.5")
                             of [[SVCB]](#biblio-svcb "Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)").
                             [[HSTS]](#biblio-hsts "HTTP Strict Transport Security (HSTS)") [[SVCB]](#biblio-svcb "Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)")

                     As all DNS operations are generally [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined"), how it is
                     determined that DNS resolution contains an HTTPS RR is also [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined"). As DNS
                     operations are not traditionally performed until attempting to [obtain a connection](#concept-connection-obtain "#concept-connection-obtain"), user
                     agents might need to perform DNS operations earlier, consult local DNS caches, or wait until later
                     in the fetch algorithm and potentially unwind logic on discovering the need to change
                     request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme").

                     - If recursive is false, then run the remaining steps [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel").

                       - If response is null, then set response to the result of running the steps
                         corresponding to the first matching statement:

                         fetchParams’s [preloaded response candidate](#fetch-params-preloaded-response-candidate "#fetch-params-preloaded-response-candidate") is non-null: 1. Wait until fetchParams’s [preloaded response candidate](#fetch-params-preloaded-response-candidate "#fetch-params-preloaded-response-candidate") is not "`pending`". - [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): fetchParams’s [preloaded response candidate](#fetch-params-preloaded-response-candidate "#fetch-params-preloaded-response-candidate") is a [response](#concept-response "#concept-response"). - Return fetchParams’s [preloaded response candidate](#fetch-params-preloaded-response-candidate "#fetch-params-preloaded-response-candidate"). request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") is [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with request’s [origin](#concept-request-origin "#concept-request-origin"), and request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is "`basic`" request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is "`data`" request’s [mode](#concept-request-mode "#concept-request-mode") is "`navigate`", "`websocket`" or "`webtransport`": 1. Set request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") to "`basic`". - Return the result of running [override fetch](#concept-override-fetch "#concept-override-fetch") given "`scheme-fetch`" and fetchParams. HTML assigns any documents and workers created from [URLs](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") whose [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is "`data`" a unique [opaque origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-opaque "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-opaque"). Service workers can only be created from [URLs](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") whose [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is an [HTTP(S) scheme](#http-scheme "#http-scheme"). [[HTML]](#biblio-html "HTML Standard") [[SW]](#biblio-sw "Service Workers Nightly") request’s [mode](#concept-request-mode "#concept-request-mode") is "`same-origin`": Return a [network error](#concept-network-error "#concept-network-error"). request’s [mode](#concept-request-mode "#concept-request-mode") is "`no-cors`": 1. If request’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") is not "`follow`", then return a [network error](#concept-network-error "#concept-network-error"). - Set request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") to "`opaque`". - Return the result of running [override fetch](#concept-override-fetch "#concept-override-fetch") given "`scheme-fetch`" and fetchParams. request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is not an [HTTP(S) scheme](#http-scheme "#http-scheme"): Return a [network error](#concept-network-error "#concept-network-error"). request’s [use-CORS-preflight flag](#use-cors-preflight-flag "#use-cors-preflight-flag") is set request’s [unsafe-request flag](#unsafe-request-flag "#unsafe-request-flag") is set and either request’s [method](#concept-request-method "#concept-request-method") is not a [CORS-safelisted method](#cors-safelisted-method "#cors-safelisted-method") or [CORS-unsafe request-header names](#cors-unsafe-request-header-names "#cors-unsafe-request-header-names") with request’s [header list](#concept-request-header-list "#concept-request-header-list") [is not empty](https://infra.spec.whatwg.org/#list-is-empty "https://infra.spec.whatwg.org/#list-is-empty"): 1. Set request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") to "`cors`". - Let corsWithPreflightResponse be the result of running [override fetch](#concept-override-fetch "#concept-override-fetch") given "`http-fetch`", fetchParams, and true. - If corsWithPreflightResponse is a [network error](#concept-network-error "#concept-network-error"), then [clear cache entries](#concept-cache-clear "#concept-cache-clear") using request. - Return corsWithPreflightResponse. Otherwise: 1. Set request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") to "`cors`". - Return the result of running [override fetch](#concept-override-fetch "#concept-override-fetch") given "`http-fetch`" and fetchParams.

                         - If recursive is true, then return response.

                           - If response is not a [network error](#concept-network-error "#concept-network-error") and response is not a
                             [filtered response](#concept-filtered-response "#concept-filtered-response"), then:

                             1. If request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is "`cors`", then:

                                1. Let headerNames be the result of [extracting header list values](#extract-header-list-values "#extract-header-list-values") given
                                   `[`Access-Control-Expose-Headers`](#http-access-control-expose-headers "#http-access-control-expose-headers")` and response’s
                                   [header list](#concept-response-header-list "#concept-response-header-list").

                                   - If request’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is not
                                     "`include`" and headerNames contains ``*``, then set
                                     response’s [CORS-exposed header-name list](#concept-response-cors-exposed-header-name-list "#concept-response-cors-exposed-header-name-list") to all unique
                                     [header](#concept-header "#concept-header") [names](#concept-header-name "#concept-header-name") in response’s
                                     [header list](#concept-response-header-list "#concept-response-header-list").

                                     - Otherwise, if headerNames is non-null or failure, then set response’s
                                       [CORS-exposed header-name list](#concept-response-cors-exposed-header-name-list "#concept-response-cors-exposed-header-name-list") to headerNames.

                                       One of the headerNames can still be ``*`` at this point,
                                       but will only match a [header](#concept-header "#concept-header") whose [name](#concept-header-name "#concept-header-name") is ``*``.- Set response to the following [filtered response](#concept-filtered-response "#concept-filtered-response") with response as
                                  its [internal response](#concept-internal-response "#concept-internal-response"), depending on request’s
                                  [response tainting](#concept-request-response-tainting "#concept-request-response-tainting"):

                                  "`basic`": [basic filtered response](#concept-filtered-response-basic "#concept-filtered-response-basic") "`cors`": [CORS filtered response](#concept-filtered-response-cors "#concept-filtered-response-cors") "`opaque`": [opaque filtered response](#concept-filtered-response-opaque "#concept-filtered-response-opaque")- Let internalResponse be response, if response is a
                               [network error](#concept-network-error "#concept-network-error"); otherwise response’s
                               [internal response](#concept-internal-response "#concept-internal-response").

                               - If internalResponse’s [URL list](#concept-response-url-list "#concept-response-url-list") [is empty](https://infra.spec.whatwg.org/#list-is-empty "https://infra.spec.whatwg.org/#list-is-empty"), then
                                 set it to a [clone](https://infra.spec.whatwg.org/#list-clone "https://infra.spec.whatwg.org/#list-clone") of request’s [URL list](#concept-request-url-list "#concept-request-url-list").

                                 A [response](#concept-response "#concept-response")’s [URL list](#concept-response-url-list "#concept-response-url-list") can be empty, e.g., when
                                 fetching an `about:` URL.

                                 - Set internalResponse’s [redirect taint](#response-redirect-taint "#response-redirect-taint") to request’s
                                   [redirect-taint](#concept-request-tainted-origin "#concept-request-tainted-origin").

                                   - If request’s [timing allow failed flag](#timing-allow-failed "#timing-allow-failed") is unset, then set
                                     internalResponse’s [timing allow passed flag](#concept-response-timing-allow-passed "#concept-response-timing-allow-passed").

                                     - If response is not a [network error](#concept-network-error "#concept-network-error") and any of the following returns
                                       **blocked**

                                       * [should internalResponse to request be blocked as mixed content](https://w3c.github.io/webappsec-mixed-content/#should-block-response "https://w3c.github.io/webappsec-mixed-content/#should-block-response")

                                         * [should internalResponse to request be blocked by Content Security Policy](https://w3c.github.io/webappsec-csp/#should-block-response "https://w3c.github.io/webappsec-csp/#should-block-response")

                                           * [should internalResponse to request be blocked due to its MIME type](#should-response-to-request-be-blocked-due-to-mime-type? "#should-response-to-request-be-blocked-due-to-mime-type?")

                                             * [should internalResponse to request be blocked due to nosniff](#should-response-to-request-be-blocked-due-to-nosniff? "#should-response-to-request-be-blocked-due-to-nosniff?")

                                       then set response and internalResponse to a [network error](#concept-network-error "#concept-network-error").

                                       - If response’s [type](#concept-response-type "#concept-response-type") is "`opaque`",
                                         internalResponse’s [status](#concept-response-status "#concept-response-status") is a [range status](#range-status "#range-status"),
                                         internalResponse’s [range-requested flag](#concept-response-range-requested-flag "#concept-response-range-requested-flag") is set, and
                                         request’s [header list](#concept-request-header-list "#concept-request-header-list") [does not contain](#header-list-contains "#header-list-contains")
                                         ``Range``, then set response and internalResponse to a
                                         [network error](#concept-network-error "#concept-network-error").

                                         Traditionally, APIs accept a ranged response even if a range was not requested. This prevents
                                         a partial response or a range not satisfiable response from an earlier ranged request being
                                         provided to an API that did not make a range request.

                                         Further details

                                         The above steps prevent the following attack:

                                         A media element is used to request a range of a cross-origin HTML resource. Although this is
                                         invalid media, a reference to a clone of the response can be retained in a service worker. This
                                         can later be used as the response to a script element’s fetch. If the partial response is valid
                                         JavaScript (even though the whole resource is not), executing it would leak private data.

                                         - If response is not a [network error](#concept-network-error "#concept-network-error") and
                                           either request’s [method](#concept-request-method "#concept-request-method") is
                                           ``HEAD`` or ``CONNECT``, or internalResponse’s
                                           [status](#concept-response-status "#concept-response-status") is a [null body status](#null-body-status "#null-body-status"),
                                           set internalResponse’s [body](#concept-response-body "#concept-response-body") to
                                           null and disregard any enqueuing toward it (if any).

                                           This standardizes the error handling for servers that violate HTTP.

                                           - If request’s [integrity metadata](#concept-request-integrity-metadata "#concept-request-integrity-metadata") is not the empty string, then:

                                             1. Let processBodyError be this step: run [fetch response handover](#fetch-finale "#fetch-finale") given
                                                fetchParams and a [network error](#concept-network-error "#concept-network-error").

                                                - If response’s [body](#concept-response-body "#concept-response-body") is null, then run
                                                  processBodyError and abort these steps.

                                                  - Let processBody given bytes be these steps:

                                                    1. If bytes do not [match](https://w3c.github.io/webappsec-subresource-integrity/#does-response-match-metadatalist "https://w3c.github.io/webappsec-subresource-integrity/#does-response-match-metadatalist")
                                                       request’s [integrity metadata](#concept-request-integrity-metadata "#concept-request-integrity-metadata"), then run
                                                       processBodyError and abort these steps. [[SRI]](#biblio-sri "Subresource Integrity")

                                                       - Set response’s [body](#concept-response-body "#concept-response-body") to bytes
                                                         [as a body](#byte-sequence-as-a-body "#byte-sequence-as-a-body").

                                                         - Run [fetch response handover](#fetch-finale "#fetch-finale") given fetchParams and response.- [Fully read](#body-fully-read "#body-fully-read") response’s [body](#concept-response-body "#concept-response-body") given
                                                      processBody and processBodyError.- Otherwise, run [fetch response handover](#fetch-finale "#fetch-finale") given fetchParams and
                                               response.

---

The fetch response handover, given a [fetch params](#fetch-params "#fetch-params")
fetchParams and a [response](#concept-response "#concept-response") response, run these steps:

1. Let timingInfo be fetchParams’s
   [timing info](#fetch-params-timing-info "#fetch-params-timing-info").

   - If response is not a [network error](#concept-network-error "#concept-network-error") and fetchParams’s
     [request](#fetch-params-request "#fetch-params-request")’s [client](#concept-request-client "#concept-request-client") is a [secure context](https://html.spec.whatwg.org/multipage/webappapis.html#secure-context "https://html.spec.whatwg.org/multipage/webappapis.html#secure-context"), then set
     timingInfo’s [server-timing headers](#fetch-timing-info-server-timing-headers "#fetch-timing-info-server-timing-headers") to the
     result of [getting, decoding, and splitting](#concept-header-list-get-decode-split "#concept-header-list-get-decode-split") ``Server-Timing``
     from response’s [internal response](#concept-internal-response "#concept-internal-response")’s
     [header list](#concept-response-header-list "#concept-response-header-list").

     Using \_response\_’s [internal response](#concept-internal-response "#concept-internal-response") is safe as
     exposing ``Server-Timing`` header data is guarded through the
     ``Timing-Allow-Origin`` header.

     The user agent may decide to expose ``Server-Timing`` headers to non-secure contexts
     requests as well.

     - If fetchParams’s [request](#fetch-params-request "#fetch-params-request")’s
       [destination](#concept-request-destination "#concept-request-destination") is "`document`", then set fetchParams’s
       [controller](#fetch-params-controller "#fetch-params-controller")’s [full timing info](#fetch-controller-full-timing-info "#fetch-controller-full-timing-info") to
       fetchParams’s [timing info](#fetch-params-timing-info "#fetch-params-timing-info").

       - Let processResponseEndOfBody be the following steps:

         1. Let unsafeEndTime be the [unsafe shared current time](https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time "https://w3c.github.io/hr-time/#dfn-unsafe-shared-current-time").

            - Set fetchParams’s [controller](#fetch-params-controller "#fetch-params-controller")’s
              [report timing steps](#fetch-controller-report-timing-steps "#fetch-controller-report-timing-steps") to the following steps given a
              [global object](https://html.spec.whatwg.org/multipage/webappapis.html#global-object "https://html.spec.whatwg.org/multipage/webappapis.html#global-object") global:

              1. If fetchParams’s [request](#fetch-params-request "#fetch-params-request")’s [URL](#concept-request-url "#concept-request-url")’s
                 [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is not an [HTTP(S) scheme](#http-scheme "#http-scheme"), then return.

                 - Set timingInfo’s [end time](#fetch-timing-info-end-time "#fetch-timing-info-end-time") to the
                   [relative high resolution time](https://w3c.github.io/hr-time/#dfn-relative-high-resolution-time "https://w3c.github.io/hr-time/#dfn-relative-high-resolution-time") given unsafeEndTime and
                   global.

                   - Let cacheState be response’s [cache state](#concept-response-cache-state "#concept-response-cache-state").

                     - Let bodyInfo be response’s [body info](#concept-response-body-info "#concept-response-body-info").

                       - If response’s [timing allow passed flag](#concept-response-timing-allow-passed "#concept-response-timing-allow-passed") is not set,
                         then set timingInfo to the result of [creating an opaque timing info](#create-an-opaque-timing-info "#create-an-opaque-timing-info") for
                         timingInfo and set cacheState to the empty string.

                         This covers the case of response being a [network error](#concept-network-error "#concept-network-error").

                         - Let responseStatus be 0.

                           - If fetchParams’s [request](#fetch-params-request "#fetch-params-request")’s [mode](#concept-request-mode "#concept-request-mode") is
                             not "`navigate`" or response’s
                             [redirect taint](#response-redirect-taint "#response-redirect-taint") is "`same-origin`":

                             1. Set responseStatus to response’s [status](#concept-response-status "#concept-response-status").

                                - Let mimeType be the result of
                                  [extracting a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type") from response’s
                                  [header list](#concept-response-header-list "#concept-response-header-list").

                                  - If mimeType is not failure, then set bodyInfo’s
                                    [content type](#response-body-info-content-type "#response-body-info-content-type") to the result of
                                    [minimizing a supported MIME type](https://mimesniff.spec.whatwg.org/#minimize-a-supported-mime-type "https://mimesniff.spec.whatwg.org/#minimize-a-supported-mime-type") given mimeType.- If fetchParams’s [request](#fetch-params-request "#fetch-params-request")’s
                               [initiator type](#request-initiator-type "#request-initiator-type") is non-null, then [mark resource timing](https://w3c.github.io/resource-timing/#dfn-mark-resource-timing "https://w3c.github.io/resource-timing/#dfn-mark-resource-timing") given
                               timingInfo, fetchParams’s [request](#fetch-params-request "#fetch-params-request")’s
                               [URL](#concept-request-url "#concept-request-url"), fetchParams’s [request](#fetch-params-request "#fetch-params-request")’s
                               [initiator type](#request-initiator-type "#request-initiator-type"), global, cacheState,
                               bodyInfo, and responseStatus.- Let processResponseEndOfBodyTask be the following steps:

                1. Set fetchParams’s [request](#fetch-params-request "#fetch-params-request")’s
                   [done flag](#done-flag "#done-flag").

                   - If fetchParams’s [process response end-of-body](#fetch-params-process-response-end-of-body "#fetch-params-process-response-end-of-body") is
                     non-null, then run fetchParams’s
                     [process response end-of-body](#fetch-params-process-response-end-of-body "#fetch-params-process-response-end-of-body") given response.

                     - If fetchParams’s [request](#fetch-params-request "#fetch-params-request")’s
                       [initiator type](#request-initiator-type "#request-initiator-type") is non-null and fetchParams’s
                       [request](#fetch-params-request "#fetch-params-request")’s [client](#concept-request-client "#concept-request-client")’s
                       [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global") is fetchParams’s
                       [task destination](#fetch-params-task-destination "#fetch-params-task-destination"), then run fetchParams’s
                       [controller](#fetch-params-controller "#fetch-params-controller")’s [report timing steps](#fetch-controller-report-timing-steps "#fetch-controller-report-timing-steps") given
                       fetchParams’s [request](#fetch-params-request "#fetch-params-request")’s [client](#concept-request-client "#concept-request-client")’s
                       [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global").- [Queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") to run processResponseEndOfBodyTask with
                  fetchParams’s [task destination](#fetch-params-task-destination "#fetch-params-task-destination").- If fetchParams’s [process response](#fetch-params-process-response "#fetch-params-process-response") is non-null, then
           [queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") to run fetchParams’s
           [process response](#fetch-params-process-response "#fetch-params-process-response") given response, with fetchParams’s
           [task destination](#fetch-params-task-destination "#fetch-params-task-destination").

           - Let internalResponse be response, if response is a
             [network error](#concept-network-error "#concept-network-error"); otherwise response’s
             [internal response](#concept-internal-response "#concept-internal-response").

             - If response is a [network error](#concept-network-error "#concept-network-error"), then run
               the [WebDriver BiDi fetch error](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-fetch-error "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-fetch-error") steps with request. Otherwise,
               run the [WebDriver BiDi response completed](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-completed "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-completed") steps with
               request and response.

               - If internalResponse’s [body](#concept-response-body "#concept-response-body") is null, then run
                 processResponseEndOfBody.

                 - Otherwise:

                   1. Let transformStream be a new `TransformStream`.

                      - Let identityTransformAlgorithm be an algorithm which, given chunk,
                        [enqueues](https://streams.spec.whatwg.org/#transformstream-enqueue "https://streams.spec.whatwg.org/#transformstream-enqueue") chunk in transformStream.

                        - [Set up](https://streams.spec.whatwg.org/#transformstream-set-up "https://streams.spec.whatwg.org/#transformstream-set-up") transformStream with
                          [*transformAlgorithm*](https://streams.spec.whatwg.org/#transformstream-set-up-transformalgorithm "https://streams.spec.whatwg.org/#transformstream-set-up-transformalgorithm") set to
                          identityTransformAlgorithm and
                          [*flushAlgorithm*](https://streams.spec.whatwg.org/#transformstream-set-up-flushalgorithm "https://streams.spec.whatwg.org/#transformstream-set-up-flushalgorithm") set to
                          processResponseEndOfBody.

                          - Set internalResponse’s [body](#concept-response-body "#concept-response-body")’s [stream](#concept-body-stream "#concept-body-stream") to the
                            result of internalResponse’s [body](#concept-response-body "#concept-response-body")’s [stream](#concept-body-stream "#concept-body-stream")
                            [piped through](https://streams.spec.whatwg.org/#readablestream-pipe-through "https://streams.spec.whatwg.org/#readablestream-pipe-through") transformStream.

                   This `TransformStream` is needed for the purpose of receiving a notification when
                   the stream reaches its end, and is otherwise an [identity transform stream](https://streams.spec.whatwg.org/#identity-transform-stream "https://streams.spec.whatwg.org/#identity-transform-stream").

                   - If fetchParams’s [process response consume body](#fetch-params-process-response-consume-body "#fetch-params-process-response-consume-body") is
                     non-null, then:

                     1. Let processBody given nullOrBytes be this step: run
                        fetchParams’s [process response consume body](#fetch-params-process-response-consume-body "#fetch-params-process-response-consume-body") given
                        response and nullOrBytes.

                        - Let processBodyError be this step: run fetchParams’s
                          [process response consume body](#fetch-params-process-response-consume-body "#fetch-params-process-response-consume-body") given response and failure.

                          - If internalResponse’s [body](#concept-response-body "#concept-response-body") is null, then
                            [queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") to run processBody given null, with fetchParams’s
                            [task destination](#fetch-params-task-destination "#fetch-params-task-destination").

                            - Otherwise, [fully read](#body-fully-read "#body-fully-read") internalResponse’s
                              [body](#concept-response-body "#concept-response-body") given processBody, processBodyError, and
                              fetchParams’s [task destination](#fetch-params-task-destination "#fetch-params-task-destination").

### 4.2. Override fetch

To override fetch, given "`scheme-fetch`" or
"`http-fetch`" type, a [fetch params](#fetch-params "#fetch-params") fetchParams, and
an optional boolean makeCORSPreflight (default false):

1. Let request be fetchParams’ [request](#fetch-params-request "#fetch-params-request").

   - Let response be the result of executing
     [potentially override response for a request](#potentially-override-response-for-a-request "#potentially-override-response-for-a-request") on request.

     - If response is non-null, then return response.

       - Switch on type and run the associated step:

         "`scheme fetch`": Set response be the result of running [scheme fetch](#concept-scheme-fetch "#concept-scheme-fetch") given fetchParams. "`HTTP fetch`": Set response be the result of running [HTTP fetch](#concept-http-fetch "#concept-http-fetch") given fetchParams and makeCORSPreflight.

         - Return response.

The potentially override response for a request algorithm takes a [request](#concept-request "#concept-request")
request, and returns either a [response](#concept-response "#concept-response") or null. Its behavior is
[implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined"), allowing user agents to intervene on the [request](#concept-request "#concept-request") by
returning a response directly, or allowing the request to proceed by returning null.

By default, the algorithm has the following trivial implementation:

1. Return null.

User agents will generally override this default implementation with a somewhat more complex
set of behaviors. For example, a user agent might decide that its users' safety is best preserved
by generally blocking requests to `https://unsafe.example/`, while synthesizing a shim for the
widely-used resource `https://unsafe.example/widget.js` to avoid breakage. That implementation
might look like the following:

1. If request’s [current url](#concept-request-current-url "#concept-request-current-url")’s [host](https://url.spec.whatwg.org/#concept-url-host "https://url.spec.whatwg.org/#concept-url-host")’s
   [registrable domain](https://url.spec.whatwg.org/#host-registrable-domain "https://url.spec.whatwg.org/#host-registrable-domain") is "`unsafe.example`":

   1. If request’s [current url](#concept-request-current-url "#concept-request-current-url")’s [path](https://url.spec.whatwg.org/#concept-url-path "https://url.spec.whatwg.org/#concept-url-path") is
      « "`widget.js`" »:

      1. Let body be [*insert a byte sequence representing the shimmed
         content here*].

         - Return a new [response](#concept-response "#concept-response") with the following properties:

           [type](#concept-response-type "#concept-response-type"): "`cors`" [status](#concept-response-status "#concept-response-status"): 200 ...: ... [body](#concept-response-body "#concept-response-body"): The result of getting body [as a body](#byte-sequence-as-a-body "#byte-sequence-as-a-body").- Return a [network error](#concept-network-error "#concept-network-error").- Return null.

### 4.3. Scheme fetch

To scheme fetch, given a
[fetch params](#fetch-params "#fetch-params") fetchParams:

1. If fetchParams is [canceled](#fetch-params-canceled "#fetch-params-canceled"), then return the
   [appropriate network error](#appropriate-network-error "#appropriate-network-error") for fetchParams.

   - Let request be fetchParams’s [request](#fetch-params-request "#fetch-params-request").

     - Switch on request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") and run
       the associated steps:

       "`about`": If request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [path](https://url.spec.whatwg.org/#concept-url-path "https://url.spec.whatwg.org/#concept-url-path") is the string "`blank`", then return a new [response](#concept-response "#concept-response") whose [status message](#concept-response-status-message "#concept-response-status-message") is ``OK``, [header list](#concept-response-header-list "#concept-response-header-list") is « (``Content-Type``, ``text/html;charset=utf-8``) », and [body](#concept-response-body "#concept-response-body") is the empty byte sequence [as a body](#byte-sequence-as-a-body "#byte-sequence-as-a-body"). [URLs](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") such as "`about:config`" are handled during [navigation](https://html.spec.whatwg.org/multipage/browsing-the-web.html#navigate "https://html.spec.whatwg.org/multipage/browsing-the-web.html#navigate") and result in a [network error](#concept-network-error "#concept-network-error") in the context of [fetching](#concept-fetch "#concept-fetch"). "`blob`": 1. Let blobURLEntry be request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [blob URL entry](https://url.spec.whatwg.org/#concept-url-blob-entry "https://url.spec.whatwg.org/#concept-url-blob-entry"). - If request’s [method](#concept-request-method "#concept-request-method") is not ``GET`` or blobURLEntry is null, then return a [network error](#concept-network-error "#concept-network-error"). [[FILEAPI]](#biblio-fileapi "File API") The ``GET`` [method](#concept-method "#concept-method") restriction serves no useful purpose other than being interoperable. - Let requestEnvironment be the result of [determining the environment](#request-determine-the-environment "#request-determine-the-environment") given request. - Let isTopLevelSelfFetch be false. - If request’s [client](#concept-request-client "#concept-request-client") is non-null: 1. Let global be request’s [client](#concept-request-client "#concept-request-client")’s [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global"). - If all of the following conditions are true: * global is a `Window` object; * global’s [navigable](https://html.spec.whatwg.org/multipage/nav-history-apis.html#window-navigable "https://html.spec.whatwg.org/multipage/nav-history-apis.html#window-navigable") is not null; * global’s [navigable](https://html.spec.whatwg.org/multipage/nav-history-apis.html#window-navigable "https://html.spec.whatwg.org/multipage/nav-history-apis.html#window-navigable")’s [parent](https://html.spec.whatwg.org/multipage/document-sequences.html#nav-parent "https://html.spec.whatwg.org/multipage/document-sequences.html#nav-parent") is null; and * requestEnvironment’s [creation URL](https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-creation-url "https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-creation-url") [equals](https://url.spec.whatwg.org/#concept-url-equals "https://url.spec.whatwg.org/#concept-url-equals") request’s [current URL](#concept-request-current-url "#concept-request-current-url"), then set isTopLevelSelfFetch to true.- Let stringOrEnvironment be the result of these steps: 1. If request’s [destination](#concept-request-destination "#concept-request-destination") is "`document`", then return "`top-level-navigation`". - If isTopLevelSelfFetch is true, then return "`top-level-self-fetch`". - Return requestEnvironment.- Let blob be the result of [obtaining a blob object](https://w3c.github.io/FileAPI/#blob-url-obtain-object "https://w3c.github.io/FileAPI/#blob-url-obtain-object") given blobURLEntry and stringOrEnvironment. - If blob is not a `Blob` object, then return a [network error](#concept-network-error "#concept-network-error"). - Let response be a new [response](#concept-response "#concept-response"). - Let fullLength be blob’s `size`. - Let serializedFullLength be fullLength, [serialized](#serialize-an-integer "#serialize-an-integer") and [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode"). - Let type be blob’s `type`. - If request’s [header list](#concept-request-header-list "#concept-request-header-list") [does not contain](#header-list-contains "#header-list-contains") ``Range``: 1. Let bodyWithType be the result of [safely extracting](#bodyinit-safely-extract "#bodyinit-safely-extract") blob. - Set response’s [status message](#concept-response-status-message "#concept-response-status-message") to ``OK``. - Set response’s [body](#concept-response-body "#concept-response-body") to bodyWithType’s [body](#body-with-type-body "#body-with-type-body"). - Set response’s [header list](#concept-response-header-list "#concept-response-header-list") to « (``Content-Length``, serializedFullLength), (``Content-Type``, type) ».- Otherwise: 1. Set response’s [range-requested flag](#concept-response-range-requested-flag "#concept-response-range-requested-flag"). - Let rangeHeader be the result of [getting](#concept-header-list-get "#concept-header-list-get") ``Range`` from request’s [header list](#concept-request-header-list "#concept-request-header-list"). - Let rangeValue be the result of [parsing a single range header value](#simple-range-header-value "#simple-range-header-value") given rangeHeader and true. - If rangeValue is failure, then return a [network error](#concept-network-error "#concept-network-error"). - Let (rangeStart, rangeEnd) be rangeValue. - If rangeStart is null: 1. Set rangeStart to fullLength − rangeEnd. - Set rangeEnd to rangeStart + rangeEnd − 1.- Otherwise: 1. If rangeStart is greater than or equal to fullLength, then return a [network error](#concept-network-error "#concept-network-error"). - If rangeEnd is null or rangeEnd is greater than or equal to fullLength, then set rangeEnd to fullLength − 1.- Let slicedBlob be the result of invoking [slice blob](https://w3c.github.io/FileAPI/#slice-blob "https://w3c.github.io/FileAPI/#slice-blob") given blob, rangeStart, rangeEnd + 1, and type. A range header denotes an inclusive byte range, while the [slice blob](https://w3c.github.io/FileAPI/#slice-blob "https://w3c.github.io/FileAPI/#slice-blob") algorithm input range does not. To use the [slice blob](https://w3c.github.io/FileAPI/#slice-blob "https://w3c.github.io/FileAPI/#slice-blob") algorithm, we have to increment rangeEnd. - Let slicedBodyWithType be the result of [safely extracting](#bodyinit-safely-extract "#bodyinit-safely-extract") slicedBlob. - Set response’s [body](#concept-response-body "#concept-response-body") to slicedBodyWithType’s [body](#body-with-type-body "#body-with-type-body"). - Let serializedSlicedLength be slicedBlob’s `size`, [serialized](#serialize-an-integer "#serialize-an-integer") and [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode"). - Let contentRange be the result of invoking [build a content range](#build-a-content-range "#build-a-content-range") given rangeStart, rangeEnd, and fullLength. - Set response’s [status](#concept-response-status "#concept-response-status") to 206. - Set response’s [status message](#concept-response-status-message "#concept-response-status-message") to ``Partial Content``. - Set response’s [header list](#concept-response-header-list "#concept-response-header-list") to « (``Content-Length``, serializedSlicedLength), (``Content-Type``, type), (``Content-Range``, contentRange) ».- Return response. "`data`": 1. Let dataURLStruct be the result of running the [`data:` URL processor](#data-url-processor "#data-url-processor") on request’s [current URL](#concept-request-current-url "#concept-request-current-url"). - If dataURLStruct is failure, then return a [network error](#concept-network-error "#concept-network-error"). - Let mimeType be dataURLStruct’s [MIME type](#data-url-struct-mime-type "#data-url-struct-mime-type"), [serialized](https://mimesniff.spec.whatwg.org/#serialize-a-mime-type-to-bytes "https://mimesniff.spec.whatwg.org/#serialize-a-mime-type-to-bytes"). - Return a new [response](#concept-response "#concept-response") whose [status message](#concept-response-status-message "#concept-response-status-message") is ``OK``, [header list](#concept-response-header-list "#concept-response-header-list") is « (``Content-Type``, mimeType) », and [body](#concept-response-body "#concept-response-body") is dataURLStruct’s [body](#data-url-struct-body "#data-url-struct-body") [as a body](#byte-sequence-as-a-body "#byte-sequence-as-a-body"). "`file`": For now, unfortunate as it is, `file:` [URLs](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url") are left as an exercise for the reader. When in doubt, return a [network error](#concept-network-error "#concept-network-error"). [HTTP(S) scheme](#http-scheme "#http-scheme"): Return the result of running [HTTP fetch](#concept-http-fetch "#concept-http-fetch") given fetchParams.

       - Return a [network error](#concept-network-error "#concept-network-error").

To determine the environment, given a [request](#concept-request "#concept-request")
request:

1. If request’s [reserved client](#concept-request-reserved-client "#concept-request-reserved-client") is non-null, then return
   request’s [reserved client](#concept-request-reserved-client "#concept-request-reserved-client").

   - If request’s [client](#concept-request-client "#concept-request-client") is non-null, then return
     request’s [client](#concept-request-client "#concept-request-client").

     - Return null.

### 4.4. HTTP fetch

To HTTP fetch, given a [fetch params](#fetch-params "#fetch-params")
fetchParams and an optional boolean makeCORSPreflight (default false), run
these steps:

1. Let request be fetchParams’s [request](#fetch-params-request "#fetch-params-request").

   - Let response and internalResponse be null.

     - If request’s [service-workers mode](#request-service-workers-mode "#request-service-workers-mode") is "`all`", then:

       1. Let requestForServiceWorker be a [clone](#concept-request-clone "#concept-request-clone") of
          request.

          - If requestForServiceWorker’s [body](#concept-body "#concept-body") is non-null, then:

            1. Let transformStream be a new `TransformStream`.

               - Let transformAlgorithm given chunk be these steps:

                 1. If fetchParams is [canceled](#fetch-params-canceled "#fetch-params-canceled"), then abort these
                    steps.

                    - If chunk is not a `Uint8Array` object, then
                      [terminate](#fetch-controller-terminate "#fetch-controller-terminate") fetchParams’s
                      [controller](#fetch-params-controller "#fetch-params-controller").

                      - Otherwise, [enqueue](https://streams.spec.whatwg.org/#readablestream-enqueue "https://streams.spec.whatwg.org/#readablestream-enqueue") chunk in
                        transformStream. The user agent may split the chunk into
                        [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") practical sizes and [enqueue](https://streams.spec.whatwg.org/#readablestream-enqueue "https://streams.spec.whatwg.org/#readablestream-enqueue") each of
                        them. The user agent also may concatenate the chunks into an [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined")
                        practical size and [enqueue](https://streams.spec.whatwg.org/#readablestream-enqueue "https://streams.spec.whatwg.org/#readablestream-enqueue") it.- [Set up](https://streams.spec.whatwg.org/#transformstream-set-up "https://streams.spec.whatwg.org/#transformstream-set-up") transformStream with
                   [*transformAlgorithm*](https://streams.spec.whatwg.org/#transformstream-set-up-transformalgorithm "https://streams.spec.whatwg.org/#transformstream-set-up-transformalgorithm") set to
                   transformAlgorithm.

                   - Set requestForServiceWorker’s [body](#concept-body "#concept-body")’s [stream](#concept-body-stream "#concept-body-stream") to
                     the result of requestForServiceWorker’s [body](#concept-body "#concept-body")’s [stream](#concept-body-stream "#concept-body-stream")
                     [piped through](https://streams.spec.whatwg.org/#readablestream-pipe-through "https://streams.spec.whatwg.org/#readablestream-pipe-through") transformStream.- Let serviceWorkerStartTime be the [coarsened shared current time](https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time "https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time")
              given fetchParams’s [cross-origin isolated capability](#fetch-params-cross-origin-isolated-capability "#fetch-params-cross-origin-isolated-capability").

              - Let fetchResponse be the result of invoking [handle fetch](https://w3c.github.io/ServiceWorker/#handle-fetch "https://w3c.github.io/ServiceWorker/#handle-fetch") for
                requestForServiceWorker, with fetchParams’s
                [controller](#fetch-params-controller "#fetch-params-controller") and fetchParams’s
                [cross-origin isolated capability](#fetch-params-cross-origin-isolated-capability "#fetch-params-cross-origin-isolated-capability"). [[HTML]](#biblio-html "HTML Standard") [[SW]](#biblio-sw "Service Workers Nightly")

                - If fetchResponse is a [response](#concept-response "#concept-response"):

                  1. Set response to fetchResponse.

                     - Set fetchParams’s [timing info](#fetch-params-timing-info "#fetch-params-timing-info")’s
                       [final service worker start time](#fetch-timing-info-final-service-worker-start-time "#fetch-timing-info-final-service-worker-start-time") to
                       serviceWorkerStartTime.

                       - Set fetchParams’s [timing info](#fetch-params-timing-info "#fetch-params-timing-info")’s
                         [service worker timing info](#fetch-timing-info-service-worker-timing-info "#fetch-timing-info-service-worker-timing-info") to response’s
                         [service worker timing info](#response-service-worker-timing-info "#response-service-worker-timing-info").

                         - If request’s [body](#concept-request-body "#concept-request-body") is non-null, then
                           [cancel](https://streams.spec.whatwg.org/#readablestream-cancel "https://streams.spec.whatwg.org/#readablestream-cancel") request’s [body](#concept-request-body "#concept-request-body") with undefined.

                           - Set internalResponse to response, if response is not a
                             [filtered response](#concept-filtered-response "#concept-filtered-response"); otherwise to response’s
                             [internal response](#concept-internal-response "#concept-internal-response").

                             - Run the [WebDriver BiDi response started](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-started "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-started") steps with
                               request and response.

                               - If one of the following is true

                                 * response’s [type](#concept-response-type "#concept-response-type") is "`error`"

                                   * request’s [mode](#concept-request-mode "#concept-request-mode") is "`same-origin`" and
                                     response’s [type](#concept-response-type "#concept-response-type") is "`cors`"

                                     * request’s [mode](#concept-request-mode "#concept-request-mode") is not "`no-cors`" and
                                       response’s [type](#concept-response-type "#concept-response-type") is "`opaque`"

                                       * request’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") is not "`manual`" and
                                         response’s [type](#concept-response-type "#concept-response-type") is "`opaqueredirect`"* request’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") is not "`follow`" and
                                           response’s [URL list](#concept-response-url-list "#concept-response-url-list") has more than one item

                                 then return a [network error](#concept-network-error "#concept-network-error").- Otherwise, if fetchResponse is a [service worker timing info](https://w3c.github.io/ServiceWorker/#service-worker-timing-info "https://w3c.github.io/ServiceWorker/#service-worker-timing-info"),
                    then set fetchParams’s [timing info](#fetch-params-timing-info "#fetch-params-timing-info")’s
                    [service worker timing info](#fetch-timing-info-service-worker-timing-info "#fetch-timing-info-service-worker-timing-info") to fetchResponse.- If response is null, then:

         1. If makeCORSPreflight is true and one of these conditions is true:

            * There is no [method cache entry match](#concept-cache-match-method "#concept-cache-match-method") for request’s
              [method](#concept-request-method "#concept-request-method") using request, and either request’s
              [method](#concept-request-method "#concept-request-method") is not a [CORS-safelisted method](#cors-safelisted-method "#cors-safelisted-method") or request’s
              [use-CORS-preflight flag](#use-cors-preflight-flag "#use-cors-preflight-flag") is set.

              * There is at least one [item](https://infra.spec.whatwg.org/#list-item "https://infra.spec.whatwg.org/#list-item") in the [CORS-unsafe request-header names](#cors-unsafe-request-header-names "#cors-unsafe-request-header-names")
                with request’s [header list](#concept-request-header-list "#concept-request-header-list") for which there is no
                [header-name cache entry match](#concept-cache-match-header "#concept-cache-match-header") using request.

            Then:

            1. Let preflightResponse be the result of running [CORS-preflight fetch](#cors-preflight-fetch-0 "#cors-preflight-fetch-0")
               given request.

               - If preflightResponse is a [network error](#concept-network-error "#concept-network-error"), then return
                 preflightResponse.

            This step checks the [CORS-preflight cache](#concept-cache "#concept-cache") and if there is no suitable entry
            it performs a [CORS-preflight fetch](#cors-preflight-fetch-0 "#cors-preflight-fetch-0") which, if successful, populates the cache. The purpose
            of the [CORS-preflight fetch](#cors-preflight-fetch-0 "#cors-preflight-fetch-0") is to ensure the [fetched](#concept-fetch "#concept-fetch") resource is
            familiar with the [CORS protocol](#cors-protocol "#cors-protocol"). The cache is there to minimize the number of
            [CORS-preflight fetches](#cors-preflight-fetch-0 "#cors-preflight-fetch-0").

            - If request’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") is "`follow`", then set
              request’s [service-workers mode](#request-service-workers-mode "#request-service-workers-mode") to "`none`".

              Redirects coming from the network (as opposed to from a service worker) are not to
              be exposed to a service worker.

              - Set response and internalResponse to the result of running
                [HTTP-network-or-cache fetch](#concept-http-network-or-cache-fetch "#concept-http-network-or-cache-fetch") given fetchParams.

                - If request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is "`cors`" and a
                  [CORS check](#concept-cors-check "#concept-cors-check") for request and response returns failure, then return a
                  [network error](#concept-network-error "#concept-network-error").

                  As the [CORS check](#concept-cors-check "#concept-cors-check") is not to be applied to [responses](#concept-response "#concept-response") whose
                  [status](#concept-response-status "#concept-response-status") is 304 or 407, or [responses](#concept-response "#concept-response") from a service worker for
                  that matter, it is applied here.

                  - If the [TAO check](#concept-tao-check "#concept-tao-check") for request and response returns failure,
                    then set request’s [timing allow failed flag](#timing-allow-failed "#timing-allow-failed").- If either request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") or response’s
           [type](#concept-response-type "#concept-response-type") is "`opaque`", and the
           [cross-origin resource policy check](#cross-origin-resource-policy-check "#cross-origin-resource-policy-check") with request’s [origin](#concept-request-origin "#concept-request-origin"),
           request’s [client](#concept-request-client "#concept-request-client"), request’s
           [destination](#concept-request-destination "#concept-request-destination"), and internalResponse returns **blocked**, then
           return a [network error](#concept-network-error "#concept-network-error").

           The [cross-origin resource policy check](#cross-origin-resource-policy-check "#cross-origin-resource-policy-check") runs for responses coming from the
           network and responses coming from the service worker. This is different from the
           [CORS check](#concept-cors-check "#concept-cors-check"), as request’s [client](#concept-request-client "#concept-request-client") and the service worker can
           have different embedder policies.

           - If internalResponse’s [status](#concept-response-status "#concept-response-status") is a [redirect status](#redirect-status "#redirect-status"):

             1. If internalResponse’s [status](#concept-response-status "#concept-response-status") is not 303, request’s
                [body](#concept-request-body "#concept-request-body") is non-null, and the [connection](#concept-connection "#concept-connection") uses HTTP/2, then user agents
                may, and are even encouraged to, transmit an `RST_STREAM` frame.

                303 is excluded as certain communities ascribe special status to it.

                - Switch on request’s
                  [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode"):

                  "`error`": 1. Set response to a [network error](#concept-network-error "#concept-network-error"). "`manual`": 1. If request’s [mode](#concept-request-mode "#concept-request-mode") is "`navigate`", then set fetchParams’s [controller](#fetch-params-controller "#fetch-params-controller")’s [next manual redirect steps](#fetch-controller-next-manual-redirect-steps "#fetch-controller-next-manual-redirect-steps") to run [HTTP-redirect fetch](#concept-http-redirect-fetch "#concept-http-redirect-fetch") given fetchParams and response. - Otherwise, set response to an [opaque-redirect filtered response](#concept-filtered-response-opaque-redirect "#concept-filtered-response-opaque-redirect") whose [internal response](#concept-internal-response "#concept-internal-response") is internalResponse. "`follow`": 1. Run the [WebDriver BiDi response completed](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-completed "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-completed") steps with request and response.- Set response to the result of running [HTTP-redirect fetch](#concept-http-redirect-fetch "#concept-http-redirect-fetch") given fetchParams and response.- Return response. Typically internalResponse’s
               [body](#concept-response-body "#concept-response-body")’s [stream](#concept-body-stream "#concept-body-stream") is still being enqueued to after
               returning.

### 4.5. HTTP-redirect fetch

To HTTP-redirect fetch, given a
[fetch params](#fetch-params "#fetch-params") fetchParams and a [response](#concept-response "#concept-response") response,
run these steps:

1. Let request be fetchParams’s [request](#fetch-params-request "#fetch-params-request").

   - Let internalResponse be response, if response is not a
     [filtered response](#concept-filtered-response "#concept-filtered-response"); otherwise response’s
     [internal response](#concept-internal-response "#concept-internal-response").

     - Let locationURL be internalResponse’s [location URL](#concept-response-location-url "#concept-response-location-url")
       given request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [fragment](https://url.spec.whatwg.org/#concept-url-fragment "https://url.spec.whatwg.org/#concept-url-fragment").

       - If locationURL is null, then return response.

         - If locationURL is failure, then return a [network error](#concept-network-error "#concept-network-error").

           - If locationURL’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is not an [HTTP(S) scheme](#http-scheme "#http-scheme"), then
             return a [network error](#concept-network-error "#concept-network-error").

             - If request’s [redirect count](#concept-request-redirect-count "#concept-request-redirect-count") is 20, then return a
               [network error](#concept-network-error "#concept-network-error").

               - Increase request’s [redirect count](#concept-request-redirect-count "#concept-request-redirect-count") by 1.

                 - If request’s [mode](#concept-request-mode "#concept-request-mode") is "`cors`",
                   locationURL [includes credentials](https://url.spec.whatwg.org/#include-credentials "https://url.spec.whatwg.org/#include-credentials"), and request’s
                   [origin](#concept-request-origin "#concept-request-origin") is not [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with locationURL’s
                   [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin"), then return a [network error](#concept-network-error "#concept-network-error").

                   - If request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is "`cors`" and
                     locationURL [includes credentials](https://url.spec.whatwg.org/#include-credentials "https://url.spec.whatwg.org/#include-credentials"), then return a [network error](#concept-network-error "#concept-network-error").

                     This catches a cross-origin resource redirecting to a same-origin URL.

                     - If internalResponse’s [status](#concept-response-status "#concept-response-status") is not 303, request’s
                       [body](#concept-request-body "#concept-request-body") is non-null, and request’s [body](#concept-request-body "#concept-request-body")’s
                       [source](#concept-body-source "#concept-body-source") is null, then return a [network error](#concept-network-error "#concept-network-error").

                       - If one of the following is true

                         * internalResponse’s [status](#concept-response-status "#concept-response-status") is 301 or 302 and
                           request’s [method](#concept-request-method "#concept-request-method") is ``POST``

                           * internalResponse’s [status](#concept-response-status "#concept-response-status") is 303 and request’s
                             [method](#concept-request-method "#concept-request-method") is not ``GET`` or ``HEAD``

                         then:

                         1. Set request’s [method](#concept-request-method "#concept-request-method") to ``GET`` and
                            request’s [body](#concept-request-body "#concept-request-body") to null.

                            - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") headerName of [request-body-header name](#request-body-header-name "#request-body-header-name"),
                              [delete](#concept-header-list-delete "#concept-header-list-delete") headerName from request’s
                              [header list](#concept-request-header-list "#concept-request-header-list").- If request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") is not
                           [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with locationURL’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin"), then
                           [for each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") headerName of [CORS non-wildcard request-header name](#cors-non-wildcard-request-header-name "#cors-non-wildcard-request-header-name"),
                           [delete](#concept-header-list-delete "#concept-header-list-delete") headerName from request’s
                           [header list](#concept-request-header-list "#concept-request-header-list").

                           I.e., the moment another origin is seen after the initial request, the
                           ``Authorization`` header is removed.

                           - If request’s [body](#concept-request-body "#concept-request-body") is non-null, then set request’s
                             [body](#concept-request-body "#concept-request-body") to the [body](#body-with-type-body "#body-with-type-body") of the result of
                             [safely extracting](#bodyinit-safely-extract "#bodyinit-safely-extract") request’s [body](#concept-request-body "#concept-request-body")’s
                             [source](#concept-body-source "#concept-body-source").

                             request’s [body](#concept-request-body "#concept-request-body")’s [source](#concept-body-source "#concept-body-source")’s nullity has
                             already been checked.

                             - Let timingInfo be fetchParams’s [timing info](#fetch-params-timing-info "#fetch-params-timing-info").

                               - Set timingInfo’s [redirect end time](#fetch-timing-info-redirect-end-time "#fetch-timing-info-redirect-end-time") and
                                 [post-redirect start time](#fetch-timing-info-post-redirect-start-time "#fetch-timing-info-post-redirect-start-time") to the
                                 [coarsened shared current time](https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time "https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time") given fetchParams’s
                                 [cross-origin isolated capability](#fetch-params-cross-origin-isolated-capability "#fetch-params-cross-origin-isolated-capability").

                                 - If timingInfo’s [redirect start time](#fetch-timing-info-redirect-start-time "#fetch-timing-info-redirect-start-time") is 0, then set
                                   timingInfo’s [redirect start time](#fetch-timing-info-redirect-start-time "#fetch-timing-info-redirect-start-time") to
                                   timingInfo’s [start time](#fetch-timing-info-start-time "#fetch-timing-info-start-time").

                                   - [Append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") locationURL to request’s
                                     [URL list](#concept-request-url-list "#concept-request-url-list").

                                     - Invoke [set request’s referrer policy on redirect](https://w3c.github.io/webappsec-referrer-policy/#set-requests-referrer-policy-on-redirect "https://w3c.github.io/webappsec-referrer-policy/#set-requests-referrer-policy-on-redirect") on request and
                                       internalResponse. [[REFERRER]](#biblio-referrer "Referrer Policy")

                                       - Let recursive be true.

                                         - If request’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") is "`manual`", then:

                                           1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [mode](#concept-request-mode "#concept-request-mode") is
                                              "`navigate`".

                                              - Set recursive to false.- Return the result of running [main fetch](#concept-main-fetch "#concept-main-fetch") given fetchParams and
                                             recursive.

                                             This has to invoke [main fetch](#concept-main-fetch "#concept-main-fetch") to get request’s
                                             [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") correct.

### 4.6. HTTP-network-or-cache fetch

To HTTP-network-or-cache fetch, given a
[fetch params](#fetch-params "#fetch-params") fetchParams, an optional boolean
isAuthenticationFetch (default false), and an optional boolean
isNewConnectionFetch (default false), run these steps:

Some implementations might support caching of partial content, as per
HTTP Caching. However, this is not widely supported by browser caches.
[[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

1. Let request be fetchParams’s [request](#fetch-params-request "#fetch-params-request").

   - Let httpFetchParams be null.

     - Let httpRequest be null.

       - Let response be null.

         - Let storedResponse be null.

           - Let httpCache be null.

             - Let the revalidatingFlag be unset.

               - Run these steps, but [abort when](https://infra.spec.whatwg.org/#abort-when "https://infra.spec.whatwg.org/#abort-when") fetchParams is
                 [canceled](#fetch-params-canceled "#fetch-params-canceled"):

                 1. If request’s [traversable for user prompts](#concept-request-window "#concept-request-window") is
                    "`no-traversable`" and request’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") is
                    "`error`", then set httpFetchParams to fetchParams and
                    httpRequest to request.

                    - Otherwise:

                      1. Set httpRequest to a [clone](#concept-request-clone "#concept-request-clone") of request.

                         Implementations are encouraged to avoid teeing request’s
                         [body](#concept-request-body "#concept-request-body")’s [stream](#concept-body-stream "#concept-body-stream") when request’s
                         [body](#concept-request-body "#concept-request-body")’s [source](#concept-body-source "#concept-body-source") is null as only a single body is needed in
                         that case. E.g., when request’s [body](#concept-request-body "#concept-request-body")’s [source](#concept-body-source "#concept-body-source")
                         is null, redirects and authentication will end up failing the fetch.

                         - Set httpFetchParams to a copy of fetchParams.

                           - Set httpFetchParams’s [request](#fetch-params-request "#fetch-params-request") to
                             httpRequest.

                      If user prompts or redirects are possible, then the user agent might need to
                      re-send the request with a new set of headers after the user answers the prompt or the redirect
                      location is determined. At that time, the original request body might have been partially sent
                      already, so we need to clone the request (including the body) beforehand so that we have a
                      spare copy available.

                      - Let includeCredentials be true if one of

                        * request’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is
                          "`include`"* request’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is
                            "`same-origin`" and request’s
                            [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is "`basic`"

                        is true; otherwise false.

                        - If [Cross-Origin-Embedder-Policy allows credentials](#cross-origin-embedder-policy-allows-credentials "#cross-origin-embedder-policy-allows-credentials") with request returns
                          false, then set includeCredentials to false.

                          - Let contentLength be httpRequest’s [body](#concept-request-body "#concept-request-body")’s
                            [length](#concept-body-total-bytes "#concept-body-total-bytes"), if httpRequest’s [body](#concept-request-body "#concept-request-body") is non-null;
                            otherwise null.

                            - Let contentLengthHeaderValue be null.

                              - If httpRequest’s [body](#concept-request-body "#concept-request-body") is null and httpRequest’s
                                [method](#concept-request-method "#concept-request-method") is ``POST`` or ``PUT``, then set
                                contentLengthHeaderValue to ``0``.

                                - If contentLength is non-null, then set contentLengthHeaderValue to
                                  contentLength, [serialized](#serialize-an-integer "#serialize-an-integer") and
                                  [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode").

                                  - If contentLengthHeaderValue is non-null, then [append](#concept-header-list-append "#concept-header-list-append")
                                    (``Content-Length``, contentLengthHeaderValue) to httpRequest’s
                                    [header list](#concept-request-header-list "#concept-request-header-list").

                                    - If contentLength is non-null and httpRequest’s
                                      [keepalive](#request-keepalive-flag "#request-keepalive-flag") is true, then:

                                      1. Let inflightKeepaliveBytes be 0.

                                         - Let group be httpRequest’s [client](#concept-request-client "#concept-request-client")’s
                                           [fetch group](#environment-settings-object-fetch-group "#environment-settings-object-fetch-group").

                                           - Let inflightRecords be the set of [fetch records](#concept-fetch-record "#concept-fetch-record") in
                                             group whose [request](#concept-fetch-record-request "#concept-fetch-record-request")’s [keepalive](#request-keepalive-flag "#request-keepalive-flag") is true
                                             and [done flag](#done-flag "#done-flag") is unset.

                                             - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") fetchRecord of inflightRecords:

                                               1. Let inflightRequest be fetchRecord’s
                                                  [request](#concept-fetch-record-request "#concept-fetch-record-request").

                                                  - Increment inflightKeepaliveBytes by inflightRequest’s
                                                    [body](#concept-request-body "#concept-request-body")’s [length](#concept-body-total-bytes "#concept-body-total-bytes").- If the sum of contentLength and inflightKeepaliveBytes is greater
                                                 than 64 kibibytes, then return a [network error](#concept-network-error "#concept-network-error").

                                      The above limit ensures that requests that are allowed to outlive the
                                      [environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object") and contain a body, have a bounded size and are not allowed
                                      to stay alive indefinitely.

                                      - If httpRequest’s [referrer](#concept-request-referrer "#concept-request-referrer") is a [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url"), then:

                                        1. Let referrerValue be httpRequest’s [referrer](#concept-request-referrer "#concept-request-referrer"),
                                           [serialized](https://url.spec.whatwg.org/#concept-url-serializer "https://url.spec.whatwg.org/#concept-url-serializer") and [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode").

                                           - [Append](#concept-header-list-append "#concept-header-list-append") (``Referer``, referrerValue) to
                                             httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list").- [Append a request ``Origin`` header](#append-a-request-origin-header "#append-a-request-origin-header") for httpRequest.

                                          - [Append the Fetch metadata headers for httpRequest](https://w3c.github.io/webappsec-fetch-metadata/#abstract-opdef-append-the-fetch-metadata-headers-for-a-request "https://w3c.github.io/webappsec-fetch-metadata/#abstract-opdef-append-the-fetch-metadata-headers-for-a-request").
                                            [[FETCH-METADATA]](#biblio-fetch-metadata "Fetch Metadata Request Headers")

                                            - If httpRequest’s [initiator](#concept-request-initiator "#concept-request-initiator") is "`prefetch`", then
                                              [set a structured field value](#concept-header-list-set-structured-header "#concept-header-list-set-structured-header") given (`[`Sec-Purpose`](#http-sec-purpose "#http-sec-purpose")`,
                                              the [token](https://httpwg.org/specs/rfc9651.html#token "https://httpwg.org/specs/rfc9651.html#token") `prefetch`) in
                                              httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list").

                                              - If httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list") [does not contain](#header-list-contains "#header-list-contains") ``User-Agent``, then user agents should:

                                                1. Let userAgent be httpRequest’s [client](#concept-request-client "#concept-request-client")’s
                                                   [environment default ``User-Agent`` value](#environment-default-user-agent-value "#environment-default-user-agent-value").

                                                   - [Append](#concept-header-list-append "#concept-header-list-append") (``User-Agent``, userAgent) to
                                                     httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list").- If httpRequest’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") is "`default`" and
                                                  httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list") [contains](#header-list-contains "#header-list-contains")
                                                  ``If-Modified-Since``,
                                                  ``If-None-Match``,
                                                  ``If-Unmodified-Since``,
                                                  ``If-Match``, or
                                                  ``If-Range``, then set httpRequest’s
                                                  [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") to "`no-store`".

                                                  - If httpRequest’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") is "`no-cache`",
                                                    httpRequest’s [prevent no-cache cache-control header modification flag](#no-cache-prevent-cache-control "#no-cache-prevent-cache-control")
                                                    is unset, and httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list")
                                                    [does not contain](#header-list-contains "#header-list-contains") ``Cache-Control``, then
                                                    [append](#concept-header-list-append "#concept-header-list-append") (``Cache-Control``, ``max-age=0``) to
                                                    httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list").

                                                    - If httpRequest’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") is "`no-store`" or
                                                      "`reload`", then:

                                                      1. If httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list")
                                                         [does not contain](#header-list-contains "#header-list-contains") ``Pragma``, then
                                                         [append](#concept-header-list-append "#concept-header-list-append") (``Pragma``, ``no-cache``) to
                                                         httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list").

                                                         - If httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list")
                                                           [does not contain](#header-list-contains "#header-list-contains") ``Cache-Control``, then
                                                           [append](#concept-header-list-append "#concept-header-list-append") (``Cache-Control``, ``no-cache``) to
                                                           httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list").- If httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list") [contains](#header-list-contains "#header-list-contains")
                                                        ``Range``, then [append](#concept-header-list-append "#concept-header-list-append") (``Accept-Encoding``,
                                                        ``identity``) to httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list").

                                                        This avoids a failure when [handling content codings](#handle-content-codings "#handle-content-codings") with
                                                        a part of an encoded [response](#concept-response "#concept-response").

                                                        Additionally,
                                                        [many servers](https://jakearchibald.github.io/accept-encoding-range-test/ "https://jakearchibald.github.io/accept-encoding-range-test/")
                                                        mistakenly ignore ``Range`` headers if a non-identity encoding is accepted.

                                                        - Modify httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list") per HTTP. Do not
                                                          [append](#concept-header-list-append "#concept-header-list-append") a given [header](#concept-header "#concept-header") if httpRequest’s
                                                          [header list](#concept-request-header-list "#concept-request-header-list") [contains](#header-list-contains "#header-list-contains") that [header](#concept-header "#concept-header")’s
                                                          [name](#concept-header-name "#concept-header-name").

                                                          It would be great if we could make this more normative somehow. At this point
                                                          [headers](#concept-header "#concept-header") such as
                                                          ``Accept-Encoding``,
                                                          ``Connection``,
                                                          ``DNT``, and
                                                          ``Host``,
                                                          are to be [appended](#concept-header-list-append "#concept-header-list-append") if necessary.

                                                          ``Accept``,
                                                          ``Accept-Charset``, and
                                                          ``Accept-Language`` must not be included at this point.

                                                          ``Accept`` and ``Accept-Language`` are already included
                                                          (unless [`fetch()`](#dom-global-fetch "#dom-global-fetch") is used, which does not include the latter by
                                                          default), and ``Accept-Charset`` is a waste of bytes. See
                                                          [HTTP header layer division](#http-header-layer-division "#http-header-layer-division") for more details.

                                                          - If includeCredentials is true, then:

                                                            1. [Append a request ``Cookie`` header](#append-a-request-cookie-header "#append-a-request-cookie-header") for httpRequest.

                                                               - If httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list")
                                                                 [does not contain](#header-list-contains "#header-list-contains") ``Authorization``, then:

                                                                 1. Let authorizationValue be null.

                                                                    - If there’s an [authentication entry](#authentication-entry "#authentication-entry") for httpRequest and either
                                                                      httpRequest’s [use-URL-credentials flag](#concept-request-use-url-credentials-flag "#concept-request-use-url-credentials-flag") is unset or
                                                                      httpRequest’s [current URL](#concept-request-current-url "#concept-request-current-url") does not [include credentials](https://url.spec.whatwg.org/#include-credentials "https://url.spec.whatwg.org/#include-credentials"),
                                                                      then set authorizationValue to [authentication entry](#authentication-entry "#authentication-entry").

                                                                      - Otherwise, if httpRequest’s [current URL](#concept-request-current-url "#concept-request-current-url") does
                                                                        [include credentials](https://url.spec.whatwg.org/#include-credentials "https://url.spec.whatwg.org/#include-credentials") and isAuthenticationFetch is true, set
                                                                        authorizationValue to httpRequest’s [current URL](#concept-request-current-url "#concept-request-current-url"),
                                                                        converted to an ``Authorization`` value.

                                                                        - If authorizationValue is non-null, then [append](#concept-header-list-append "#concept-header-list-append")
                                                                          (``Authorization``, authorizationValue) to httpRequest’s
                                                                          [header list](#concept-request-header-list "#concept-request-header-list").- If there’s a [proxy-authentication entry](#proxy-authentication-entry "#proxy-authentication-entry"), use it as appropriate.

                                                              This intentionally does not depend on httpRequest’s
                                                              [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode").

                                                              - Run the [WebDriver BiDi before request sent](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-before-request-sent "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-before-request-sent") steps with request.

                                                                - Set httpCache to the result of [determining the HTTP cache partition](#determine-the-http-cache-partition "#determine-the-http-cache-partition"),
                                                                  given httpRequest.

                                                                  - If httpCache is null, then set httpRequest’s
                                                                    [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") to "`no-store`".

                                                                    - If httpRequest’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") is neither "`no-store`"
                                                                      nor "`reload`", then:

                                                                      1. Set storedResponse to the result of selecting a response from the
                                                                         httpCache, possibly needing validation, as per the
                                                                         "[Constructing Responses from Caches](https://httpwg.org/specs/rfc9111.html#constructing.responses.from.caches "https://httpwg.org/specs/rfc9111.html#constructing.responses.from.caches")" chapter of HTTP Caching, if any.
                                                                         [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

                                                                         As mandated by HTTP, this still takes the ``Vary``
                                                                         [header](#concept-header "#concept-header") into account.

                                                                         - If storedResponse is non-null, then:

                                                                           1. If [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") is "`default`", storedResponse
                                                                              is a [stale-while-revalidate response](#concept-stale-while-revalidate-response "#concept-stale-while-revalidate-response"), and httpRequest’s
                                                                              [client](#concept-request-client "#concept-request-client") is non-null, then:

                                                                              1. Set response to storedResponse.

                                                                                 - Set response’s [cache state](#concept-response-cache-state "#concept-response-cache-state") to "`local`".

                                                                                   - Let revalidateRequest be a [clone](#concept-request-clone "#concept-request-clone") of
                                                                                     request.

                                                                                     - Set revalidateRequest’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") set to
                                                                                       "`no-cache`".

                                                                                       - Set revalidateRequest’s
                                                                                         [prevent no-cache cache-control header modification flag](#no-cache-prevent-cache-control "#no-cache-prevent-cache-control").

                                                                                         - Set revalidateRequest’s [service-workers mode](#request-service-workers-mode "#request-service-workers-mode") set to
                                                                                           "`none`".

                                                                                           - [In parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel"), run [main fetch](#concept-main-fetch "#concept-main-fetch") given a new [fetch params](#fetch-params "#fetch-params") whose
                                                                                             [request](#fetch-params-request "#fetch-params-request") is revalidateRequest.

                                                                                             This fetch is only meant to update the state of httpCache
                                                                                             and the response will be unused until another cache access. The stale response will be used
                                                                                             as the response to current request. This fetch is issued in the context of a client so if
                                                                                             it goes away the request will be terminated.- Otherwise:

                                                                                1. If storedResponse is a [stale response](#concept-stale-response "#concept-stale-response"), then set the
                                                                                   revalidatingFlag.

                                                                                   - If the revalidatingFlag is set and httpRequest’s
                                                                                     [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") is neither "`force-cache`" nor
                                                                                     "`only-if-cached`", then:

                                                                                     1. If storedResponse’s [header list](#concept-response-header-list "#concept-response-header-list")
                                                                                        [contains](#header-list-contains "#header-list-contains") ``ETag``, then
                                                                                        [append](#concept-header-list-append "#concept-header-list-append") (``If-None-Match``, ``ETag``'s
                                                                                        [value](#concept-header-value "#concept-header-value")) to httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list").

                                                                                        - If storedResponse’s [header list](#concept-response-header-list "#concept-response-header-list")
                                                                                          [contains](#header-list-contains "#header-list-contains") ``Last-Modified``, then
                                                                                          [append](#concept-header-list-append "#concept-header-list-append") (``If-Modified-Since``,
                                                                                          ``Last-Modified``'s [value](#concept-header-value "#concept-header-value")) to httpRequest’s
                                                                                          [header list](#concept-request-header-list "#concept-request-header-list").

                                                                                     See also the "[Sending a Validation Request](https://httpwg.org/specs/rfc9111.html#validation.sent "https://httpwg.org/specs/rfc9111.html#validation.sent")" chapter of
                                                                                     HTTP Caching. [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

                                                                                     - Otherwise, set response to storedResponse and set
                                                                                       response’s [cache state](#concept-response-cache-state "#concept-response-cache-state") to "`local`".- [If aborted](https://infra.spec.whatwg.org/#if-aborted "https://infra.spec.whatwg.org/#if-aborted"), then return the [appropriate network error](#appropriate-network-error "#appropriate-network-error") for
                   fetchParams.

                   - If response is not null, then run the [WebDriver BiDi response
                     started](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-started "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-started") steps with request and response.

                     - If response is null, then:

                       1. If httpRequest’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") is
                          "`only-if-cached`", then return a [network error](#concept-network-error "#concept-network-error").

                          - Let forwardResponse be the result of running [HTTP-network fetch](#concept-http-network-fetch "#concept-http-network-fetch") given
                            httpFetchParams, includeCredentials, and isNewConnectionFetch.

                            - If httpRequest’s [method](#concept-request-method "#concept-request-method") is [unsafe](https://httpwg.org/specs/rfc9110.html#rfc.section.9.2.1 "https://httpwg.org/specs/rfc9110.html#rfc.section.9.2.1") and
                              forwardResponse’s [status](#concept-response-status "#concept-response-status") is in the range 200 to 399, inclusive,
                              invalidate appropriate stored responses in httpCache, as per the
                              "[Invalidating Stored Responses](https://httpwg.org/specs/rfc9111.html#invalidation "https://httpwg.org/specs/rfc9111.html#invalidation")" chapter of HTTP Caching, and set
                              storedResponse to null. [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

                              - If the revalidatingFlag is set and forwardResponse’s
                                [status](#concept-response-status "#concept-response-status") is 304, then:

                                1. Update storedResponse’s [header list](#concept-response-header-list "#concept-response-header-list") using
                                   forwardResponse’s [header list](#concept-response-header-list "#concept-response-header-list"), as per the
                                   "[Freshening Stored Responses upon Validation](https://httpwg.org/specs/rfc9111.html#freshening.responses "https://httpwg.org/specs/rfc9111.html#freshening.responses")" chapter of HTTP Caching.
                                   [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

                                   This updates the stored response in cache as well.

                                   - Set response to storedResponse.

                                     - Set response’s [cache state](#concept-response-cache-state "#concept-response-cache-state") to "`validated`".- If response is null, then:

                                  1. Set response to forwardResponse.

                                     - Store httpRequest and forwardResponse in httpCache, as per
                                       the "[Storing Responses in Caches](https://httpwg.org/specs/rfc9111.html#response.cacheability "https://httpwg.org/specs/rfc9111.html#response.cacheability")" chapter of HTTP Caching.
                                       [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

                                       If forwardResponse is a [network error](#concept-network-error "#concept-network-error"), this effectively caches
                                       the network error, which is sometimes known as "negative caching".

                                       The associated [body info](#concept-response-body-info "#concept-response-body-info") is stored in the cache
                                       alongside the response.- Set response’s [URL list](#concept-response-url-list "#concept-response-url-list") to a [clone](https://infra.spec.whatwg.org/#list-clone "https://infra.spec.whatwg.org/#list-clone") of
                         httpRequest’s [URL list](#concept-request-url-list "#concept-request-url-list").

                         - If httpRequest’s [header list](#concept-request-header-list "#concept-request-header-list") [contains](#header-list-contains "#header-list-contains")
                           ``Range``, then set response’s [range-requested flag](#concept-response-range-requested-flag "#concept-response-range-requested-flag").

                           - Set response’s [request-includes-credentials](#response-request-includes-credentials "#response-request-includes-credentials") to
                             includeCredentials.

                             - If response’s [status](#concept-response-status "#concept-response-status") is 401, httpRequest’s
                               [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is not "`cors`", includeCredentials is
                               true, and request’s [traversable for user prompts](#concept-request-window "#concept-request-window") is a
                               [traversable navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable"):

                               1. Needs testing: multiple ``WWW-Authenticate`` headers, missing,
                                  parsing issues.

                                  - If request’s [body](#concept-request-body "#concept-request-body") is non-null, then:

                                    1. If request’s [body](#concept-request-body "#concept-request-body")’s [source](#concept-body-source "#concept-body-source") is null,
                                       then return a [network error](#concept-network-error "#concept-network-error").

                                       - Set request’s [body](#concept-request-body "#concept-request-body") to the [body](#body-with-type-body "#body-with-type-body")
                                         of the result of [safely extracting](#bodyinit-safely-extract "#bodyinit-safely-extract") request’s
                                         [body](#concept-request-body "#concept-request-body")’s [source](#concept-body-source "#concept-body-source").- If request’s [use-URL-credentials flag](#concept-request-use-url-credentials-flag "#concept-request-use-url-credentials-flag") is unset or
                                      isAuthenticationFetch is true, then:

                                      1. If fetchParams is [canceled](#fetch-params-canceled "#fetch-params-canceled"), then return the
                                         [appropriate network error](#appropriate-network-error "#appropriate-network-error") for fetchParams.

                                         - Let username and password be the result of prompting the end user
                                           for a username and password, respectively, in request’s
                                           [traversable for user prompts](#concept-request-window "#concept-request-window").

                                           - [Set the username](https://url.spec.whatwg.org/#set-the-username "https://url.spec.whatwg.org/#set-the-username") given request’s [current URL](#concept-request-current-url "#concept-request-current-url") and
                                             username.

                                             - [Set the password](https://url.spec.whatwg.org/#set-the-password "https://url.spec.whatwg.org/#set-the-password") given request’s [current URL](#concept-request-current-url "#concept-request-current-url") and
                                               password.- Set response to the result of running [HTTP-network-or-cache fetch](#concept-http-network-or-cache-fetch "#concept-http-network-or-cache-fetch") given
                                        fetchParams and true.- If response’s [status](#concept-response-status "#concept-response-status") is 407, then:

                                 1. If request’s [traversable for user prompts](#concept-request-window "#concept-request-window") is
                                    "`no-traversable`", then return a [network error](#concept-network-error "#concept-network-error").

                                    - Needs testing: multiple ``Proxy-Authenticate`` headers, missing,
                                      parsing issues.

                                      - If fetchParams is [canceled](#fetch-params-canceled "#fetch-params-canceled"), then return the
                                        [appropriate network error](#appropriate-network-error "#appropriate-network-error") for fetchParams.

                                        - Prompt the end user as appropriate in request’s
                                          [traversable for user prompts](#concept-request-window "#concept-request-window") and store the result as a
                                          [proxy-authentication entry](#proxy-authentication-entry "#proxy-authentication-entry"). [[HTTP]](#biblio-http "HTTP Semantics")

                                          Remaining details surrounding proxy authentication are defined by HTTP.

                                          - Set response to the result of running [HTTP-network-or-cache fetch](#concept-http-network-or-cache-fetch "#concept-http-network-or-cache-fetch") given
                                            fetchParams.- If all of the following are true

                                   * response’s [status](#concept-response-status "#concept-response-status") is 421

                                     * isNewConnectionFetch is false

                                       * request’s [body](#concept-request-body "#concept-request-body") is null, or request’s
                                         [body](#concept-request-body "#concept-request-body") is non-null and request’s [body](#concept-request-body "#concept-request-body")’s
                                         [source](#concept-body-source "#concept-body-source") is non-null

                                   then:

                                   1. If fetchParams is [canceled](#fetch-params-canceled "#fetch-params-canceled"), then return the
                                      [appropriate network error](#appropriate-network-error "#appropriate-network-error") for fetchParams.

                                      - Set response to the result of running [HTTP-network-or-cache fetch](#concept-http-network-or-cache-fetch "#concept-http-network-or-cache-fetch") given
                                        fetchParams, isAuthenticationFetch, and true.- If isAuthenticationFetch is true, then create an [authentication entry](#authentication-entry "#authentication-entry") for
                                     request and the given realm.

                                     - Return response. Typically response’s
                                       [body](#concept-response-body "#concept-response-body")’s [stream](#concept-body-stream "#concept-body-stream") is still being enqueued to after
                                       returning.

### 4.7. HTTP-network fetch

To HTTP-network fetch, given a [fetch params](#fetch-params "#fetch-params")
fetchParams, an optional boolean includeCredentials (default false), and an
optional boolean forceNewConnection (default false), run these steps:

1. Let request be fetchParams’s [request](#fetch-params-request "#fetch-params-request").

   - If request’s [client](#concept-request-client "#concept-request-client") [is offline](#is-offline "#is-offline"), then return a
     [network error](#concept-network-error "#concept-network-error").

     - Let response be null.

       - Let timingInfo be fetchParams’s [timing info](#fetch-params-timing-info "#fetch-params-timing-info").

         - Let networkPartitionKey be the result of
           [determining the network partition key](#request-determine-the-network-partition-key "#request-determine-the-network-partition-key") given request.

           - Let newConnection be "`yes`" if forceNewConnection is true;
             otherwise "`no`".

             - Switch on request’s [mode](#concept-request-mode "#concept-request-mode"):

               "`websocket`": Let connection be the result of [obtaining a WebSocket connection](https://websockets.spec.whatwg.org/#concept-websocket-connection-obtain "https://websockets.spec.whatwg.org/#concept-websocket-connection-obtain"), given request’s [current URL](#concept-request-current-url "#concept-request-current-url"). "`webtransport`": Let connection be the result of [obtaining a WebTransport connection](https://w3c.github.io/webtransport/#obtain-a-webtransport-connection "https://w3c.github.io/webtransport/#obtain-a-webtransport-connection"), given networkPartitionKey and request. Otherwise: Let connection be the result of [obtaining a connection](#concept-connection-obtain "#concept-connection-obtain"), given networkPartitionKey, request’s [current URL](#concept-request-current-url "#concept-request-current-url"), includeCredentials, and newConnection.

               - Run these steps, but [abort when](https://infra.spec.whatwg.org/#abort-when "https://infra.spec.whatwg.org/#abort-when") fetchParams is
                 [canceled](#fetch-params-canceled "#fetch-params-canceled"):

                 1. If connection is failure, then return a [network error](#concept-network-error "#concept-network-error").

                    - Set timingInfo’s [final connection timing info](#fetch-timing-info-final-connection-timing-info "#fetch-timing-info-final-connection-timing-info") to
                      the result of calling [clamp and coarsen connection timing info](#clamp-and-coarsen-connection-timing-info "#clamp-and-coarsen-connection-timing-info") with
                      connection’s [timing info](#concept-connection-timing-info "#concept-connection-timing-info"), timingInfo’s
                      [post-redirect start time](#fetch-timing-info-post-redirect-start-time "#fetch-timing-info-post-redirect-start-time"), and fetchParams’s
                      [cross-origin isolated capability](#fetch-params-cross-origin-isolated-capability "#fetch-params-cross-origin-isolated-capability").

                      - If connection is an HTTP/1.x connection, request’s
                        [body](#concept-request-body "#concept-request-body") is non-null, and request’s [body](#concept-request-body "#concept-request-body")’s
                        [source](#concept-body-source "#concept-body-source") is null, then return a [network error](#concept-network-error "#concept-network-error").

                        - Set timingInfo’s [final network-request start time](#fetch-timing-info-final-network-request-start-time "#fetch-timing-info-final-network-request-start-time")
                          to the [coarsened shared current time](https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time "https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time") given fetchParams’s
                          [cross-origin isolated capability](#fetch-params-cross-origin-isolated-capability "#fetch-params-cross-origin-isolated-capability").- Set response to the result of making an HTTP request over connection
                            using request with the following caveats:

                            * Follow the relevant requirements from HTTP. [[HTTP]](#biblio-http "HTTP Semantics") [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

                              * If request’s [body](#concept-request-body "#concept-request-body") is non-null, and request’s
                                [body](#concept-request-body "#concept-request-body")’s [source](#concept-body-source "#concept-body-source") is null, then the user agent may have a
                                buffer of up to 64 kibibytes and store a part of request’s [body](#concept-request-body "#concept-request-body")
                                in that buffer. If the user agent reads from request’s [body](#concept-request-body "#concept-request-body")
                                beyond that buffer’s size and the user agent needs to resend request, then instead
                                return a [network error](#concept-network-error "#concept-network-error").

                                The resending is needed when the connection is timed out, for example.

                                The buffer is not needed when request’s [body](#concept-request-body "#concept-request-body")’s
                                [source](#concept-body-source "#concept-body-source") is non-null, because request’s [body](#concept-request-body "#concept-request-body") can
                                be recreated from it.

                                When request’s [body](#concept-request-body "#concept-request-body")’s [source](#concept-body-source "#concept-body-source") is null, it
                                means [body](#concept-request-body "#concept-request-body") is created from a `ReadableStream` object, which means
                                [body](#concept-request-body "#concept-request-body") cannot be recreated and that is why the buffer is needed.

                                * While true:

                                  1. Set timingInfo’s
                                     [final network-response start time](#fetch-timing-info-final-network-response-start-time "#fetch-timing-info-final-network-response-start-time") to the
                                     [coarsened shared current time](https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time "https://w3c.github.io/hr-time/#dfn-coarsened-shared-current-time") given fetchParams’s
                                     [cross-origin isolated capability](#fetch-params-cross-origin-isolated-capability "#fetch-params-cross-origin-isolated-capability"), immediately after the user
                                     agent’s HTTP parser receives the first byte of the response (e.g., frame header bytes for
                                     HTTP/2 or response status line for HTTP/1.x).

                                     * Wait until all the HTTP response headers are transmitted.

                                       * Run the [WebDriver BiDi response started](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-started "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-response-started") steps with
                                         request and response.

                                         * Let status be the HTTP response’s status code.

                                           * If status is in the range 100 to 199, inclusive:

                                             1. If timingInfo’s
                                                [first interim network-response start time](#fetch-timing-info-first-interim-network-response-start-time "#fetch-timing-info-first-interim-network-response-start-time") is 0, then set
                                                timingInfo’s
                                                [first interim network-response start time](#fetch-timing-info-first-interim-network-response-start-time "#fetch-timing-info-first-interim-network-response-start-time") to
                                                timingInfo’s [final network-response start time](#fetch-timing-info-final-network-response-start-time "#fetch-timing-info-final-network-response-start-time").

                                                * If request’s [mode](#concept-request-mode "#concept-request-mode") is "`websocket`" and
                                                  status is 101, then [break](https://infra.spec.whatwg.org/#iteration-break "https://infra.spec.whatwg.org/#iteration-break").

                                                  * If status is 103 and fetchParams’s
                                                    [process early hints response](#fetch-params-process-early-hints-response "#fetch-params-process-early-hints-response") is non-null, then
                                                    [queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") to run fetchParams’s
                                                    [process early hints response](#fetch-params-process-early-hints-response "#fetch-params-process-early-hints-response"), with [response](#concept-response "#concept-response").

                                                    * [Continue](https://infra.spec.whatwg.org/#iteration-continue "https://infra.spec.whatwg.org/#iteration-continue").

                                             These kind of HTTP responses are eventually followed by a "final" HTTP
                                             response.

                                             * [Break](https://infra.spec.whatwg.org/#iteration-break "https://infra.spec.whatwg.org/#iteration-break").

                            The exact layering between Fetch and HTTP still needs to be sorted through and
                            therefore response represents both a [response](#concept-response "#concept-response") and
                            an HTTP response here.

                            If the HTTP request results in a TLS client certificate dialog, then:

                            1. If request’s [traversable for user prompts](#concept-request-window "#concept-request-window") is a
                               [traversable navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#traversable-navigable"), then make the dialog available in request’s
                               [traversable for user prompts](#concept-request-window "#concept-request-window").

                               - Otherwise, return a [network error](#concept-network-error "#concept-network-error").

                            To transmit request’s [body](#concept-request-body "#concept-request-body") body, run these steps:

                            1. If body is null and fetchParams’s
                               [process request end-of-body](#fetch-params-process-request-end-of-body "#fetch-params-process-request-end-of-body") is non-null, then
                               [queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") given fetchParams’s
                               [process request end-of-body](#fetch-params-process-request-end-of-body "#fetch-params-process-request-end-of-body") and fetchParams’s
                               [task destination](#fetch-params-task-destination "#fetch-params-task-destination").

                               - Otherwise, if body is non-null:

                                 1. Let processBodyChunk given bytes be these steps:

                                    1. If fetchParams is [canceled](#fetch-params-canceled "#fetch-params-canceled"), then abort these
                                       steps.

                                       - Run this step [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel"): transmit bytes.

                                         - If fetchParams’s
                                           [process request body chunk length](#fetch-params-process-request-body "#fetch-params-process-request-body") is non-null, then run
                                           fetchParams’s [process request body chunk length](#fetch-params-process-request-body "#fetch-params-process-request-body") given
                                           bytes’s [length](https://infra.spec.whatwg.org/#byte-sequence-length "https://infra.spec.whatwg.org/#byte-sequence-length").- Let processEndOfBody be these steps:

                                      1. If fetchParams is [canceled](#fetch-params-canceled "#fetch-params-canceled"), then abort these
                                         steps.

                                         - If fetchParams’s [process request end-of-body](#fetch-params-process-request-end-of-body "#fetch-params-process-request-end-of-body") is
                                           non-null, then run fetchParams’s
                                           [process request end-of-body](#fetch-params-process-request-end-of-body "#fetch-params-process-request-end-of-body").- Let processBodyError given e be these steps:

                                        1. If fetchParams is [canceled](#fetch-params-canceled "#fetch-params-canceled"), then abort these
                                           steps.

                                           - If e is an "`AbortError`" `DOMException`,
                                             then [abort](#fetch-controller-abort "#fetch-controller-abort") fetchParams’s
                                             [controller](#fetch-params-controller "#fetch-params-controller").

                                             - Otherwise, [terminate](#fetch-controller-terminate "#fetch-controller-terminate") fetchParams’s
                                               [controller](#fetch-params-controller "#fetch-params-controller").- [Incrementally read](#body-incrementally-read "#body-incrementally-read") request’s [body](#concept-request-body "#concept-request-body") given
                                          processBodyChunk, processEndOfBody, processBodyError, and
                                          fetchParams’s [task destination](#fetch-params-task-destination "#fetch-params-task-destination").- [If aborted](https://infra.spec.whatwg.org/#if-aborted "https://infra.spec.whatwg.org/#if-aborted"), then:

                   1. If connection uses HTTP/2, then transmit an `RST_STREAM` frame.

                      - Return the [appropriate network error](#appropriate-network-error "#appropriate-network-error") for fetchParams.- Let buffer be an empty [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence").

                     This represents an internal buffer inside the network layer of the user agent.

                     - Let stream be a [new](https://webidl.spec.whatwg.org/#new "https://webidl.spec.whatwg.org/#new") `ReadableStream`.

                       - Let pullAlgorithm be the following steps:

                         1. Let promise be [a new promise](https://webidl.spec.whatwg.org/#a-new-promise "https://webidl.spec.whatwg.org/#a-new-promise").

                            - Run the following steps [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel"):

                              1. If the size of buffer is smaller than a lower limit chosen by the user agent and the
                                 ongoing fetch is [suspended](#concept-fetch-suspend "#concept-fetch-suspend"), [resume](#concept-fetch-resume "#concept-fetch-resume") the fetch.

                                 - Wait until buffer is not empty.

                                   - [Queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task") to run the following steps, with fetchParams’s
                                     [task destination](#fetch-params-task-destination "#fetch-params-task-destination").

                                     1. [Pull from bytes](https://streams.spec.whatwg.org/#readablestream-pull-from-bytes "https://streams.spec.whatwg.org/#readablestream-pull-from-bytes") buffer into stream.

                                        - If stream is [errored](https://streams.spec.whatwg.org/#readablestream-errored "https://streams.spec.whatwg.org/#readablestream-errored"), then [terminate](#fetch-controller-terminate "#fetch-controller-terminate")
                                          fetchParams’s [controller](#fetch-params-controller "#fetch-params-controller").

                                          - [Resolve](https://webidl.spec.whatwg.org/#resolve "https://webidl.spec.whatwg.org/#resolve") promise with undefined.- Return promise.- Let cancelAlgorithm be an algorithm that [aborts](#fetch-controller-abort "#fetch-controller-abort")
                           fetchParams’s [controller](#fetch-params-controller "#fetch-params-controller") with reason, given
                           reason.

                           - [Set up](https://streams.spec.whatwg.org/#readablestream-set-up-with-byte-reading-support "https://streams.spec.whatwg.org/#readablestream-set-up-with-byte-reading-support") stream with byte reading
                             support with [pullAlgorithm](https://streams.spec.whatwg.org/#readablestream-set-up-pullalgorithm "https://streams.spec.whatwg.org/#readablestream-set-up-pullalgorithm") set to pullAlgorithm,
                             [cancelAlgorithm](https://streams.spec.whatwg.org/#readablestream-set-up-cancelalgorithm "https://streams.spec.whatwg.org/#readablestream-set-up-cancelalgorithm") set to cancelAlgorithm.

                             - Set response’s [body](#concept-response-body "#concept-response-body") to a new [body](#concept-body "#concept-body") whose
                               [stream](#concept-body-stream "#concept-body-stream") is stream.

                               - Run the [WebDriver BiDi clone network response body](https://w3c.github.io/webdriver-bidi/#webdriver-bidi-clone-network-response-body "https://w3c.github.io/webdriver-bidi/#webdriver-bidi-clone-network-response-body") steps with request and response.

                                 - [![(This is a tracking vector.)](https://resources.whatwg.org/tracking-vector.svg "There is a tracking vector here.")](https://infra.spec.whatwg.org/#tracking-vector "https://infra.spec.whatwg.org/#tracking-vector") If includeCredentials is true, then the user agent should
                                   [parse and store response ``Set-Cookie`` headers](#parse-and-store-response-set-cookie-headers "#parse-and-store-response-set-cookie-headers") given request and
                                   response.

                                   - Run these steps [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel"):

                                     1. Run these steps, but [abort when](https://infra.spec.whatwg.org/#abort-when "https://infra.spec.whatwg.org/#abort-when") fetchParams is
                                        [canceled](#fetch-params-canceled "#fetch-params-canceled"):

                                        1. While true:

                                           1. If one or more bytes have been transmitted from response’s message body, then:

                                              1. Let bytes be the transmitted bytes.

                                                 - Let codings be the result of [extracting header list values](#extract-header-list-values "#extract-header-list-values") given
                                                   ``Content-Encoding`` and response’s [header list](#concept-response-header-list "#concept-response-header-list").

                                                   - Let filteredCoding be "`@unknown`".

                                                     - If codings is null or failure, then set filteredCoding to
                                                       the empty string.

                                                       - Otherwise, if codings’s [size](https://infra.spec.whatwg.org/#list-size "https://infra.spec.whatwg.org/#list-size") is greater than 1, then set
                                                         filteredCoding to "`multiple`".

                                                         - Otherwise, if codings[0] is the empty string, or it is supported by the
                                                           user agent, and is a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for an entry listed in the
                                                           HTTP Content Coding Registry, then set filteredCoding to the result
                                                           of [byte-lowercasing](https://infra.spec.whatwg.org/#byte-lowercase "https://infra.spec.whatwg.org/#byte-lowercase") codings[0]. [[IANA-HTTP-PARAMS]](#biblio-iana-http-params "Hypertext Transfer Protocol (HTTP) Parameters")

                                                           - Set response’s [body info](#concept-response-body-info "#concept-response-body-info")’s
                                                             [content encoding](#response-body-info-content-encoding "#response-body-info-content-encoding") to filteredCoding.

                                                             - Increase response’s [body info](#concept-response-body-info "#concept-response-body-info")’s
                                                               [encoded size](#fetch-timing-info-encoded-body-size "#fetch-timing-info-encoded-body-size") by bytes’s
                                                               [length](https://infra.spec.whatwg.org/#byte-sequence-length "https://infra.spec.whatwg.org/#byte-sequence-length").

                                                               - Set bytes to the result of [handling content
                                                                 codings](#handle-content-codings "#handle-content-codings") given codings and bytes.

                                                                 This makes the ``Content-Length`` [header](#concept-header "#concept-header") unreliable
                                                                 to the extent that it was reliable to begin with.

                                                                 - Increase response’s [body info](#concept-response-body-info "#concept-response-body-info")’s
                                                                   [decoded size](#fetch-timing-info-decoded-body-size "#fetch-timing-info-decoded-body-size") by
                                                                   bytes’s [length](https://infra.spec.whatwg.org/#byte-sequence-length "https://infra.spec.whatwg.org/#byte-sequence-length").

                                                                   - If bytes is failure, then [terminate](#fetch-controller-terminate "#fetch-controller-terminate")
                                                                     fetchParams’s [controller](#fetch-params-controller "#fetch-params-controller").

                                                                     - Append bytes to buffer.

                                                                       - If the size of buffer is larger than an upper limit chosen by the user agent, ask
                                                                         the user agent to [suspend](#concept-fetch-suspend "#concept-fetch-suspend") the ongoing fetch.- Otherwise, if the bytes transmission for response’s message body is done
                                                normally and stream is [readable](https://streams.spec.whatwg.org/#readablestream-readable "https://streams.spec.whatwg.org/#readablestream-readable"), then
                                                [close](https://streams.spec.whatwg.org/#readablestream-close "https://streams.spec.whatwg.org/#readablestream-close") stream, and abort these in-parallel steps.- [If aborted](https://infra.spec.whatwg.org/#if-aborted "https://infra.spec.whatwg.org/#if-aborted"), then:

                                          1. If fetchParams is [aborted](#fetch-params-aborted "#fetch-params-aborted"), then:

                                             1. Set response’s [aborted flag](#concept-response-aborted "#concept-response-aborted").

                                                - If stream is [readable](https://streams.spec.whatwg.org/#readablestream-readable "https://streams.spec.whatwg.org/#readablestream-readable"), then
                                                  [error](https://streams.spec.whatwg.org/#readablestream-error "https://streams.spec.whatwg.org/#readablestream-error") stream with the result of
                                                  [deserialize a serialized abort reason](#deserialize-a-serialized-abort-reason "#deserialize-a-serialized-abort-reason") given fetchParams’s
                                                  [controller](#fetch-params-controller "#fetch-params-controller")’s [serialized abort reason](#fetch-controller-serialized-abort-reason "#fetch-controller-serialized-abort-reason")
                                                  and an [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined") [realm](https://tc39.es/ecma262/#realm "https://tc39.es/ecma262/#realm").- Otherwise, if stream is [readable](https://streams.spec.whatwg.org/#readablestream-readable "https://streams.spec.whatwg.org/#readablestream-readable"),
                                               [error](https://streams.spec.whatwg.org/#readablestream-error "https://streams.spec.whatwg.org/#readablestream-error") stream with a `TypeError`.

                                               - If connection uses HTTP/2, then transmit an `RST_STREAM` frame.

                                                 - Otherwise, the user agent should close connection unless it would be bad for
                                                   performance to do so.

                                                   For instance, the user agent could keep the connection open if it knows there’s
                                                   only a few bytes of transfer remaining on a reusable connection. In this case it could be
                                                   worse to close the connection and go through the handshake process again for the next fetch.

                                     These are run [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel") as at this point it is unclear whether
                                     response’s [body](#concept-response-body "#concept-response-body") is relevant (response might be a
                                     redirect).

                                     - Return response. Typically response’s
                                       [body](#concept-response-body "#concept-response-body")’s [stream](#concept-body-stream "#concept-body-stream") is still being enqueued to after
                                       returning.

### 4.8. CORS-preflight fetch

This is effectively the user agent implementation of the check to see if the
[CORS protocol](#cors-protocol "#cors-protocol") is understood. The so-called [CORS-preflight request](#cors-preflight-request "#cors-preflight-request"). If successful it
populates the [CORS-preflight cache](#concept-cache "#concept-cache") to minimize the number of these
[fetches](#cors-preflight-fetch-0 "#cors-preflight-fetch-0").

To CORS-preflight fetch, given a [request](#concept-request "#concept-request")
request, run these steps:

1. Let preflight be a new [request](#concept-request "#concept-request") whose
   [method](#concept-request-method "#concept-request-method") is ``OPTIONS``,
   [URL list](#concept-request-url-list "#concept-request-url-list") is a [clone](https://infra.spec.whatwg.org/#list-clone "https://infra.spec.whatwg.org/#list-clone") of request’s
   [URL list](#concept-request-url-list "#concept-request-url-list"),
   [initiator](#concept-request-initiator "#concept-request-initiator") is request’s [initiator](#concept-request-initiator "#concept-request-initiator"),
   [destination](#concept-request-destination "#concept-request-destination") is request’s [destination](#concept-request-destination "#concept-request-destination"),
   [origin](#concept-request-origin "#concept-request-origin") is request’s [origin](#concept-request-origin "#concept-request-origin"),
   [referrer](#concept-request-referrer "#concept-request-referrer") is request’s [referrer](#concept-request-referrer "#concept-request-referrer"),
   [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy") is request’s [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy"),
   [mode](#concept-request-mode "#concept-request-mode") is "`cors`",
   [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is "`cors`", and
   [WebDriver id](#concept-webdriver-id "#concept-webdriver-id") is request’s [WebDriver id](#concept-webdriver-id "#concept-webdriver-id").

   The [service-workers mode](#request-service-workers-mode "#request-service-workers-mode") of preflight does not matter
   as this algorithm uses [HTTP-network-or-cache fetch](#concept-http-network-or-cache-fetch "#concept-http-network-or-cache-fetch") rather than [HTTP fetch](#concept-http-fetch "#concept-http-fetch").

   - [Append](#concept-header-list-append "#concept-header-list-append") (``Accept``, ``*/*``) to
     preflight’s [header list](#concept-request-header-list "#concept-request-header-list").

     - [Append](#concept-header-list-append "#concept-header-list-append")
       (`[`Access-Control-Request-Method`](#http-access-control-request-method "#http-access-control-request-method")`, request’s
       [method](#concept-request-method "#concept-request-method")) to preflight’s [header list](#concept-request-header-list "#concept-request-header-list").

       - Let headers be the [CORS-unsafe request-header names](#cors-unsafe-request-header-names "#cors-unsafe-request-header-names") with
         request’s [header list](#concept-request-header-list "#concept-request-header-list").

         - If headers [is not empty](https://infra.spec.whatwg.org/#list-is-empty "https://infra.spec.whatwg.org/#list-is-empty"), then:

           1. Let value be the items in headers separated from each other by
              ``,``.

              - [Append](#concept-header-list-append "#concept-header-list-append")
                (`[`Access-Control-Request-Headers`](#http-access-control-request-headers "#http-access-control-request-headers")`, value) to
                preflight’s [header list](#concept-request-header-list "#concept-request-header-list").

           This intentionally does not use [combine](#concept-header-list-combine "#concept-header-list-combine"), as 0x20 following
           0x2C is not the way this was implemented, for better or worse.

           - Let response be the result of running [HTTP-network-or-cache fetch](#concept-http-network-or-cache-fetch "#concept-http-network-or-cache-fetch") given
             a new [fetch params](#fetch-params "#fetch-params") whose [request](#fetch-params-request "#fetch-params-request") is preflight.

             - If a [CORS check](#concept-cors-check "#concept-cors-check") for request and response returns success and
               response’s [status](#concept-response-status "#concept-response-status") is an [ok status](#ok-status "#ok-status"), then:

               The [CORS check](#concept-cors-check "#concept-cors-check") is done on request rather than preflight
               to ensure the correct [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is used.

               1. Let methods be the result of [extracting header list values](#extract-header-list-values "#extract-header-list-values") given
                  `[`Access-Control-Allow-Methods`](#http-access-control-allow-methods "#http-access-control-allow-methods")` and response’s
                  [header list](#concept-response-header-list "#concept-response-header-list").

                  - Let headerNames be the result of [extracting header list values](#extract-header-list-values "#extract-header-list-values") given
                    `[`Access-Control-Allow-Headers`](#http-access-control-allow-headers "#http-access-control-allow-headers")` and response’s
                    [header list](#concept-response-header-list "#concept-response-header-list").

                    - If either methods or headerNames is failure,
                      return a [network error](#concept-network-error "#concept-network-error").

                      - If methods is null and request’s [use-CORS-preflight flag](#use-cors-preflight-flag "#use-cors-preflight-flag")
                        is set, then set methods to a new list containing request’s
                        [method](#concept-request-method "#concept-request-method").

                        This ensures that a [CORS-preflight fetch](#cors-preflight-fetch-0 "#cors-preflight-fetch-0") that happened due to
                        request’s [use-CORS-preflight flag](#use-cors-preflight-flag "#use-cors-preflight-flag") being set is
                        [cached](#concept-cache "#concept-cache").

                        - If request’s [method](#concept-request-method "#concept-request-method") is not in methods,
                          request’s [method](#concept-request-method "#concept-request-method") is not a [CORS-safelisted method](#cors-safelisted-method "#cors-safelisted-method"), and
                          request’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is "`include`" or
                          methods does not contain ``*``, then return a [network error](#concept-network-error "#concept-network-error").

                          - If one of request’s [header list](#concept-request-header-list "#concept-request-header-list")’s
                            [names](#concept-header-name "#concept-header-name") is a [CORS non-wildcard request-header name](#cors-non-wildcard-request-header-name "#cors-non-wildcard-request-header-name") and is not a
                            [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for an [item](https://infra.spec.whatwg.org/#list-item "https://infra.spec.whatwg.org/#list-item") in headerNames, then
                            return a [network error](#concept-network-error "#concept-network-error").

                            - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") unsafeName of the
                              [CORS-unsafe request-header names](#cors-unsafe-request-header-names "#cors-unsafe-request-header-names") with request’s
                              [header list](#concept-request-header-list "#concept-request-header-list"), if unsafeName is not a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive")
                              match for an [item](https://infra.spec.whatwg.org/#list-item "https://infra.spec.whatwg.org/#list-item") in headerNames and request’s
                              [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is "`include`" or headerNames does not
                              contain ``*``, return a [network error](#concept-network-error "#concept-network-error").

                              - Let max-age be the result of [extracting header list values](#extract-header-list-values "#extract-header-list-values") given
                                `[`Access-Control-Max-Age`](#http-access-control-max-age "#http-access-control-max-age")` and response’s
                                [header list](#concept-response-header-list "#concept-response-header-list").

                                - If max-age is failure or null, then set max-age to 5.

                                  - If max-age is greater than an imposed limit on
                                    [max-age](#concept-cache-max-age "#concept-cache-max-age"), then set max-age to the imposed limit.

                                    - If the user agent does not provide for a [cache](#concept-cache "#concept-cache"), then
                                      return response.

                                      - For each method in methods for which there is a
                                        [method cache entry match](#concept-cache-match-method "#concept-cache-match-method") using request, set matching entry’s
                                        [max-age](#concept-cache-max-age "#concept-cache-max-age") to max-age.

                                        - For each method in methods for which there is no
                                          [method cache entry match](#concept-cache-match-method "#concept-cache-match-method") using request, [create a new cache entry](#concept-cache-create-entry "#concept-cache-create-entry") with
                                          request, max-age, method, and null.

                                          - For each headerName in headerNames for which there is a
                                            [header-name cache entry match](#concept-cache-match-header "#concept-cache-match-header") using request, set matching entry’s
                                            [max-age](#concept-cache-max-age "#concept-cache-max-age") to max-age.

                                            - For each headerName in headerNames for which there is no
                                              [header-name cache entry match](#concept-cache-match-header "#concept-cache-match-header") using request, [create a new cache entry](#concept-cache-create-entry "#concept-cache-create-entry")
                                              with request, max-age, null, and headerName.

                                              - Return response.- Otherwise, return a [network error](#concept-network-error "#concept-network-error").

### 4.9. CORS-preflight cache

A user agent has an associated [CORS-preflight cache](#concept-cache "#concept-cache"). A
CORS-preflight cache is a [list](https://infra.spec.whatwg.org/#list "https://infra.spec.whatwg.org/#list") of [cache entries](#cache-entry "#cache-entry").

A cache entry consists of:

* key (a [network partition key](#network-partition-key "#network-partition-key"))* byte-serialized origin (a
    [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"))* URL (a [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url"))* max-age (a number of seconds)* credentials (a boolean)* method (null, ``*``, or a
            [method](#concept-method "#concept-method"))* header name (null, ``*``,
              or a [header name](#header-name "#header-name"))

[Cache entries](#cache-entry "#cache-entry") must be removed after the seconds specified in their
[max-age](#concept-cache-max-age "#concept-cache-max-age") field have passed since storing the entry. [Cache entries](#cache-entry "#cache-entry") may
be removed before that moment arrives.

To create a new cache entry, given request,
max-age, method, and headerName, run these steps:

1. Let entry be a [cache entry](#cache-entry "#cache-entry"), initialized as follows:

   [key](#concept-cache-key "#concept-cache-key"): The result of [determining the network partition key](#request-determine-the-network-partition-key "#request-determine-the-network-partition-key") given request [byte-serialized origin](#concept-cache-origin "#concept-cache-origin"): The result of [byte-serializing a request origin](#byte-serializing-a-request-origin "#byte-serializing-a-request-origin") with request [URL](#concept-cache-url "#concept-cache-url"): request’s [current URL](#concept-request-current-url "#concept-request-current-url") [max-age](#concept-cache-max-age "#concept-cache-max-age"): max-age [credentials](#concept-cache-credentials "#concept-cache-credentials"): True if request’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is "`include`", and false otherwise [method](#concept-cache-method "#concept-cache-method"): method [header name](#concept-cache-header-name "#concept-cache-header-name"): headerName

   - [Append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") entry to the user agent’s [CORS-preflight cache](#concept-cache "#concept-cache").

To clear cache entries, given a request,
[remove](https://infra.spec.whatwg.org/#list-remove "https://infra.spec.whatwg.org/#list-remove") any [cache entries](#cache-entry "#cache-entry") in the user agent’s [CORS-preflight cache](#concept-cache "#concept-cache")
whose [key](#concept-cache-key "#concept-cache-key") is the result of
[determining the network partition key](#request-determine-the-network-partition-key "#request-determine-the-network-partition-key") given request,
[byte-serialized origin](#concept-cache-origin "#concept-cache-origin") is the result of
[byte-serializing a request origin](#byte-serializing-a-request-origin "#byte-serializing-a-request-origin") with request, and [URL](#concept-cache-url "#concept-cache-url")
is request’s [current URL](#concept-request-current-url "#concept-request-current-url").

There is a cache entry match for a [cache entry](#cache-entry "#cache-entry")
entry with request if entry’s [key](#concept-cache-key "#concept-cache-key") is the
result of [determining the network partition key](#request-determine-the-network-partition-key "#request-determine-the-network-partition-key") given request,
entry’s [byte-serialized origin](#concept-cache-origin "#concept-cache-origin") is the result of
[byte-serializing a request origin](#byte-serializing-a-request-origin "#byte-serializing-a-request-origin") with request, entry’s
[URL](#concept-cache-url "#concept-cache-url") is request’s [current URL](#concept-request-current-url "#concept-request-current-url"), and one of

* entry’s [credentials](#concept-cache-credentials "#concept-cache-credentials") is true* entry’s [credentials](#concept-cache-credentials "#concept-cache-credentials") is false and request’s
    [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is not "`include`".

is true.

There is a method cache entry match for
method using request when there is a [cache entry](#cache-entry "#cache-entry") in the user agent’s
[CORS-preflight cache](#concept-cache "#concept-cache") for which there is a [cache entry match](#concept-cache-match "#concept-cache-match") with request
and its [method](#concept-cache-method "#concept-cache-method") is method or ``*``.

There is a header-name cache entry match for
headerName using request when there is a [cache entry](#cache-entry "#cache-entry") in the user
agent’s [CORS-preflight cache](#concept-cache "#concept-cache") for which there is a [cache entry match](#concept-cache-match "#concept-cache-match") with
request and one of

* its [header name](#concept-cache-header-name "#concept-cache-header-name") is a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match for
  headerName* its [header name](#concept-cache-header-name "#concept-cache-header-name") is ``*`` and headerName is not
    a [CORS non-wildcard request-header name](#cors-non-wildcard-request-header-name "#cors-non-wildcard-request-header-name")

is true.

### 4.10. CORS check

To perform a CORS check for a request and
response, run these steps:

1. Let origin be the result of [getting](#concept-header-list-get "#concept-header-list-get")
   `[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` from response’s
   [header list](#concept-response-header-list "#concept-response-header-list").

   - If origin is null, then return failure.

     Null is not ``null``.

     - If request’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is not "`include`"
       and origin is ``*``, then return success.

       - If the result of [byte-serializing a request origin](#byte-serializing-a-request-origin "#byte-serializing-a-request-origin") with request is not
         origin, then return failure.

         - If request’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") is not "`include`",
           then return success.

           - Let credentials be the result of [getting](#concept-header-list-get "#concept-header-list-get")
             `[`Access-Control-Allow-Credentials`](#http-access-control-allow-credentials "#http-access-control-allow-credentials")` from response’s
             [header list](#concept-response-header-list "#concept-response-header-list").

             - If credentials is ``true``, then return success.

               - Return failure.

### 4.11. TAO check

To perform a TAO check for a request and
response, run these steps:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): request’s [origin](#concept-request-origin "#concept-request-origin") is not
   "`client`".

   - If request’s [timing allow failed flag](#timing-allow-failed "#timing-allow-failed") is set, then return
     failure.

     - Let values be the result of
       [getting, decoding, and splitting](#concept-header-list-get-decode-split "#concept-header-list-get-decode-split") ``Timing-Allow-Origin`` from
       response’s [header list](#concept-response-header-list "#concept-response-header-list").

       - If values [contains](https://infra.spec.whatwg.org/#list-contain "https://infra.spec.whatwg.org/#list-contain") "`*`", then return success.

         - If values [contains](https://infra.spec.whatwg.org/#list-contain "https://infra.spec.whatwg.org/#list-contain") the result of
           [serializing a request origin](#serializing-a-request-origin "#serializing-a-request-origin") with request, then return success.

           - If request’s [mode](#concept-request-mode "#concept-request-mode") is "`navigate`" and
             request’s [current URL](#concept-request-current-url "#concept-request-current-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") is not
             [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with request’s [origin](#concept-request-origin "#concept-request-origin"), then return failure.

             This is necessary for navigations of a nested navigable. There,
             request’s [origin](#concept-request-origin "#concept-request-origin") would be the container document’s
             [origin](https://dom.spec.whatwg.org/#concept-document-origin "https://dom.spec.whatwg.org/#concept-document-origin") and the [TAO check](#concept-tao-check "#concept-tao-check") would return failure. Since navigation timing
             never validates the results of the [TAO check](#concept-tao-check "#concept-tao-check"), the nested document would still have access
             to the full timing information, but the container document would not.

             - If request’s [response tainting](#concept-request-response-tainting "#concept-request-response-tainting") is "`basic`", then
               return success.

               - Return failure.

### 4.12. Deferred fetching

Deferred fetching allows callers to request that a fetch is invoked at the latest possible
moment, i.e., when a [fetch group](#concept-fetch-group "#concept-fetch-group") is [terminated](#concept-fetch-group-terminate "#concept-fetch-group-terminate"), or after a
timeout.

The deferred fetch task source is a [task source](https://html.spec.whatwg.org/multipage/webappapis.html#task-source "https://html.spec.whatwg.org/multipage/webappapis.html#task-source") used to update the result of a
deferred fetch. User agents must prioritize tasks in this [task source](https://html.spec.whatwg.org/multipage/webappapis.html#task-source "https://html.spec.whatwg.org/multipage/webappapis.html#task-source") before other task
sources, specifically task sources that can result in running scripts such as the
[DOM manipulation task source](https://html.spec.whatwg.org/multipage/webappapis.html#dom-manipulation-task-source "https://html.spec.whatwg.org/multipage/webappapis.html#dom-manipulation-task-source"), to reflect the most recent state of a
[`fetchLater()`](#dom-window-fetchlater "#dom-window-fetchlater") call before running any scripts that might depend on it.

To queue a deferred fetch given a [request](#concept-request "#concept-request") request, a null or
`DOMHighResTimeStamp` activateAfter, and onActivatedWithoutTermination,
which is an algorithm that takes no arguments:

1. [Populate request from client](#populate-request-from-client "#populate-request-from-client") given request.

   - Set request’s [service-workers mode](#request-service-workers-mode "#request-service-workers-mode") to "`none`".

     - Set request’s [keepalive](#request-keepalive-flag "#request-keepalive-flag") to true.

       - Let deferredRecord be a new [deferred fetch record](#deferred-fetch-record "#deferred-fetch-record") whose
         [request](#deferred-fetch-record-request "#deferred-fetch-record-request") is request, and whose
         [notify invoked](#deferred-fetch-record-notify-invoked "#deferred-fetch-record-notify-invoked") is
         onActivatedWithoutTermination.

         - [Append](https://infra.spec.whatwg.org/#list-append "https://infra.spec.whatwg.org/#list-append") deferredRecord to request’s
           [client](#concept-request-client "#concept-request-client")’s [fetch group](#environment-settings-object-fetch-group "#environment-settings-object-fetch-group")’s
           [deferred fetch records](#fetch-group-deferred-fetch-records "#fetch-group-deferred-fetch-records").

           - If activateAfter is non-null, then run the following steps [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel"):

             1. The user agent should wait until any of the following conditions is met:

                * At least activateAfter milliseconds have passed.

                  * The user agent has a reason to believe that it is about to lose the opportunity to
                    execute scripts, e.g., when the browser is moved to the background, or when
                    request’s [client](#concept-request-client "#concept-request-client")’s
                    [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global") is a `Window` object whose
                    [associated document](https://html.spec.whatwg.org/multipage/nav-history-apis.html#concept-document-window "https://html.spec.whatwg.org/multipage/nav-history-apis.html#concept-document-window") had a "`hidden`" [visibility state](https://html.spec.whatwg.org/multipage/interaction.html#visibility-state "https://html.spec.whatwg.org/multipage/interaction.html#visibility-state") for
                    a long period of time.- [Process](#process-a-deferred-fetch "#process-a-deferred-fetch") deferredRecord.- Return deferredRecord.

To compute the total request length of a [request](#concept-request "#concept-request") request:

1. Let totalRequestLength be the [length](https://infra.spec.whatwg.org/#string-length "https://infra.spec.whatwg.org/#string-length") of request’s
   [URL](#concept-request-url "#concept-request-url"), [serialized](https://url.spec.whatwg.org/#concept-url-serializer "https://url.spec.whatwg.org/#concept-url-serializer") with
   [*exclude fragment*](https://url.spec.whatwg.org/#url-serializer-exclude-fragment "https://url.spec.whatwg.org/#url-serializer-exclude-fragment") set to true.

   - Increment totalRequestLength by the [length](https://infra.spec.whatwg.org/#string-length "https://infra.spec.whatwg.org/#string-length") of
     request’s [referrer](#concept-request-referrer "#concept-request-referrer"), [serialized](https://url.spec.whatwg.org/#concept-url-serializer "https://url.spec.whatwg.org/#concept-url-serializer").

     - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") (name, value) of request’s
       [header list](#concept-request-header-list "#concept-request-header-list"), increment totalRequestLength by name’s
       [length](https://infra.spec.whatwg.org/#byte-sequence-length "https://infra.spec.whatwg.org/#byte-sequence-length") + value’s [length](https://infra.spec.whatwg.org/#byte-sequence-length "https://infra.spec.whatwg.org/#byte-sequence-length").

       - Increment totalRequestLength by request’s [body](#concept-request-body "#concept-request-body")’s
         [length](#concept-body-total-bytes "#concept-body-total-bytes").

         - Return totalRequestLength.

To process deferred fetches given a [fetch group](#concept-fetch-group "#concept-fetch-group") fetchGroup:

1. [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") [deferred fetch record](#fetch-group-deferred-fetch-records "#fetch-group-deferred-fetch-records")
   deferredRecord of fetchGroup’s
   [deferred fetch records](#fetch-group-deferred-fetch-records "#fetch-group-deferred-fetch-records"), [process a deferred fetch](#process-a-deferred-fetch "#process-a-deferred-fetch")
   deferredRecord.

To process a deferred fetch deferredRecord:

1. If deferredRecord’s [invoke state](#deferred-fetch-record-invoke-state "#deferred-fetch-record-invoke-state") is not
   "`pending`", then return.

   - Set deferredRecord’s [invoke state](#deferred-fetch-record-invoke-state "#deferred-fetch-record-invoke-state") to
     "`sent`".

     - [Fetch](#concept-fetch "#concept-fetch") deferredRecord’s [request](#deferred-fetch-record-request "#deferred-fetch-record-request").

       - [Queue a global task](https://html.spec.whatwg.org/multipage/webappapis.html#queue-a-global-task "https://html.spec.whatwg.org/multipage/webappapis.html#queue-a-global-task") on the [deferred fetch task source](#deferred-fetch-task-source "#deferred-fetch-task-source") with
         deferredRecord’s [request](#deferred-fetch-record-request "#deferred-fetch-record-request")’s
         [client](#concept-request-client "#concept-request-client")’s [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global") to run
         deferredRecord’s [notify invoked](#deferred-fetch-record-notify-invoked "#deferred-fetch-record-notify-invoked").

#### 4.12.1. Deferred fetching quota

*This section is non-normative.*

The deferred-fetch quota is allocated to a [top-level traversable](https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable "https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable") (a "tab"),
amounting to 640 kibibytes. The top-level document and its same-origin directly nested documents can
use this quota to queue deferred fetches, or delegate some of it to cross-origin nested documents,
using permissions policy.

By default, 128 kibibytes out of these 640 kibibytes are allocated to delegating the quota to
cross-origin nested documents, each reserving 8 kibibytes.

The top-level [document](https://dom.spec.whatwg.org/#concept-document "https://dom.spec.whatwg.org/#concept-document"), and subsequently its nested documents, can control how much
of their quota is delegates to cross-origin child documents, using permissions policy. By default,
the "`deferred-fetch-minimal`" policy is enabled for any origin, while
"`deferred-fetch`" is enabled for the top-level document’s origin only. By
relaxing the "`deferred-fetch`" policy for particular origins and nested
documents, the top-level document can allocate 64 kibibytes to those nested documents. Similarly, by
restricting the "`deferred-fetch-minimal`" policy for a particular origin or
nested document, the document can prevent the document from reserving the 8 kibibytes it would
receive by default. By disabling the "`deferred-fetch-minimal`" policy for the
top-level document itself, the entire 128 kibibytes delegated quota is collected back into the main
pool of 640 kibibytes.

Out of the allocated quota for a [document](https://dom.spec.whatwg.org/#concept-document "https://dom.spec.whatwg.org/#concept-document"), only 64 kibibytes can be used
concurrently for the same reporting origin (the [request](#concept-request "#concept-request")’s [URL](#concept-request-url "#concept-request-url")’s
[origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin")). This prevents a situation where particular third-party libraries would reserve
quota opportunistically, before they have data to send.

Any of the following calls to [`fetchLater()`](#dom-window-fetchlater "#dom-window-fetchlater") would throw due to
the request itself exceeding the 64 kibibytes quota allocated to a reporting origin. Note that the
size of the request includes the [URL](#concept-request-url "#concept-request-url") itself, the [body](#concept-request-body "#concept-request-body"), the
[header list](#concept-request-header-list "#concept-request-header-list"), and the [referrer](#concept-request-referrer "#concept-request-referrer").

```
fetchLater(a_72_kb_url);
fetchLater("https://origin.example.com", {headers: headers_exceeding_64kb});
fetchLater(a_32_kb_url, {headers: headers_exceeding_32kb});
fetchLater("https://origin.example.com", {method: "POST", body: body_exceeding_64_kb});
fetchLater(a_62_kb_url /* with a 3kb referrer */);
```

In the following sequence, the first two requests would succeed, but the third one would throw.
That’s because the overall 640 kibibytes quota was not exceeded in the first two calls, however the
3rd request exceeds the reporting-origin quota for `https://a.example.com`, and would
throw.

```
fetchLater("https://a.example.com", {method: "POST", body: a_64kb_body});
fetchLater("https://b.example.com", {method: "POST", body: a_64kb_body});
fetchLater("https://a.example.com");
```

Same-origin nested documents share the quota of their parent. However, cross-origin or
cross-agent iframes only receive 8kb of quota by default. So in the following example, the first
three calls would succeed and the last one would throw.

```
// In main page
fetchLater("https://a.example.com", {method: "POST", body: a_64kb_body});

// In same-origin nested document
fetchLater("https://b.example.com", {method: "POST", body: a_64kb_body});

// In cross-origin nested document at https://fratop.example.com
fetchLater("https://a.example.com", {body: a_5kb_body});
fetchLater("https://a.example.com", {body: a_12kb_body});
```

To make the previous example not throw, the top-level document can delegate some of its quota
to `https://fratop.example.com`, for example by serving the following header:

```
Permissions-Policy: deferred-fetch=(self "https://fratop.example.com")
```

Each nested document reserves its own quota. So the following would work, because each frame
reserve 8 kibibytes:

```
// In cross-origin nested document at https://fratop.example.com/frame-1
fetchLater("https://a.example.com", {body: a_6kb_body});

// In cross-origin nested document at https://fratop.example.com/frame-2
fetchLater("https://a.example.com", {body: a_6kb_body});
```

The following tree illustrates how quota is distributed to different nested documents in a tree:

* `https://top.example.com`, with permissions policy set to
  `Permissions-policy: deferred-fetch=(self "https://ok.example.com")`

  + `https://top.example.com/frame`: shares quota with the top-level traversable, as
    they are same origin.

    - `https://x.example.com`: receives 8 kibibytes.+ `https://x.example.com`: receives 8 kibibytes.

      - `https://top.example.com`: 0. Even though it’s same origin with the
        top-level traversable, it does not automatically share its quota as they are separated by a
        cross-origin intermediary.+ `https://ok.example.com/good`: receives 64 kibibytes, granted via the
        "`deferred-fetch`" policy.

        - `https://x.example.com`: receives no quota. Only documents with the same
          origin as the top-level traversable can grant the 8 kibibytes based on the
          "`deferred-fetch-minimal`" policy.+ `https://ok.example.com/redirect`, navigated to
          `https://x.example.com`: receives no quota. The reserved 64 kibibytes for
          `https://ok.example.com` are not available for
          `https://x.example.com`.

          + `https://ok.example.com/back`, navigated to
            `https://top.example.com`: shares quota with the top-level traversable, as they’re
            same origin.

In the above example, the [top-level traversable](https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable "https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable") and its [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin")
descendants share a quota of 384 kibibytes. That value is computed as such:

* 640 kibibytes are initially granted to the [top-level traversable](https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable "https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable").

  * 128 kibibytes are reserved for the "`deferred-fetch-minimal`" policy.

    * 64 kibibytes are reserved for the container navigating to
      `https://ok.example/good`.

      * 64 kibibytes are reserved for the container navigating to
        `https://ok.example/redirect`, and lost when it navigates away.

        * `https://ok.example.com/back` did not reserve 64 kibibytes, because it navigated
          back to [top-level traversable](https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable "https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable")’s origin.* 640 − 128 − 64 − 64 = 384 kibibytes.

This specification defines a [policy-controlled feature](https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature "https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature") identified by the string
"`deferred-fetch`". Its
[default allowlist](https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature-default-allowlist "https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature-default-allowlist") is "`self`".

This specification defines a [policy-controlled feature](https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature "https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature") identified by the string
"`deferred-fetch-minimal`". Its
[default allowlist](https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature-default-allowlist "https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature-default-allowlist") is "`*`".

The quota reserved for `deferred-fetch-minimal` is 128 kibibytes.

Each [navigable container](https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container "https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container") has an associated number
reserved deferred-fetch quota. Its possible values are
minimal quota, which is 8 kibibytes, and
normal quota, which is 0 or 64 kibibytes. Unless
stated otherwise, it is 0.

To get the available deferred-fetch quota given a [document](https://dom.spec.whatwg.org/#concept-document "https://dom.spec.whatwg.org/#concept-document")
document and an [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin")-or-null origin:

1. Let controlDocument be document’s
   [deferred-fetch control document](#deferred-fetch-control-document "#deferred-fetch-control-document").

   - Let navigable be controlDocument’s [node navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable").

     - Let isTopLevel be true if controlDocument’s [node navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable") is a
       [top-level traversable](https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable "https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable"); otherwise false.

       - Let deferredFetchAllowed be true if controlDocument is
         [allowed to use](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#allowed-to-use "https://html.spec.whatwg.org/multipage/iframe-embed-object.html#allowed-to-use") the [policy-controlled feature](https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature "https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature")
         "`deferred-fetch`"; otherwise false.

         - Let deferredFetchMinimalAllowed be true if controlDocument is
           [allowed to use](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#allowed-to-use "https://html.spec.whatwg.org/multipage/iframe-embed-object.html#allowed-to-use") the [policy-controlled feature](https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature "https://w3c.github.io/webappsec-permissions-policy/#policy-controlled-feature")
           "`deferred-fetch-minimal`"; otherwise false.

           - Let quota be the result of the first matching statement:

             isTopLevel is true and deferredFetchAllowed is false: 0 isTopLevel is true and deferredFetchMinimalAllowed is false: 640 kibibytes 640kb should be enough for everyone. isTopLevel is true: 512 kibibytes The default of 640 kibibytes, decremented By [quota reserved for `deferred-fetch-minimal`](#quota-reserved-for-deferred-fetch-minimal "#quota-reserved-for-deferred-fetch-minimal")) deferredFetchAllowed is true, and navigable’s [navigable container](https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container "https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container")’s [reserved deferred-fetch quota](#reserved-deferred-fetch-quota "#reserved-deferred-fetch-quota") is [normal quota](#reserved-deferred-fetch-quota-normal-quota "#reserved-deferred-fetch-quota-normal-quota"): [normal quota](#reserved-deferred-fetch-quota-normal-quota "#reserved-deferred-fetch-quota-normal-quota") deferredFetchMinimalAllowed is true, and navigable’s [navigable container](https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container "https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container")’s [reserved deferred-fetch quota](#reserved-deferred-fetch-quota "#reserved-deferred-fetch-quota") is [minimal quota](#reserved-deferred-fetch-quota-minimal-quota "#reserved-deferred-fetch-quota-minimal-quota"): [minimal quota](#reserved-deferred-fetch-quota-minimal-quota "#reserved-deferred-fetch-quota-minimal-quota") Otherwise: 0

             - Let quotaForRequestOrigin be 64 kibibytes.

               - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") navigable in controlDocument’s
                 [node navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable")’s [inclusive descendant navigables](https://html.spec.whatwg.org/multipage/document-sequences.html#inclusive-descendant-navigables "https://html.spec.whatwg.org/multipage/document-sequences.html#inclusive-descendant-navigables") whose
                 [active document](https://html.spec.whatwg.org/multipage/document-sequences.html#nav-document "https://html.spec.whatwg.org/multipage/document-sequences.html#nav-document")’s [deferred-fetch control document](#deferred-fetch-control-document "#deferred-fetch-control-document") is
                 controlDocument:

                 1. [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") container in navigable’s
                    [active document](https://html.spec.whatwg.org/multipage/document-sequences.html#nav-document "https://html.spec.whatwg.org/multipage/document-sequences.html#nav-document")’s [shadow-including inclusive descendants](https://dom.spec.whatwg.org/#concept-shadow-including-inclusive-descendant "https://dom.spec.whatwg.org/#concept-shadow-including-inclusive-descendant") which is a
                    [navigable container](https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container "https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container"), decrement quota by container’s
                    [reserved deferred-fetch quota](#reserved-deferred-fetch-quota "#reserved-deferred-fetch-quota").

                    - [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") [deferred fetch record](#deferred-fetch-record "#deferred-fetch-record") deferredRecord of
                      navigable’s [active document](https://html.spec.whatwg.org/multipage/document-sequences.html#nav-document "https://html.spec.whatwg.org/multipage/document-sequences.html#nav-document")’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object")’s
                      [fetch group](#environment-settings-object-fetch-group "#environment-settings-object-fetch-group")’s
                      [deferred fetch records](#fetch-group-deferred-fetch-records "#fetch-group-deferred-fetch-records"):

                      1. If deferredRecord’s [invoke state](#deferred-fetch-record-invoke-state "#deferred-fetch-record-invoke-state")
                         is not "`pending`", then [continue](https://infra.spec.whatwg.org/#iteration-continue "https://infra.spec.whatwg.org/#iteration-continue").

                         - Let requestLength be the [total request length](#total-request-length "#total-request-length") of
                           deferredRecord’s [request](#deferred-fetch-record-request "#deferred-fetch-record-request").

                           - Decrement quota by requestLength.

                             - If deferredRecord’s [request](#deferred-fetch-record-request "#deferred-fetch-record-request")’s
                               [URL](#concept-request-url "#concept-request-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") is [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with origin,
                               then decrement quotaForRequestOrigin by requestLength.- If quota is equal or less than 0, then return 0.

                   - If quota is less than quotaForRequestOrigin, then return
                     quota.

                     - Return quotaForRequestOrigin.

To reserve deferred-fetch quota for a [navigable container](https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container "https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container")
container given an [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin") originToNavigateTo:

This is called on navigation, when the source document of the navigation is the
[navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#navigable")’s parent document. It potentially reserves either 64kb or 8kb of quota for
the container and its navigable, if allowed by permissions policy. It is not observable to the
container document whether the reserved quota was used in practice. This algorithm assumes that the
container’s document might delegate quota to the navigated container, and the reserved quota would
only apply in that case, and would be ignored if it ends up being shared. If quota was reserved and
the document ends up being [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with its parent, the quota would be
[freed](#potentially-free-deferred-fetch-quota "#potentially-free-deferred-fetch-quota").

1. Set container’s [reserved deferred-fetch quota](#reserved-deferred-fetch-quota "#reserved-deferred-fetch-quota") to 0.

   - Let controlDocument be container’s [node document](https://dom.spec.whatwg.org/#concept-node-document "https://dom.spec.whatwg.org/#concept-node-document")’s
     [deferred-fetch control document](#deferred-fetch-control-document "#deferred-fetch-control-document").

     - If the [inherited policy](https://w3c.github.io/webappsec-permissions-policy/#algo-define-inherited-policy-in-container "https://w3c.github.io/webappsec-permissions-policy/#algo-define-inherited-policy-in-container")
       for "`deferred-fetch`", container and originToNavigateTo
       is `"Enabled"`, and the [available deferred-fetch quota](#available-deferred-fetch-quota "#available-deferred-fetch-quota") for
       controlDocument is equal or greater than
       [normal quota](#reserved-deferred-fetch-quota-normal-quota "#reserved-deferred-fetch-quota-normal-quota"), then set container’s
       [reserved deferred-fetch quota](#reserved-deferred-fetch-quota "#reserved-deferred-fetch-quota") to [normal quota](#reserved-deferred-fetch-quota-normal-quota "#reserved-deferred-fetch-quota-normal-quota") and
       return.

       - If all of the following conditions are true:

         * controlDocument’s [node navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable") is a [top-level traversable](https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable "https://html.spec.whatwg.org/multipage/document-sequences.html#top-level-traversable");

           * the [inherited policy](https://w3c.github.io/webappsec-permissions-policy/#algo-define-inherited-policy-in-container "https://w3c.github.io/webappsec-permissions-policy/#algo-define-inherited-policy-in-container")
             for "`deferred-fetch-minimal`", container and
             originToNavigateTo is `"Enabled"`; and

             * the [size](https://infra.spec.whatwg.org/#list-size "https://infra.spec.whatwg.org/#list-size") of controlDocument’s [node navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable")’s
               [descendant navigables](https://html.spec.whatwg.org/multipage/document-sequences.html#descendant-navigables "https://html.spec.whatwg.org/multipage/document-sequences.html#descendant-navigables"), [removing](https://infra.spec.whatwg.org/#list-remove "https://infra.spec.whatwg.org/#list-remove") any [navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#navigable")
               whose [navigable container](https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container "https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container")’s [reserved deferred-fetch quota](#reserved-deferred-fetch-quota "#reserved-deferred-fetch-quota") is not
               [minimal quota](#reserved-deferred-fetch-quota-minimal-quota "#reserved-deferred-fetch-quota-minimal-quota"), is less than
               [quota reserved for `deferred-fetch-minimal`](#quota-reserved-for-deferred-fetch-minimal "#quota-reserved-for-deferred-fetch-minimal") /
               [minimal quota](#reserved-deferred-fetch-quota-minimal-quota "#reserved-deferred-fetch-quota-minimal-quota"),

         then set container’s [reserved deferred-fetch quota](#reserved-deferred-fetch-quota "#reserved-deferred-fetch-quota") to
         [minimal quota](#reserved-deferred-fetch-quota-minimal-quota "#reserved-deferred-fetch-quota-minimal-quota").

To potentially free deferred-fetch quota for a [document](https://dom.spec.whatwg.org/#concept-document "https://dom.spec.whatwg.org/#concept-document")
document, if document’s [node navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable")’s [container document](https://html.spec.whatwg.org/multipage/document-sequences.html#nav-container-document "https://html.spec.whatwg.org/multipage/document-sequences.html#nav-container-document") is
not null, and its [origin](https://dom.spec.whatwg.org/#concept-document-origin "https://dom.spec.whatwg.org/#concept-document-origin") is [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with document, then
set document’s [node navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable")’s [navigable container](https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container "https://html.spec.whatwg.org/multipage/document-sequences.html#navigable-container")’s
[reserved deferred-fetch quota](#reserved-deferred-fetch-quota "#reserved-deferred-fetch-quota") to 0.

This is called when a [document](https://dom.spec.whatwg.org/#concept-document "https://dom.spec.whatwg.org/#concept-document") is created. It ensures that same-origin
nested documents don’t reserve quota, as they anyway share their parent quota. It can only be called
upon document creation, as the [origin](https://dom.spec.whatwg.org/#concept-document-origin "https://dom.spec.whatwg.org/#concept-document-origin") of the [document](https://dom.spec.whatwg.org/#concept-document "https://dom.spec.whatwg.org/#concept-document") is only known
after redirects are handled.

To get the deferred-fetch control document of a [document](https://dom.spec.whatwg.org/#concept-document "https://dom.spec.whatwg.org/#concept-document")
document:

1. If document’ [node navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable")’s [container document](https://html.spec.whatwg.org/multipage/document-sequences.html#nav-container-document "https://html.spec.whatwg.org/multipage/document-sequences.html#nav-container-document") is null or a
   [document](https://dom.spec.whatwg.org/#concept-document "https://dom.spec.whatwg.org/#concept-document") whose [origin](https://dom.spec.whatwg.org/#concept-document-origin "https://dom.spec.whatwg.org/#concept-document-origin") is not [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with
   document, then return document; otherwise, return the
   [deferred-fetch control document](#deferred-fetch-control-document "#deferred-fetch-control-document") given document’s [node navigable](https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable "https://html.spec.whatwg.org/multipage/document-sequences.html#node-navigable")’s
   [container document](https://html.spec.whatwg.org/multipage/document-sequences.html#nav-container-document "https://html.spec.whatwg.org/multipage/document-sequences.html#nav-container-document").

5. Fetch API
------------

The [`fetch()`](#dom-global-fetch "#dom-global-fetch") method is relatively low-level API for
[fetching](#concept-fetch "#concept-fetch") resources. It covers slightly more ground than `XMLHttpRequest`,
although it is currently lacking when it comes to request progression (not response progression).

The [`fetch()`](#dom-global-fetch "#dom-global-fetch") method makes it quite straightforward to
[fetch](#concept-fetch "#concept-fetch") a resource and extract its contents as a `Blob`:

```
fetch("/music/pk/altes-kamuffel.flac")
  .then(res => res.blob()).then(playBlob)
```

If you just care to log a particular response header:

```
fetch("/", {method:"HEAD"})
  .then(res => log(res.headers.get("strict-transport-security")))
```

If you want to check a particular response header and then process the response of a
cross-origin resource:

```
fetch("https://pk.example/berlin-calling.json", {mode:"cors"})
  .then(res => {
    if(res.headers.get("content-type") &&
       res.headers.get("content-type").toLowerCase().indexOf("application/json") >= 0) {
      return res.json()
    } else {
      throw new TypeError()
    }
  }).then(processJSON)
```

If you want to work with URL query parameters:

```
var url = new URL("https://geo.example.org/api"),
    params = {lat:35.696233, long:139.570431}
Object.keys(params).forEach(key => url.searchParams.append(key, params[key]))
fetch(url).then(/* … */)
```

If you want to receive the body data progressively:

```
function consume(reader) {
  var total = 0
  return pump()
  function pump() {
    return reader.read().then(({done, value}) => {
      if (done) {
        return
      }
      total += value.byteLength
      log(`received ${value.byteLength} bytes (${total} bytes in total)`)
      return pump()
    })
  }
}

fetch("/music/pk/altes-kamuffel.flac")
  .then(res => consume(res.body.getReader()))
  .then(() => log("consumed the entire body without keeping the whole thing in memory!"))
  .catch(e => log("something went wrong: " + e))
```

### 5.1. Headers class

```
typedef (sequence<sequence<ByteString>> or record<ByteString, ByteString>) HeadersInit;

[Exposed=(Window,Worker)]
interface Headers {
  constructor(optional HeadersInit init);

  undefined append(ByteString name, ByteString value);
  undefined delete(ByteString name);
  ByteString? get(ByteString name);
  sequence<ByteString> getSetCookie();
  boolean has(ByteString name);
  undefined set(ByteString name, ByteString value);
  iterable<ByteString, ByteString>;
};
```

A `Headers` object has an associated
header list (a
[header list](#concept-header-list "#concept-header-list")), which is initially empty. This
can be a pointer to the [header list](#concept-header-list "#concept-header-list") of something else, e.g.,
of a [request](#concept-request "#concept-request") as demonstrated by `Request`
objects.

A `Headers` object also has an associated
guard, which is a headers guard. A
[headers guard](#headers-guard "#headers-guard") is "`immutable`", "`request`",
"`request-no-cors`", "`response`" or "`none`".

---

`headers = new Headers([init])`: Creates a new `Headers` object. init can be used to fill its internal header list, as per the example below. ``` const meta = { "Content-Type": "text/xml", "Breaking-Bad": "<3" }; new Headers(meta); // The above is equivalent to const meta2 = [ [ "Content-Type", "text/xml" ], [ "Breaking-Bad", "<3" ] ]; new Headers(meta2); ``` `headers . append(name, value)`: Appends a header to headers. `headers . delete(name)`: Removes a header from headers. `headers . get(name)`: Returns as a string the values of all headers whose name is name, separated by a comma and a space. `headers . getSetCookie()`: Returns a list of the values for all headers whose name is ``Set-Cookie``. `headers . has(name)`: Returns whether there is a header whose name is name. `headers . set(name, value)`: Replaces the value of the first header whose name is name with value and removes any remaining headers whose name is name. `for(const [name, value] of headers)`: headers can be iterated over.

---

To validate a [header](#concept-header "#concept-header") (name, value) for
a `Headers` object headers:

1. If name is not a [header name](#header-name "#header-name") or value is not a
   [header value](#header-value "#header-value"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

   - If headers’s [guard](#concept-headers-guard "#concept-headers-guard") is "`immutable`", then
     [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

     - If headers’s [guard](#concept-headers-guard "#concept-headers-guard") is "`request`" and
       (name, value) is a [forbidden request-header](#forbidden-request-header "#forbidden-request-header"), then return false.

       - If headers’s [guard](#concept-headers-guard "#concept-headers-guard") is "`response`" and
         name is a [forbidden response-header name](#forbidden-response-header-name "#forbidden-response-header-name"), then return false.

         - Return true.

Steps for "`request-no-cors`" are not shared as you cannot have a fake
value (for `delete()`) that always succeeds in [CORS-safelisted request-header](#cors-safelisted-request-header "#cors-safelisted-request-header").

To append a [header](#concept-header "#concept-header")
(name, value) to a `Headers` object headers, run these steps:

1. [Normalize](#concept-header-value-normalize "#concept-header-value-normalize") value.

   - If [validating](#headers-validate "#headers-validate") (name, value) for headers
     returns false, then return.

     - If headers’s [guard](#concept-headers-guard "#concept-headers-guard") is "`request-no-cors`":

       1. Let temporaryValue be the result of [getting](#concept-header-list-get "#concept-header-list-get")
          name from headers’s [header list](#concept-headers-header-list "#concept-headers-header-list").

          - If temporaryValue is null, then set temporaryValue to
            value.

            - Otherwise, set temporaryValue to temporaryValue, followed by
              0x2C 0x20, followed by value.

              - If (name, temporaryValue) is not a
                [no-CORS-safelisted request-header](#no-cors-safelisted-request-header "#no-cors-safelisted-request-header"), then return.- [Append](#concept-header-list-append "#concept-header-list-append") (name, value) to headers’s
         [header list](#concept-headers-header-list "#concept-headers-header-list").

         - If headers’s [guard](#concept-headers-guard "#concept-headers-guard") is "`request-no-cors`", then
           [remove privileged no-CORS request-headers](#concept-headers-remove-privileged-no-cors-request-headers "#concept-headers-remove-privileged-no-cors-request-headers") from headers.

To fill a `Headers` object
headers with a given object object, run these steps:

1. If object is a [sequence](https://webidl.spec.whatwg.org/#idl-sequence "https://webidl.spec.whatwg.org/#idl-sequence"), then [for each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") header of
   object:

   1. If header’s [size](https://infra.spec.whatwg.org/#list-size "https://infra.spec.whatwg.org/#list-size") is not 2, then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

      - [Append](#concept-headers-append "#concept-headers-append") (header[0], header[1]) to
        headers.- Otherwise, object is a [record](https://tc39.es/ecma262/#sec-list-and-record-specification-type "https://tc39.es/ecma262/#sec-list-and-record-specification-type"), then [for each](https://infra.spec.whatwg.org/#map-iterate "https://infra.spec.whatwg.org/#map-iterate")
     key → value of object, [append](#concept-headers-append "#concept-headers-append") (key,
     value) to headers.

To
remove privileged no-CORS request-headers
from a `Headers` object (headers), run these steps:

1. [For each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate") headerName of
   [privileged no-CORS request-header names](#privileged-no-cors-request-header-name "#privileged-no-cors-request-header-name"):

   1. [Delete](#concept-header-list-delete "#concept-header-list-delete") headerName from headers’s
      [header list](#concept-headers-header-list "#concept-headers-header-list").

This is called when headers are modified by unprivileged code.

The
`new Headers(init)`
constructor steps are:

1. Set [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [guard](#concept-headers-guard "#concept-headers-guard") to "`none`".

   - If init is given, then [fill](#concept-headers-fill "#concept-headers-fill") [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") with init.

The `append(name, value)`
method steps are to [append](#concept-headers-append "#concept-headers-append") (name, value) to [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this").

The `delete(name)` method steps are:

1. If [validating](#headers-validate "#headers-validate") (name, ``) for [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") returns false, then
   return.

   Passing a dummy [header value](#header-value "#header-value") ought not to have any negative repercussions.

   - If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [guard](#concept-headers-guard "#concept-headers-guard") is "`request-no-cors`", name
     is not a [no-CORS-safelisted request-header name](#no-cors-safelisted-request-header-name "#no-cors-safelisted-request-header-name"), and name is not a
     [privileged no-CORS request-header name](#privileged-no-cors-request-header-name "#privileged-no-cors-request-header-name"), then return.

     - If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [header list](#concept-headers-header-list "#concept-headers-header-list") [does not contain](#header-list-contains "#header-list-contains")
       name, then return.

       - [Delete](#concept-header-list-delete "#concept-header-list-delete") name from [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
         [header list](#concept-headers-header-list "#concept-headers-header-list").

         - If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [guard](#concept-headers-guard "#concept-headers-guard") is "`request-no-cors`", then
           [remove privileged no-CORS request-headers](#concept-headers-remove-privileged-no-cors-request-headers "#concept-headers-remove-privileged-no-cors-request-headers") from [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this").

The `get(name)` method steps are:

1. If name is not a [header name](#header-name "#header-name"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

   - Return the result of [getting](#concept-header-list-get "#concept-header-list-get") name from [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
     [header list](#concept-headers-header-list "#concept-headers-header-list").

The `getSetCookie()` method steps are:

1. If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [header list](#concept-headers-header-list "#concept-headers-header-list") [does not contain](#header-list-contains "#header-list-contains")
   ``Set-Cookie``, then return « ».

   - Return the [values](#concept-header-value "#concept-header-value") of all [headers](#concept-header "#concept-header") in [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
     [header list](#concept-headers-header-list "#concept-headers-header-list") whose [name](#concept-header-name "#concept-header-name") is a [byte-case-insensitive](https://infra.spec.whatwg.org/#byte-case-insensitive "https://infra.spec.whatwg.org/#byte-case-insensitive") match
     for ``Set-Cookie``, in order.

The `has(name)` method steps are:

1. If name is not a [header name](#header-name "#header-name"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

   - Return true if [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [header list](#concept-headers-header-list "#concept-headers-header-list")
     [contains](#header-list-contains "#header-list-contains") name; otherwise false.

The `set(name, value)`
method steps are:

1. [Normalize](#concept-header-value-normalize "#concept-header-value-normalize") value.

   - If [validating](#headers-validate "#headers-validate") (name, value) for [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") returns
     false, then return.

     - If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [guard](#concept-headers-guard "#concept-headers-guard") is "`request-no-cors`" and
       (name, value) is not a [no-CORS-safelisted request-header](#no-cors-safelisted-request-header "#no-cors-safelisted-request-header"), then return.

       - [Set](#concept-header-list-set "#concept-header-list-set") (name, value) in [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
         [header list](#concept-headers-header-list "#concept-headers-header-list").

         - If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [guard](#concept-headers-guard "#concept-headers-guard") is "`request-no-cors`", then
           [remove privileged no-CORS request-headers](#concept-headers-remove-privileged-no-cors-request-headers "#concept-headers-remove-privileged-no-cors-request-headers") from [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this").

The [value pairs to iterate over](https://webidl.spec.whatwg.org/#dfn-value-pairs-to-iterate-over "https://webidl.spec.whatwg.org/#dfn-value-pairs-to-iterate-over") are the return value of running
[sort and combine](#concept-header-list-sort-and-combine "#concept-header-list-sort-and-combine") with [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [header list](#concept-headers-header-list "#concept-headers-header-list").

### 5.2. BodyInit unions

```
typedef (Blob or BufferSource or FormData or URLSearchParams or USVString) XMLHttpRequestBodyInit;

typedef (ReadableStream or XMLHttpRequestBodyInit) BodyInit;
```

To safely extract a [body with type](#body-with-type "#body-with-type") from a
[byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") or `BodyInit` object object, run these steps:

1. If object is a `ReadableStream` object, then:

   1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): object is neither [disturbed](https://streams.spec.whatwg.org/#is-readable-stream-disturbed "https://streams.spec.whatwg.org/#is-readable-stream-disturbed") nor
      [locked](https://streams.spec.whatwg.org/#readablestream-locked "https://streams.spec.whatwg.org/#readablestream-locked").- Return the result of [extracting](#concept-bodyinit-extract "#concept-bodyinit-extract") object.

The [safely extract](#bodyinit-safely-extract "#bodyinit-safely-extract") operation is a subset of the
[extract](#concept-bodyinit-extract "#concept-bodyinit-extract") operation that is guaranteed to not throw an exception.

To extract a
[body with type](#body-with-type "#body-with-type") from a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") or `BodyInit` object
object, with an optional boolean
keepalive (default false), run these
steps:

1. Let stream be null.

   - If object is a `ReadableStream` object, then set stream to
     object.

     - Otherwise, if object is a `Blob` object, set stream to the result of
       running object’s [get stream](https://w3c.github.io/FileAPI/#blob-get-stream "https://w3c.github.io/FileAPI/#blob-get-stream").

       - Otherwise, set stream to a [new](https://webidl.spec.whatwg.org/#new "https://webidl.spec.whatwg.org/#new") `ReadableStream` object, and
         [set up](https://streams.spec.whatwg.org/#readablestream-set-up-with-byte-reading-support "https://streams.spec.whatwg.org/#readablestream-set-up-with-byte-reading-support") stream with byte reading
         support.

         - [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): stream is a `ReadableStream` object.

           - Let action be null.

             - Let source be null.

               - Let length be null.

                 - Let type be null.

                   - Switch on object:

                     `Blob`: Set source to object. Set length to object’s `size`. If object’s `type` attribute is not the empty byte sequence, set type to its value. [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"): Set source to object. `BufferSource`: Set source to a [copy of the bytes](https://webidl.spec.whatwg.org/#dfn-get-buffer-source-copy "https://webidl.spec.whatwg.org/#dfn-get-buffer-source-copy") held by object. `FormData`: Set action to this step: run the [`multipart/form-data` encoding algorithm](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart%2Fform-data-encoding-algorithm "https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart%2Fform-data-encoding-algorithm"), with object’s [entry list](https://xhr.spec.whatwg.org/#concept-formdata-entry-list "https://xhr.spec.whatwg.org/#concept-formdata-entry-list") and [UTF-8](https://encoding.spec.whatwg.org/#utf-8 "https://encoding.spec.whatwg.org/#utf-8"). Set source to object. Set length to unclear, see [html/6424](https://github.com/whatwg/html/issues/6424 "https://github.com/whatwg/html/issues/6424") for improving this. Set type to ``multipart/form-data; boundary=``, followed by the [`multipart/form-data` boundary string](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart%2Fform-data-boundary-string "https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart%2Fform-data-boundary-string") generated by the [`multipart/form-data` encoding algorithm](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart%2Fform-data-encoding-algorithm "https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart%2Fform-data-encoding-algorithm"). `URLSearchParams`: Set source to the result of running the [`application/x-www-form-urlencoded` serializer](https://url.spec.whatwg.org/#concept-urlencoded-serializer "https://url.spec.whatwg.org/#concept-urlencoded-serializer") with object’s [list](https://url.spec.whatwg.org/#concept-urlsearchparams-list "https://url.spec.whatwg.org/#concept-urlsearchparams-list"). Set type to ``application/x-www-form-urlencoded;charset=UTF-8``. [scalar value string](https://infra.spec.whatwg.org/#scalar-value-string "https://infra.spec.whatwg.org/#scalar-value-string"): Set source to the [UTF-8 encoding](https://encoding.spec.whatwg.org/#utf-8-encode "https://encoding.spec.whatwg.org/#utf-8-encode") of object. Set type to ``text/plain;charset=UTF-8``. `ReadableStream`: If keepalive is true, then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`. If object is [disturbed](https://streams.spec.whatwg.org/#is-readable-stream-disturbed "https://streams.spec.whatwg.org/#is-readable-stream-disturbed") or [locked](https://streams.spec.whatwg.org/#readablestream-locked "https://streams.spec.whatwg.org/#readablestream-locked"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                     - If source is a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"), then set action to a step
                       that returns source and length to source’s
                       [length](https://infra.spec.whatwg.org/#byte-sequence-length "https://infra.spec.whatwg.org/#byte-sequence-length").

                       - If action is non-null, then run these steps [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel"):

                         1. Run action.

                            Whenever one or more bytes are available and stream is not
                            [errored](https://streams.spec.whatwg.org/#readablestream-errored "https://streams.spec.whatwg.org/#readablestream-errored"), [enqueue](https://streams.spec.whatwg.org/#readablestream-enqueue "https://streams.spec.whatwg.org/#readablestream-enqueue") the result of
                            [creating](https://webidl.spec.whatwg.org/#arraybufferview-create "https://webidl.spec.whatwg.org/#arraybufferview-create") a `Uint8Array` from the available bytes into
                            stream.

                            When running action is done, [close](https://streams.spec.whatwg.org/#readablestream-close "https://streams.spec.whatwg.org/#readablestream-close") stream.- Let body be a [body](#concept-body "#concept-body") whose [stream](#concept-body-stream "#concept-body-stream") is
                           stream, [source](#concept-body-source "#concept-body-source") is source, and [length](#concept-body-total-bytes "#concept-body-total-bytes") is
                           length.

                           - Return (body, type).

### 5.3. Body mixin

```
interface mixin Body {
  readonly attribute ReadableStream? body;
  readonly attribute boolean bodyUsed;
  [NewObject] Promise<ArrayBuffer> arrayBuffer();
  [NewObject] Promise<Blob> blob();
  [NewObject] Promise<Uint8Array> bytes();
  [NewObject] Promise<FormData> formData();
  [NewObject] Promise<any> json();
  [NewObject] Promise<USVString> text();
};
```

Formats you would not want a network layer to be dependent upon, such as
HTML, will likely not be exposed here. Rather, an HTML parser API might accept a stream in
due course.

Objects including the `Body` interface mixin have an associated
body (null or a [body](#concept-body "#concept-body")).

An object including the `Body` interface mixin is said to be
unusable if its [body](#concept-body-body "#concept-body-body") is non-null and its
[body](#concept-body-body "#concept-body-body")’s [stream](#concept-body-stream "#concept-body-stream") is [disturbed](https://streams.spec.whatwg.org/#is-readable-stream-disturbed "https://streams.spec.whatwg.org/#is-readable-stream-disturbed") or
[locked](https://streams.spec.whatwg.org/#readablestream-locked "https://streams.spec.whatwg.org/#readablestream-locked").

---

`requestOrResponse . body`: Returns requestOrResponse’s body as `ReadableStream`. `requestOrResponse . bodyUsed`: Returns whether requestOrResponse’s body has been read from. `requestOrResponse . arrayBuffer()`: Returns a promise fulfilled with requestOrResponse’s body as `ArrayBuffer`. `requestOrResponse . blob()`: Returns a promise fulfilled with requestOrResponse’s body as `Blob`. `requestOrResponse . bytes()`: Returns a promise fulfilled with requestOrResponse’s body as `Uint8Array`. `requestOrResponse . formData()`: Returns a promise fulfilled with requestOrResponse’s body as `FormData`. `requestOrResponse . json()`: Returns a promise fulfilled with requestOrResponse’s body parsed as JSON. `requestOrResponse . text()`: Returns a promise fulfilled with requestOrResponse’s body as string.

---

To get the MIME type, given a `Request` or
`Response` object requestOrResponse:

1. Let headers be null.

   - If requestOrResponse is a `Request` object, then set headers to
     requestOrResponse’s [request](#concept-request-request "#concept-request-request")’s [header list](#concept-request-header-list "#concept-request-header-list").

     - Otherwise, set headers to requestOrResponse’s
       [response](#concept-response-response "#concept-response-response")’s [header list](#concept-response-header-list "#concept-response-header-list").

       - Let mimeType be the result of [extracting a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type")
         from headers.

         - If mimeType is failure, then return null.

           - Return mimeType.

The `body` getter steps are to return null if
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [body](#concept-body-body "#concept-body-body") is null; otherwise [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [body](#concept-body-body "#concept-body-body")’s
[stream](#concept-body-stream "#concept-body-stream").

The `bodyUsed` getter steps are to return true if
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [body](#concept-body-body "#concept-body-body") is non-null and [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [body](#concept-body-body "#concept-body-body")’s
[stream](#concept-body-stream "#concept-body-stream") is [disturbed](https://streams.spec.whatwg.org/#is-readable-stream-disturbed "https://streams.spec.whatwg.org/#is-readable-stream-disturbed"); otherwise false.

The consume body
algorithm, given an object that includes `Body` object and an algorithm that takes a
[byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") and returns a JavaScript value or throws an exception
convertBytesToJSValue, runs these steps:

1. If object is [unusable](#body-unusable "#body-unusable"), then return [a promise rejected with](https://webidl.spec.whatwg.org/#a-promise-rejected-with "https://webidl.spec.whatwg.org/#a-promise-rejected-with")
   a `TypeError`.

   - Let promise be [a new promise](https://webidl.spec.whatwg.org/#a-new-promise "https://webidl.spec.whatwg.org/#a-new-promise").

     - Let errorSteps given error be to [reject](https://webidl.spec.whatwg.org/#reject "https://webidl.spec.whatwg.org/#reject") promise with
       error.- Let successSteps given a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") data be to
         [resolve](https://webidl.spec.whatwg.org/#resolve "https://webidl.spec.whatwg.org/#resolve") promise with the result of running convertBytesToJSValue
         with data. If that threw an exception, then run errorSteps with that
         exception.- If object’s [body](#concept-body-body "#concept-body-body") is null, then run successSteps
           with an empty [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence").

           - Otherwise, [fully read](#body-fully-read "#body-fully-read") object’s [body](#concept-body-body "#concept-body-body") given
             successSteps, errorSteps, and object’s
             [relevant global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-global").

             - Return promise.

The `arrayBuffer()` method steps are to return the result
of running [consume body](#concept-body-consume-body "#concept-body-consume-body") with [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") and the following step given a
[byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") bytes: return the result of [creating](https://webidl.spec.whatwg.org/#arraybuffer-create "https://webidl.spec.whatwg.org/#arraybuffer-create") an
`ArrayBuffer` from bytes in [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant realm](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm").

The above method can reject with a `RangeError`.

The `blob()` method steps are to return the result
of running [consume body](#concept-body-consume-body "#concept-body-consume-body") with [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") and the following step given a
[byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") bytes: return a `Blob` whose contents are bytes
and whose `type` attribute is the result of [get the MIME type](#concept-body-mime-type "#concept-body-mime-type") with
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this").

The `bytes()` method steps are to return the result
of running [consume body](#concept-body-consume-body "#concept-body-consume-body") with [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") and the following step given a
[byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") bytes: return the result of [creating](https://webidl.spec.whatwg.org/#arraybufferview-create "https://webidl.spec.whatwg.org/#arraybufferview-create") a
`Uint8Array` from bytes in [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant realm](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm").

The above method can reject with a `RangeError`.

The `formData()` method steps are to return the result of
running [consume body](#concept-body-consume-body "#concept-body-consume-body") with [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") and the following steps given a
[byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") bytes:

1. Let mimeType be the result of [get the MIME type](#concept-body-mime-type "#concept-body-mime-type") with [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this").

   - If mimeType is non-null, then switch on mimeType’s
     [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence "https://mimesniff.spec.whatwg.org/#mime-type-essence") and run the corresponding steps:

     "`multipart/form-data`": 1. Parse bytes, using the value of the ``boundary`` parameter from mimeType, per the rules set forth in Returning Values from Forms: multipart/form-data. [[RFC7578]](#biblio-rfc7578 "Returning Values from Forms: multipart/form-data") Each part whose ``Content-Disposition`` header contains a ``filename`` parameter must be parsed into an [entry](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-entry "https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-entry") whose value is a `File` object whose contents are the contents of the part. The `name` attribute of the `File` object must have the value of the ``filename`` parameter of the part. The `type` attribute of the `File` object must have the value of the ``Content-Type`` header of the part if the part has such header, and ``text/plain`` (the default defined by [[RFC7578]](#biblio-rfc7578 "Returning Values from Forms: multipart/form-data") section 4.4) otherwise. Each part whose ``Content-Disposition`` header does not contain a ``filename`` parameter must be parsed into an [entry](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-entry "https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-entry") whose value is the [UTF-8 decoded without BOM](https://encoding.spec.whatwg.org/#utf-8-decode-without-bom "https://encoding.spec.whatwg.org/#utf-8-decode-without-bom") content of the part. This is done regardless of the presence or the value of a ``Content-Type`` header and regardless of the presence or the value of a ``charset`` parameter. A part whose ``Content-Disposition`` header contains a ``name`` parameter whose value is ``_charset_`` is parsed like any other part. It does not change the encoding. - If that fails for some reason, then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`. - Return a new `FormData` object, appending each [entry](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-entry "https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-entry"), resulting from the parsing operation, to its [entry list](https://xhr.spec.whatwg.org/#concept-formdata-entry-list "https://xhr.spec.whatwg.org/#concept-formdata-entry-list"). The above is a rough approximation of what is needed for ``multipart/form-data``, a more detailed parsing specification is to be written. Volunteers welcome. "`application/x-www-form-urlencoded`": 1. Let entries be the result of [parsing](https://url.spec.whatwg.org/#concept-urlencoded-parser "https://url.spec.whatwg.org/#concept-urlencoded-parser") bytes. - Return a new `FormData` object whose [entry list](https://xhr.spec.whatwg.org/#concept-formdata-entry-list "https://xhr.spec.whatwg.org/#concept-formdata-entry-list") is entries.

     - [Throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

The `json()` method steps are to return the result
of running [consume body](#concept-body-consume-body "#concept-body-consume-body") with [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") and [parse JSON from bytes](https://infra.spec.whatwg.org/#parse-json-bytes-to-a-javascript-value "https://infra.spec.whatwg.org/#parse-json-bytes-to-a-javascript-value").

The above method can reject with a `SyntaxError`.

The `text()` method steps are to return the result
of running [consume body](#concept-body-consume-body "#concept-body-consume-body") with [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") and [UTF-8 decode](https://encoding.spec.whatwg.org/#utf-8-decode "https://encoding.spec.whatwg.org/#utf-8-decode").

### 5.4. Request class

```
typedef (Request or USVString) RequestInfo;

[Exposed=(Window,Worker)]
interface Request {
  constructor(RequestInfo input, optional RequestInit init = {});

  readonly attribute ByteString method;
  readonly attribute USVString url;
  [SameObject] readonly attribute Headers headers;

  readonly attribute RequestDestination destination;
  readonly attribute USVString referrer;
  readonly attribute ReferrerPolicy referrerPolicy;
  readonly attribute RequestMode mode;
  readonly attribute RequestCredentials credentials;
  readonly attribute RequestCache cache;
  readonly attribute RequestRedirect redirect;
  readonly attribute DOMString integrity;
  readonly attribute boolean keepalive;
  readonly attribute boolean isReloadNavigation;
  readonly attribute boolean isHistoryNavigation;
  readonly attribute AbortSignal signal;
  readonly attribute RequestDuplex duplex;

  [NewObject] Request clone();
};
Request includes Body;

dictionary RequestInit {
  ByteString method;
  HeadersInit headers;
  BodyInit? body;
  USVString referrer;
  ReferrerPolicy referrerPolicy;
  RequestMode mode;
  RequestCredentials credentials;
  RequestCache cache;
  RequestRedirect redirect;
  DOMString integrity;
  boolean keepalive;
  AbortSignal? signal;
  RequestDuplex duplex;
  RequestPriority priority;
  any window; // can only be set to null
};

enum RequestDestination { "", "audio", "audioworklet", "document", "embed", "font", "frame", "iframe", "image", "json", "manifest", "object", "paintworklet", "report", "script", "sharedworker", "style", "text", "track", "video", "worker", "xslt" };
enum RequestMode { "navigate", "same-origin", "no-cors", "cors" };
enum RequestCredentials { "omit", "same-origin", "include" };
enum RequestCache { "default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached" };
enum RequestRedirect { "follow", "error", "manual" };
enum RequestDuplex { "half" };
enum RequestPriority { "high", "low", "auto" };
```

"`serviceworker`" is omitted from
[`RequestDestination`](#requestdestination "#requestdestination") as it cannot be observed from JavaScript. Implementations
will still need to support it as a [destination](#concept-request-destination "#concept-request-destination"). "`websocket`" and
"`webtransport`" are omitted from [`RequestMode`](#requestmode "#requestmode") as they cannot be
used or observed from JavaScript.

A `Request` object has an associated
request (a [request](#concept-request "#concept-request")).

A `Request` object also has an associated headers (null or a
`Headers` object), initially null.

A `Request` object has an associated signal (null or an `AbortSignal`
object), initially null.

A `Request` object’s [body](#concept-body-body "#concept-body-body") is its
[request](#concept-request-request "#concept-request-request")’s
[body](#concept-request-body "#concept-request-body").

---

`request = new Request(input [, init])`: Returns a new request whose `url` property is input if input is a string, and input’s `url` if input is a `Request` object. The init argument is an object whose properties can be set as follows: `method`: A string to set request’s `method`. `headers`: A `Headers` object, an object literal, or an array of two-item arrays to set request’s `headers`. `body`: A `BodyInit` object or null to set request’s [body](#concept-request-body "#concept-request-body"). `referrer`: A string whose value is a same-origin URL, "`about:client`", or the empty string, to set request’s [referrer](#concept-request-referrer "#concept-request-referrer"). `referrerPolicy`: A [referrer policy](https://w3c.github.io/webappsec-referrer-policy/#referrer-policy "https://w3c.github.io/webappsec-referrer-policy/#referrer-policy") to set request’s `referrerPolicy`. `mode`: A string to indicate whether the request will use CORS, or will be restricted to same-origin URLs. Sets request’s `mode`. If input is a string, it defaults to "`cors`". `credentials`: A string indicating whether credentials will be sent with the request always, never, or only when sent to a same-origin URL — as well as whether any credentials sent back in the response will be used always, never, or only when received from a same-origin URL. Sets request’s `credentials`. If input is a string, it defaults to "`same-origin`". `cache`: A string indicating how the request will interact with the browser’s cache to set request’s `cache`. `redirect`: A string indicating whether request follows redirects, results in an error upon encountering a redirect, or returns the redirect (in an opaque fashion). Sets request’s `redirect`. `integrity`: A cryptographic hash of the resource to be fetched by request. Sets request’s `integrity`. `keepalive`: A boolean to set request’s `keepalive`. `signal`: An `AbortSignal` to set request’s `signal`. `window`: Can only be null. Used to disassociate request from any `Window`. `duplex`: "`half`" is the only valid value and it is for initiating a half-duplex fetch (i.e., the user agent sends the entire request before processing the response). "`full`" is reserved for future use, for initiating a full-duplex fetch (i.e., the user agent can process the response before sending the entire request). This member needs to be set when `body` is a `ReadableStream` object. See [issue #1254](https://github.com/whatwg/fetch/issues/1254 "https://github.com/whatwg/fetch/issues/1254") for defining "`full`". `priority`: A string to set request’s [priority](#request-priority "#request-priority"). `request . method`: Returns request’s HTTP method, which is "`GET`" by default. `request . url`: Returns the URL of request as a string. `request . headers`: Returns a `Headers` object consisting of the headers associated with request. Note that headers added in the network layer by the user agent will not be accounted for in this object, e.g., the "`Host`" header. `request . destination`: Returns the kind of resource requested by request, e.g., "`document`" or "`script`". `request . referrer`: Returns the referrer of request. Its value can be a same-origin URL if explicitly set in init, the empty string to indicate no referrer, and "`about:client`" when defaulting to the global’s default. This is used during fetching to determine the value of the ``Referer`` header of the request being made. `request . referrerPolicy`: Returns the referrer policy associated with request. This is used during fetching to compute the value of the request’s referrer. `request . mode`: Returns the [mode](#concept-request-mode "#concept-request-mode") associated with request, which is a string indicating whether the request will use CORS, or will be restricted to same-origin URLs. `request . credentials`: Returns the [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") associated with request, which is a string indicating whether credentials will be sent with the request always, never, or only when sent to a same-origin URL. `request . cache`: Returns the [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") associated with request, which is a string indicating how the request will interact with the browser’s cache when fetching. `request . redirect`: Returns the [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") associated with request, which is a string indicating how redirects for the request will be handled during fetching. A [request](#concept-request "#concept-request") will follow redirects by default. `request . integrity`: Returns request’s subresource integrity metadata, which is a cryptographic hash of the resource being fetched. Its value consists of multiple hashes separated by whitespace. [[SRI]](#biblio-sri "Subresource Integrity") `request . keepalive`: Returns a boolean indicating whether or not request can outlive the global in which it was created. `request . isReloadNavigation`: Returns a boolean indicating whether or not request is for a reload navigation. `request . isHistoryNavigation`: Returns a boolean indicating whether or not request is for a history navigation (a.k.a. back-foward navigation). `request . signal`: Returns the signal associated with request, which is an `AbortSignal` object indicating whether or not request has been aborted, and its abort event handler. `request . duplex`: Returns "`half`", meaning the fetch will be half-duplex (i.e., the user agent sends the entire request before processing the response). In future, it could also return "`full`", meaning the fetch will be full-duplex (i.e., the user agent can process the response before sending the entire request) to indicate that the fetch will be full-duplex. See [issue #1254](https://github.com/whatwg/fetch/issues/1254 "https://github.com/whatwg/fetch/issues/1254") for defining "`full`". `request . clone()`: Returns a clone of request.

---

To create a `Request` object, given a
[request](#concept-request "#concept-request") request, [headers guard](#headers-guard "#headers-guard") guard,
`AbortSignal` object signal, and [realm](https://tc39.es/ecma262/#realm "https://tc39.es/ecma262/#realm") realm:

1. Let requestObject be a [new](https://webidl.spec.whatwg.org/#new "https://webidl.spec.whatwg.org/#new") `Request` object with realm.

   - Set requestObject’s [request](#concept-request-request "#concept-request-request") to request.

     - Set requestObject’s [headers](#request-headers "#request-headers") to a [new](https://webidl.spec.whatwg.org/#new "https://webidl.spec.whatwg.org/#new") `Headers`
       object with realm, whose [headers list](#concept-headers-header-list "#concept-headers-header-list") is request’s
       [headers list](#concept-request-header-list "#concept-request-header-list") and [guard](#concept-headers-guard "#concept-headers-guard") is guard.

       - Set requestObject’s [signal](#request-signal "#request-signal") to signal.

         - Return requestObject.

---

The
`new Request(input, init)`
constructor steps are:

1. Let request be null.

   - Let fallbackMode be null.

     - Let baseURL be [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object")’s
       [API base URL](https://html.spec.whatwg.org/multipage/webappapis.html#api-base-url "https://html.spec.whatwg.org/multipage/webappapis.html#api-base-url").

       - Let signal be null.

         - If input is a string, then:

           1. Let parsedURL be the result of
              [parsing](https://url.spec.whatwg.org/#concept-url-parser "https://url.spec.whatwg.org/#concept-url-parser") input with
              baseURL.

              - If parsedURL is failure, then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                - If parsedURL [includes credentials](https://url.spec.whatwg.org/#include-credentials "https://url.spec.whatwg.org/#include-credentials"), then
                  [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                  - Set request to a new [request](#concept-request "#concept-request") whose [URL](#concept-request-url "#concept-request-url") is
                    parsedURL.

                    - Set fallbackMode to "`cors`".- Otherwise:

             1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): input is a `Request` object.

                - Set request to input’s
                  [request](#concept-request-request "#concept-request-request").

                  - Set signal to input’s [signal](#request-signal "#request-signal").- Let origin be [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object")’s
               [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin").

               - Let traversableForUserPrompts be "`client`".

                 - If request’s [traversable for user prompts](#concept-request-window "#concept-request-window")
                   is an [environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object") and its
                   [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin") is [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with
                   origin, then set traversableForUserPrompts to
                   request’s [traversable for user prompts](#concept-request-window "#concept-request-window").

                   - If init["`window`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists") and is non-null, then
                     [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                     - If init["`window`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set
                       traversableForUserPrompts to "`no-traversable`".

                       - Set request to a new [request](#concept-request "#concept-request") with the following properties:

                         [URL](#concept-request-url "#concept-request-url"): request’s [URL](#concept-request-url "#concept-request-url"). [method](#concept-request-method "#concept-request-method"): request’s [method](#concept-request-method "#concept-request-method"). [header list](#concept-request-header-list "#concept-request-header-list"): A copy of request’s [header list](#concept-request-header-list "#concept-request-header-list"). [unsafe-request flag](#unsafe-request-flag "#unsafe-request-flag"): Set. [client](#concept-request-client "#concept-request-client"): [This](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object"). [traversable for user prompts](#concept-request-window "#concept-request-window"): traversableForUserPrompts. [internal priority](#request-internal-priority "#request-internal-priority"): request’s [internal priority](#request-internal-priority "#request-internal-priority"). [origin](#concept-request-origin "#concept-request-origin"): request’s [origin](#concept-request-origin "#concept-request-origin"). The propagation of the [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin") is only significant for navigation requests being handled by a service worker. In this scenario a request can have an origin that is different from the current client. [referrer](#concept-request-referrer "#concept-request-referrer"): request’s [referrer](#concept-request-referrer "#concept-request-referrer"). [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy"): request’s [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy"). [mode](#concept-request-mode "#concept-request-mode"): request’s [mode](#concept-request-mode "#concept-request-mode"). [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode"): request’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode"). [cache mode](#concept-request-cache-mode "#concept-request-cache-mode"): request’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode"). [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode"): request’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode"). [integrity metadata](#concept-request-integrity-metadata "#concept-request-integrity-metadata"): request’s [integrity metadata](#concept-request-integrity-metadata "#concept-request-integrity-metadata"). [keepalive](#request-keepalive-flag "#request-keepalive-flag"): request’s [keepalive](#request-keepalive-flag "#request-keepalive-flag"). [reload-navigation flag](#concept-request-reload-navigation-flag "#concept-request-reload-navigation-flag"): request’s [reload-navigation flag](#concept-request-reload-navigation-flag "#concept-request-reload-navigation-flag"). [history-navigation flag](#concept-request-history-navigation-flag "#concept-request-history-navigation-flag"): request’s [history-navigation flag](#concept-request-history-navigation-flag "#concept-request-history-navigation-flag"). [URL list](#concept-request-url-list "#concept-request-url-list"): A [clone](https://infra.spec.whatwg.org/#list-clone "https://infra.spec.whatwg.org/#list-clone") of request’s [URL list](#concept-request-url-list "#concept-request-url-list"). [initiator type](#request-initiator-type "#request-initiator-type"): "`fetch`".

                         - If init [is not empty](https://infra.spec.whatwg.org/#map-is-empty "https://infra.spec.whatwg.org/#map-is-empty"), then:

                           1. If request’s [mode](#concept-request-mode "#concept-request-mode") is
                              "`navigate`", then set it to "`same-origin`".

                              - Unset request’s [reload-navigation flag](#concept-request-reload-navigation-flag "#concept-request-reload-navigation-flag").

                                - Unset request’s [history-navigation flag](#concept-request-history-navigation-flag "#concept-request-history-navigation-flag").

                                  - Set request’s [origin](#concept-request-origin "#concept-request-origin") to "`client`".

                                    - Set request’s [referrer](#concept-request-referrer "#concept-request-referrer") to "`client`".

                                      - Set request’s [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy") to the empty string.

                                        - Set request’s [URL](#concept-request-url "#concept-request-url") to request’s
                                          [current URL](#concept-request-current-url "#concept-request-current-url").

                                          - Set request’s [URL list](#concept-request-url-list "#concept-request-url-list") to « request’s
                                            [URL](#concept-request-url "#concept-request-url") ».

                           This is done to ensure that when a service worker "redirects" a request, e.g., from
                           an image in a cross-origin style sheet, and makes modifications, it no longer appears to come from
                           the original source (i.e., the cross-origin style sheet), but instead from the service worker that
                           "redirected" the request. This is important as the original source might not even be able to
                           generate the same kind of requests as the service worker. Services that trust the original source
                           could therefore be exploited were this not done, although that is somewhat farfetched.

                           - If init["`referrer`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then:

                             1. Let referrer be init["`referrer`"].

                                - If referrer is the empty string, then set request’s
                                  [referrer](#concept-request-referrer "#concept-request-referrer") to "`no-referrer`".

                                  - Otherwise:

                                    1. Let parsedReferrer be the result of [parsing](https://url.spec.whatwg.org/#concept-url-parser "https://url.spec.whatwg.org/#concept-url-parser")
                                       referrer with baseURL.

                                       - If parsedReferrer is failure, then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                                         - If one of the following is true

                                           * parsedReferrer’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is "`about`" and
                                             [path](https://url.spec.whatwg.org/#concept-url-path "https://url.spec.whatwg.org/#concept-url-path") is the string "`client`"

                                             * parsedReferrer’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin") is not [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin") with
                                               origin

                                           then set request’s [referrer](#concept-request-referrer "#concept-request-referrer") to "`client`".

                                           - Otherwise, set request’s [referrer](#concept-request-referrer "#concept-request-referrer") to
                                             parsedReferrer.- If init["`referrerPolicy`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set
                               request’s [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy") to it.

                               - Let mode be init["`mode`"] if it [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"),
                                 and fallbackMode otherwise.

                                 - If mode is "`navigate`", then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                                   - If mode is non-null, set request’s
                                     [mode](#concept-request-mode "#concept-request-mode") to mode.

                                     - If init["`credentials`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set
                                       request’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") to it.

                                       - If init["`cache`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set
                                         request’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") to it.

                                         - If request’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") is "`only-if-cached`" and
                                           request’s [mode](#concept-request-mode "#concept-request-mode") is *not* "`same-origin`", then
                                           [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                                           - If init["`redirect`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set
                                             request’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") to it.

                                             - If init["`integrity`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set
                                               request’s [integrity metadata](#concept-request-integrity-metadata "#concept-request-integrity-metadata") to it.

                                               - If init["`keepalive`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set
                                                 request’s [keepalive](#request-keepalive-flag "#request-keepalive-flag") to it.

                                                 - If init["`method`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then:

                                                   1. Let method be init["`method`"].

                                                      - If method is not a [method](#concept-method "#concept-method") or method is a
                                                        [forbidden method](#forbidden-method "#forbidden-method"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                                                        - [Normalize](#concept-method-normalize "#concept-method-normalize") method.

                                                          - Set request’s [method](#concept-request-method "#concept-request-method") to method.- If init["`signal`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set
                                                     signal to it.

                                                     - If init["`priority`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then:

                                                       1. If request’s [internal priority](#request-internal-priority "#request-internal-priority") is not null, then update
                                                          request’s [internal priority](#request-internal-priority "#request-internal-priority") in an [implementation-defined](https://infra.spec.whatwg.org/#implementation-defined "https://infra.spec.whatwg.org/#implementation-defined")
                                                          manner.

                                                          - Otherwise, set request’s [priority](#request-priority "#request-priority") to
                                                            init["`priority`"].- Set [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request") to request.

                                                         - Let signals be « signal » if signal is non-null; otherwise
                                                           « ».

                                                           - Set [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [signal](#request-signal "#request-signal") to the result of
                                                             [creating a dependent abort signal](https://dom.spec.whatwg.org/#create-a-dependent-abort-signal "https://dom.spec.whatwg.org/#create-a-dependent-abort-signal") from signals, using `AbortSignal` and
                                                             [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant realm](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm").

                                                             - Set [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers") to a [new](https://webidl.spec.whatwg.org/#new "https://webidl.spec.whatwg.org/#new") `Headers` object with
                                                               [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant realm](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm"), whose [header list](#concept-headers-header-list "#concept-headers-header-list") is request’s
                                                               [header list](#concept-request-header-list "#concept-request-header-list") and [guard](#concept-headers-guard "#concept-headers-guard") is "`request`".

                                                               - If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [mode](#concept-request-mode "#concept-request-mode") is
                                                                 "`no-cors`", then:

                                                                 1. If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [method](#concept-request-method "#concept-request-method") is not a
                                                                    [CORS-safelisted method](#cors-safelisted-method "#cors-safelisted-method"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                                                                    - Set [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers")’s [guard](#concept-headers-guard "#concept-headers-guard") to
                                                                      "`request-no-cors`".- If init [is not empty](https://infra.spec.whatwg.org/#map-is-empty "https://infra.spec.whatwg.org/#map-is-empty"), then:

                                                                   The headers are sanitized as they might contain headers that are not allowed by this
                                                                   mode. Otherwise, they were previously sanitized or are unmodified since they were set by a
                                                                   privileged API.

                                                                   1. Let headers be a copy of [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers") and its
                                                                      associated [header list](#concept-headers-header-list "#concept-headers-header-list").

                                                                      - If init["`headers`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set
                                                                        headers to init["`headers`"].

                                                                        - Empty [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers")’s [header list](#concept-headers-header-list "#concept-headers-header-list").

                                                                          - If headers is a `Headers` object, then [for each](https://infra.spec.whatwg.org/#list-iterate "https://infra.spec.whatwg.org/#list-iterate")
                                                                            header of its [header list](#concept-headers-header-list "#concept-headers-header-list"), [append](#concept-headers-append "#concept-headers-append")
                                                                            header to [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers").

                                                                            - Otherwise, [fill](#concept-headers-fill "#concept-headers-fill") [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers") with
                                                                              headers.- Let inputBody be input’s [request](#concept-request-request "#concept-request-request")’s
                                                                     [body](#concept-request-body "#concept-request-body") if input is a `Request` object; otherwise null.

                                                                     - If either init["`body`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists") and is non-null or
                                                                       inputBody is non-null, and request’s [method](#concept-request-method "#concept-request-method") is
                                                                       ``GET`` or ``HEAD``, then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                                                                       - Let initBody be null.

                                                                         - If init["`body`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists") and is non-null, then:

                                                                           1. Let bodyWithType be the result of [extracting](#concept-bodyinit-extract "#concept-bodyinit-extract")
                                                                              init["`body`"], with [*keepalive*](#keepalive "#keepalive")
                                                                              set to request’s [keepalive](#request-keepalive-flag "#request-keepalive-flag").

                                                                              - Set initBody to bodyWithType’s [body](#body-with-type-body "#body-with-type-body").

                                                                                - Let type be bodyWithType’s [type](#body-with-type-type "#body-with-type-type").

                                                                                  - If type is non-null and [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers")’s
                                                                                    [header list](#concept-headers-header-list "#concept-headers-header-list") [does not contain](#header-list-contains "#header-list-contains")
                                                                                    ``Content-Type``, then [append](#concept-headers-append "#concept-headers-append") (``Content-Type``,
                                                                                    type) to [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers").- Let inputOrInitBody be initBody if it is non-null; otherwise
                                                                             inputBody.

                                                                             - If inputOrInitBody is non-null and inputOrInitBody’s
                                                                               [source](#concept-body-source "#concept-body-source") is null, then:

                                                                               1. If initBody is non-null and init["`duplex`"] does
                                                                                  not [exist](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then throw a `TypeError`.

                                                                                  - If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [mode](#concept-request-mode "#concept-request-mode") is neither
                                                                                    "`same-origin`" nor "`cors`", then throw a `TypeError`.

                                                                                    - Set [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s
                                                                                      [use-CORS-preflight flag](#use-cors-preflight-flag "#use-cors-preflight-flag").- Let finalBody be inputOrInitBody.

                                                                                 - If initBody is null and inputBody is non-null, then:

                                                                                   1. If inputBody is [unusable](#body-unusable "#body-unusable"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                                                                                      - Set finalBody to the result of [creating a proxy](https://streams.spec.whatwg.org/#readablestream-create-a-proxy "https://streams.spec.whatwg.org/#readablestream-create-a-proxy") for
                                                                                        inputBody.- Set [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [body](#concept-request-body "#concept-request-body") to
                                                                                     finalBody.

The `method` getter steps are to return [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
[request](#concept-request-request "#concept-request-request")’s [method](#concept-request-method "#concept-request-method").

The `url` getter steps are to return [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
[request](#concept-request-request "#concept-request-request")’s [URL](#concept-request-url "#concept-request-url"), [serialized](https://url.spec.whatwg.org/#concept-url-serializer "https://url.spec.whatwg.org/#concept-url-serializer").

The `headers` getter steps are to return
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers").

The `destination` getter are to return [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
[request](#concept-request-request "#concept-request-request")’s [destination](#concept-request-destination "#concept-request-destination").

The `referrer` getter steps are:

1. If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [referrer](#concept-request-referrer "#concept-request-referrer") is
   "`no-referrer`", then return the empty string.

   - If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [referrer](#concept-request-referrer "#concept-request-referrer") is
     "`client`", then return "`about:client`".

     - Return [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [referrer](#concept-request-referrer "#concept-request-referrer"),
       [serialized](https://url.spec.whatwg.org/#concept-url-serializer "https://url.spec.whatwg.org/#concept-url-serializer").

The `referrerPolicy` getter steps are to return
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy").

The `mode` getter steps are to return [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
[request](#concept-request-request "#concept-request-request")’s [mode](#concept-request-mode "#concept-request-mode").

The `credentials` getter steps are to return
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode").

The `cache` getter steps are to return [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
[request](#concept-request-request "#concept-request-request")’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode").

The `redirect` getter steps are to return
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode").

The `integrity` getter steps are to return
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [integrity metadata](#concept-request-integrity-metadata "#concept-request-integrity-metadata").

The `keepalive` getter steps are to return
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [keepalive](#request-keepalive-flag "#request-keepalive-flag").

The `isReloadNavigation` getter steps are to return
true if [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [reload-navigation flag](#concept-request-reload-navigation-flag "#concept-request-reload-navigation-flag") is set;
otherwise false.

The `isHistoryNavigation` getter steps are to return
true if [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request")’s [history-navigation flag](#concept-request-history-navigation-flag "#concept-request-history-navigation-flag") is
set; otherwise false.

The `signal` getter steps are to return [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
[signal](#request-signal "#request-signal").

[This](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [signal](#request-signal "#request-signal") is always initialized in the
[constructor](#signal-initialized-in-constructor "#signal-initialized-in-constructor") and when
[cloning](#signal-initialized-when-cloning "#signal-initialized-when-cloning").

The `duplex` getter steps are to return
"`half`".

---

The `clone()` method steps are:

1. If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") is [unusable](#body-unusable "#body-unusable"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

   - Let clonedRequest be the result of [cloning](#concept-request-clone "#concept-request-clone")
     [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [request](#concept-request-request "#concept-request-request").

     - [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [signal](#request-signal "#request-signal") is non-null.

       - Let clonedSignal be the result of [creating a dependent abort signal](https://dom.spec.whatwg.org/#create-a-dependent-abort-signal "https://dom.spec.whatwg.org/#create-a-dependent-abort-signal") from
         « [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [signal](#request-signal "#request-signal") », using `AbortSignal` and [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
         [relevant realm](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm").

         - Let clonedRequestObject be the result of [creating](#request-create "#request-create") a
           `Request` object, given clonedRequest, [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#request-headers "#request-headers")’s
           [guard](#concept-headers-guard "#concept-headers-guard"), clonedSignal and [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant realm](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm").

           - Return clonedRequestObject.

### 5.5. Response class

```
[Exposed=(Window,Worker)]
interface Response {
  constructor(optional BodyInit? body = null, optional ResponseInit init = {});

  [NewObject] static Response error();
  [NewObject] static Response redirect(USVString url, optional unsigned short status = 302);
  [NewObject] static Response json(any data, optional ResponseInit init = {});

  readonly attribute ResponseType type;

  readonly attribute USVString url;
  readonly attribute boolean redirected;
  readonly attribute unsigned short status;
  readonly attribute boolean ok;
  readonly attribute ByteString statusText;
  [SameObject] readonly attribute Headers headers;

  [NewObject] Response clone();
};
Response includes Body;

dictionary ResponseInit {
  unsigned short status = 200;
  ByteString statusText = "";
  HeadersInit headers;
};

enum ResponseType { "basic", "cors", "default", "error", "opaque", "opaqueredirect" };
```

A `Response` object has an associated
response (a
[response](#concept-response "#concept-response")).

A `Response` object also has an associated headers (null or a
`Headers` object), initially null.

A `Response` object’s [body](#concept-body-body "#concept-body-body") is its
[response](#concept-response-response "#concept-response-response")’s [body](#concept-response-body "#concept-response-body").

---

`response = new Response(body = null [, init])`: Creates a `Response` whose body is body, and status, status message, and headers are provided by init. `response = Response . error()`: Creates network error `Response`. `response = Response . redirect(url, status = 302)`: Creates a redirect `Response` that redirects to url with status status. `response = Response . json(data [, init])`: Creates a `Response` whose body is the JSON-encoded data, and status, status message, and headers are provided by init. `response . type`: Returns response’s type, e.g., "`cors`". `response . url`: Returns response’s URL, if it has one; otherwise the empty string. `response . redirected`: Returns whether response was obtained through a redirect. `response . status`: Returns response’s status. `response . ok`: Returns whether response’s status is an [ok status](#ok-status "#ok-status"). `response . statusText`: Returns response’s status message. `response . headers`: Returns response’s headers as `Headers`. `response . clone()`: Returns a clone of response.

---

To create a `Response` object, given a
[response](#concept-response "#concept-response") response, [headers guard](#headers-guard "#headers-guard") guard, and
[realm](https://tc39.es/ecma262/#realm "https://tc39.es/ecma262/#realm") realm, run these steps:

1. Let responseObject be a [new](https://webidl.spec.whatwg.org/#new "https://webidl.spec.whatwg.org/#new") `Response` object with
   realm.

   - Set responseObject’s [response](#concept-response-response "#concept-response-response") to response.

     - Set responseObject’s [headers](#response-headers "#response-headers") to a [new](https://webidl.spec.whatwg.org/#new "https://webidl.spec.whatwg.org/#new")
       `Headers` object with realm, whose [headers list](#concept-headers-header-list "#concept-headers-header-list") is
       response’s [headers list](#concept-response-header-list "#concept-response-header-list") and [guard](#concept-headers-guard "#concept-headers-guard") is
       guard.

       - Return responseObject.

To initialize a response, given a `Response` object response,
`ResponseInit` init, and null or a [body with type](#body-with-type "#body-with-type") body:

1. If init["`status`"] is not in the range 200 to 599, inclusive,
   then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `RangeError`.

   - If init["`statusText`"] is not the empty string and does not match
     the [reason-phrase](https://httpwg.org/specs/rfc9112.html#status.line "https://httpwg.org/specs/rfc9112.html#status.line") token production, then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

     - Set response’s [response](#concept-response-response "#concept-response-response")’s [status](#concept-response-status "#concept-response-status") to
       init["`status`"].

       - Set response’s [response](#concept-response-response "#concept-response-response")’s [status message](#concept-response-status-message "#concept-response-status-message")
         to init["`statusText`"].

         - If init["`headers`"] [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then
           [fill](#concept-headers-fill "#concept-headers-fill") response’s [headers](#response-headers "#response-headers") with
           init["`headers`"].

           - If body is non-null, then:

             1. If response’s [status](#concept-response-status "#concept-response-status") is a [null body status](#null-body-status "#null-body-status"), then
                [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

                101 and 103 are included in [null body status](#null-body-status "#null-body-status") due to their use elsewhere.
                They do not affect this step.

                - Set response’s [body](#concept-response-body "#concept-response-body") to body’s
                  [body](#body-with-type-body "#body-with-type-body").

                  - If body’s [type](#body-with-type-type "#body-with-type-type") is non-null and
                    response’s [header list](#concept-response-header-list "#concept-response-header-list") [does not contain](#header-list-contains "#header-list-contains")
                    ``Content-Type``, then [append](#concept-header-list-append "#concept-header-list-append") (``Content-Type``,
                    body’s [type](#body-with-type-type "#body-with-type-type")) to response’s
                    [header list](#concept-response-header-list "#concept-response-header-list").

---

The
`new Response(body, init)`
constructor steps are:

1. Set [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [response](#concept-response-response "#concept-response-response") to a new [response](#concept-response "#concept-response").

   - Set [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#response-headers "#response-headers") to a [new](https://webidl.spec.whatwg.org/#new "https://webidl.spec.whatwg.org/#new") `Headers` object with
     [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant realm](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm"), whose [header list](#concept-headers-header-list "#concept-headers-header-list") is [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
     [response](#concept-response-response "#concept-response-response")’s [header list](#concept-response-header-list "#concept-response-header-list") and [guard](#concept-headers-guard "#concept-headers-guard") is
     "`response`".

     - Let bodyWithType be null.

       - If body is non-null, then set bodyWithType to the result of
         [extracting](#concept-bodyinit-extract "#concept-bodyinit-extract") body.

         - Perform [initialize a response](#initialize-a-response "#initialize-a-response") given [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this"), init, and
           bodyWithType.

The static `error()` method steps are to return the
result of [creating](#response-create "#response-create") a `Response` object, given a new [network error](#concept-network-error "#concept-network-error"),
"`immutable`", and the [current realm](https://tc39.es/ecma262/#current-realm "https://tc39.es/ecma262/#current-realm").

The static
`redirect(url, status)` method steps
are:

1. Let parsedURL be the result of [parsing](https://url.spec.whatwg.org/#concept-url-parser "https://url.spec.whatwg.org/#concept-url-parser") url with
   [current settings object](https://html.spec.whatwg.org/multipage/webappapis.html#current-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#current-settings-object")’s [API base URL](https://html.spec.whatwg.org/multipage/webappapis.html#api-base-url "https://html.spec.whatwg.org/multipage/webappapis.html#api-base-url").

   - If parsedURL is failure, then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

     - If status is not a [redirect status](#redirect-status "#redirect-status"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `RangeError`.

       - Let responseObject be the result of [creating](#response-create "#response-create") a `Response`
         object, given a new [response](#concept-response "#concept-response"), "`immutable`", and the [current realm](https://tc39.es/ecma262/#current-realm "https://tc39.es/ecma262/#current-realm").

         - Set responseObject’s [response](#concept-response-response "#concept-response-response")’s [status](#concept-response-status "#concept-response-status") to
           status.

           - Let value be parsedURL, [serialized](https://url.spec.whatwg.org/#concept-url-serializer "https://url.spec.whatwg.org/#concept-url-serializer") and
             [isomorphic encoded](https://infra.spec.whatwg.org/#isomorphic-encode "https://infra.spec.whatwg.org/#isomorphic-encode").

             - [Append](#concept-header-list-append "#concept-header-list-append") (``Location``, value) to
               responseObject’s [response](#concept-response-response "#concept-response-response")’s [header list](#concept-response-header-list "#concept-response-header-list").

               - Return responseObject.

The static
`json(data, init)` method steps
are:

1. Let bytes the result of running [serialize a JavaScript value to JSON bytes](https://infra.spec.whatwg.org/#serialize-a-javascript-value-to-json-bytes "https://infra.spec.whatwg.org/#serialize-a-javascript-value-to-json-bytes")
   on data.

   - Let body be the result of [extracting](#concept-bodyinit-extract "#concept-bodyinit-extract") bytes.

     - Let responseObject be the result of [creating](#response-create "#response-create") a `Response`
       object, given a new [response](#concept-response "#concept-response"), "`response`", and the [current realm](https://tc39.es/ecma262/#current-realm "https://tc39.es/ecma262/#current-realm").

       - Perform [initialize a response](#initialize-a-response "#initialize-a-response") given responseObject, init, and
         (body, "`application/json`").

         - Return responseObject.

The `type` getter steps are to return [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s
[response](#concept-response-response "#concept-response-response")’s [type](#concept-response-type "#concept-response-type").

The `url` getter steps are to return
the empty string if [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [response](#concept-response-response "#concept-response-response")’s [URL](#concept-response-url "#concept-response-url") is null;
otherwise [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [response](#concept-response-response "#concept-response-response")’s [URL](#concept-response-url "#concept-response-url"),
[serialized](https://url.spec.whatwg.org/#concept-url-serializer "https://url.spec.whatwg.org/#concept-url-serializer") with [*exclude fragment*](https://url.spec.whatwg.org/#url-serializer-exclude-fragment "https://url.spec.whatwg.org/#url-serializer-exclude-fragment") set
to true.

The `redirected` getter steps are to return true if
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [response](#concept-response-response "#concept-response-response")’s [URL list](#concept-response-url-list "#concept-response-url-list")’s [size](https://infra.spec.whatwg.org/#list-size "https://infra.spec.whatwg.org/#list-size") is
greater than 1; otherwise false.

To filter out [responses](#concept-response "#concept-response") that are the result of a
redirect, do this directly through the API, e.g., `fetch(url, { redirect:"error" })`.
This way a potentially unsafe [response](#concept-response "#concept-response") cannot accidentally leak.

The `status` getter steps are to return
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [response](#concept-response-response "#concept-response-response")’s [status](#concept-response-status "#concept-response-status").

The `ok` getter steps are to return true if
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [response](#concept-response-response "#concept-response-response")’s [status](#concept-response-status "#concept-response-status") is an [ok status](#ok-status "#ok-status");
otherwise false.

The `statusText` getter steps are to return
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [response](#concept-response-response "#concept-response-response")’s [status message](#concept-response-status-message "#concept-response-status-message").

The `headers` getter steps are to return
[this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#response-headers "#response-headers").

---

The `clone()` method steps are:

1. If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this") is [unusable](#body-unusable "#body-unusable"), then [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `TypeError`.

   - Let clonedResponse be the result of [cloning](#concept-response-clone "#concept-response-clone")
     [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [response](#concept-response-response "#concept-response-response").

     - Return the result of [creating](#response-create "#response-create") a `Response` object, given
       clonedResponse, [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [headers](#response-headers "#response-headers")’s [guard](#concept-headers-guard "#concept-headers-guard"),
       and [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant realm](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm").

### 5.6. Fetch methods

```
partial interface mixin WindowOrWorkerGlobalScope {
  [NewObject] Promise<Response> fetch(RequestInfo input, optional RequestInit init = {});
};

dictionary DeferredRequestInit : RequestInit {
  DOMHighResTimeStamp activateAfter;
};

[Exposed=Window]
interface FetchLaterResult {
  readonly attribute boolean activated;
};

partial interface Window {
  [NewObject, SecureContext] FetchLaterResult fetchLater(RequestInfo input, optional DeferredRequestInit init = {});
};
```

The
`fetch(input, init)`
method steps are:

1. Let p be [a new promise](https://webidl.spec.whatwg.org/#a-new-promise "https://webidl.spec.whatwg.org/#a-new-promise").

   - Let requestObject be the result of invoking the initial value of `Request` as
     constructor with input and init as arguments. If this throws an exception,
     [reject](https://webidl.spec.whatwg.org/#reject "https://webidl.spec.whatwg.org/#reject") p with it and return p.

     - Let request be requestObject’s [request](#concept-request-request "#concept-request-request").

       - If requestObject’s [signal](#request-signal "#request-signal") is [aborted](https://dom.spec.whatwg.org/#abortsignal-aborted "https://dom.spec.whatwg.org/#abortsignal-aborted"),
         then:

         1. [Abort the `fetch()` call](#abort-fetch "#abort-fetch") with p, request, null, and
            requestObject’s [signal](#request-signal "#request-signal")’s [abort reason](https://dom.spec.whatwg.org/#abortsignal-abort-reason "https://dom.spec.whatwg.org/#abortsignal-abort-reason").

            - Return p.- Let globalObject be request’s [client](#concept-request-client "#concept-request-client")’s
           [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global").- If globalObject is a `ServiceWorkerGlobalScope` object,
             then set request’s [service-workers mode](#request-service-workers-mode "#request-service-workers-mode") to "`none`".- Let responseObject be null.

               - Let relevantRealm be [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant realm](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-realm").

                 - Let locallyAborted be false.

                   This lets us reject promises with predictable timing, when the request to abort
                   comes from the same thread as the call to fetch.

                   - Let controller be null.

                     - [Add the following abort steps](https://dom.spec.whatwg.org/#abortsignal-add "https://dom.spec.whatwg.org/#abortsignal-add") to requestObject’s
                       [signal](#request-signal "#request-signal"):

                       1. Set locallyAborted to true.

                          - [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): controller is non-null.

                            - [Abort](#fetch-controller-abort "#fetch-controller-abort") controller with requestObject’s
                              [signal](#request-signal "#request-signal")’s [abort reason](https://dom.spec.whatwg.org/#abortsignal-abort-reason "https://dom.spec.whatwg.org/#abortsignal-abort-reason").

                              - [Abort the `fetch()` call](#abort-fetch "#abort-fetch") with p, request,
                                responseObject, and requestObject’s [signal](#request-signal "#request-signal")’s
                                [abort reason](https://dom.spec.whatwg.org/#abortsignal-abort-reason "https://dom.spec.whatwg.org/#abortsignal-abort-reason").- Set controller to the result of calling [fetch](#concept-fetch "#concept-fetch") given
                         request and [*processResponse*](#process-response "#process-response") given response being
                         these steps:

                         1. If locallyAborted is true, then abort these steps.

                            - If response’s [aborted flag](#concept-response-aborted "#concept-response-aborted") is set, then:

                              1. Let deserializedError be the result of
                                 [deserialize a serialized abort reason](#deserialize-a-serialized-abort-reason "#deserialize-a-serialized-abort-reason") given controller’s
                                 [serialized abort reason](#fetch-controller-serialized-abort-reason "#fetch-controller-serialized-abort-reason") and relevantRealm.

                                 - [Abort the `fetch()` call](#abort-fetch "#abort-fetch") with p, request,
                                   responseObject, and deserializedError.

                                   - Abort these steps.- If response is a [network error](#concept-network-error "#concept-network-error"), then [reject](https://webidl.spec.whatwg.org/#reject "https://webidl.spec.whatwg.org/#reject") p
                                with a `TypeError` and abort these steps.

                                - Set responseObject to the result of [creating](#response-create "#response-create") a `Response`
                                  object, given response, "`immutable`", and relevantRealm.

                                  - [Resolve](https://webidl.spec.whatwg.org/#resolve "https://webidl.spec.whatwg.org/#resolve") p with responseObject.- Return p.

To abort a `fetch()` call
with a promise, request, responseObject, and an error:

1. [Reject](https://webidl.spec.whatwg.org/#reject "https://webidl.spec.whatwg.org/#reject") promise with error.

   This is a no-op if promise has already fulfilled.

   - If request’s [body](#concept-request-body "#concept-request-body") is non-null and is
     [readable](https://streams.spec.whatwg.org/#readablestream-readable "https://streams.spec.whatwg.org/#readablestream-readable"), then [cancel](https://streams.spec.whatwg.org/#readablestream-cancel "https://streams.spec.whatwg.org/#readablestream-cancel") request’s
     [body](#concept-request-body "#concept-request-body") with error.

     - If responseObject is null, then return.

       - Let response be responseObject’s [response](#concept-response-response "#concept-response-response").

         - If response’s [body](#concept-response-body "#concept-response-body") is non-null and is
           [readable](https://streams.spec.whatwg.org/#readablestream-readable "https://streams.spec.whatwg.org/#readablestream-readable"), then [error](https://streams.spec.whatwg.org/#readablestream-error "https://streams.spec.whatwg.org/#readablestream-error") response’s
           [body](#concept-response-body "#concept-response-body") with error.

A `FetchLaterResult` has an associated activated getter steps,
which is an algorithm returning a boolean.

The `activated` getter steps are to return
the result of running [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [activated getter steps](#fetchlaterresult-activated-getter-steps "#fetchlaterresult-activated-getter-steps").

The `fetchLater(input, init)`
method steps are:

1. Let requestObject be the result of invoking the initial value of `Request` as
   constructor with input and init as arguments.

   - If requestObject’s [signal](#request-signal "#request-signal") is [aborted](https://dom.spec.whatwg.org/#abortsignal-aborted "https://dom.spec.whatwg.org/#abortsignal-aborted"),
     then throw [signal](#request-signal "#request-signal")’s [abort reason](https://dom.spec.whatwg.org/#abortsignal-abort-reason "https://dom.spec.whatwg.org/#abortsignal-abort-reason").

     - Let request be requestObject’s [request](#concept-request-request "#concept-request-request").

       - Let activateAfter be null.

         - If init is given and init["`activateAfter`"]
           [exists](https://infra.spec.whatwg.org/#map-exists "https://infra.spec.whatwg.org/#map-exists"), then set activateAfter to
           init["`activateAfter`"].

           - If activateAfter is less than 0, then throw a `RangeError`.

             - If [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-relevant-global")’s [associated document](https://html.spec.whatwg.org/multipage/nav-history-apis.html#concept-document-window "https://html.spec.whatwg.org/multipage/nav-history-apis.html#concept-document-window") is not
               [fully active](https://html.spec.whatwg.org/multipage/document-sequences.html#fully-active "https://html.spec.whatwg.org/multipage/document-sequences.html#fully-active"), then throw a `TypeError`.

               - If request’s [URL](#concept-request-url "#concept-request-url")’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is not an
                 [HTTP(S) scheme](#http-scheme "#http-scheme"), then throw a `TypeError`.

                 - If request’s [URL](#concept-request-url "#concept-request-url") is not a [potentially trustworthy URL](https://w3c.github.io/webappsec-secure-contexts/#potentially-trustworthy-url "https://w3c.github.io/webappsec-secure-contexts/#potentially-trustworthy-url"),
                   then throw a `TypeError`.

                   - If request’s [body](#concept-request-body "#concept-request-body") is not null, and request’s
                     [body](#concept-request-body "#concept-request-body") [length](#concept-body-total-bytes "#concept-body-total-bytes") is null, then throw a `TypeError`.

                     Requests whose [body](#concept-request-body "#concept-request-body") is a `ReadableStream` object cannot be
                     deferred.

                     - Let quota be the [available deferred-fetch quota](#available-deferred-fetch-quota "#available-deferred-fetch-quota") given request’s
                       [client](#concept-request-client "#concept-request-client") and request’s [URL](#concept-request-url "#concept-request-url")’s [origin](https://url.spec.whatwg.org/#concept-url-origin "https://url.spec.whatwg.org/#concept-url-origin").

                       - Let requested be request’s [total request length](#total-request-length "#total-request-length").

                         - If quota is less than requested, then
                           [throw](https://webidl.spec.whatwg.org/#dfn-throw "https://webidl.spec.whatwg.org/#dfn-throw") a `QuotaExceededError` whose [quota](https://webidl.spec.whatwg.org/#quotaexceedederror-quota "https://webidl.spec.whatwg.org/#quotaexceedederror-quota") is
                           quota and [requested](https://webidl.spec.whatwg.org/#quotaexceedederror-requested "https://webidl.spec.whatwg.org/#quotaexceedederror-requested") is requested.

                           - Let activated be false.

                             - Let deferredRecord be the result of calling [queue a deferred fetch](#queue-a-deferred-fetch "#queue-a-deferred-fetch") given
                               request, activateAfter, and the following step: set activated to
                               true.

                               - [Add the following abort steps](https://dom.spec.whatwg.org/#abortsignal-add "https://dom.spec.whatwg.org/#abortsignal-add") to requestObject’s
                                 [signal](#request-signal "#request-signal"): Set deferredRecord’s
                                 [invoke state](#deferred-fetch-record-invoke-state "#deferred-fetch-record-invoke-state") to "`aborted`".

                                 - Return a new `FetchLaterResult` whose
                                   [activated getter steps](#fetchlaterresult-activated-getter-steps "#fetchlaterresult-activated-getter-steps") are to return activated.

The following call would queue a request to be fetched when the document is terminated:

```
fetchLater("https://report.example.com", {
  method: "POST",
  body: JSON.stringify(myReport),
  headers: { "Content-Type": "application/json" }
})
```

The following call would also queue this request after 5 seconds, and the returned value would
allow callers to observe if it was indeed activated. Note that the request is guaranteed to be
invoked, even in cases where the user agent throttles timers.

```
const result = fetchLater("https://report.example.com", {
  method: "POST",
  body: JSON.stringify(myReport),
  headers: { "Content-Type": "application/json" },
  activateAfter: 5000
});

function check_if_fetched() {
  return result.activated;
}
```

The `FetchLaterResult` object can be used together with an `AbortSignal`. For example:

```
let accumulated_events = [];
let previous_result = null;
const abort_signal = new AbortSignal();
function accumulate_event(event) {
  if (previous_result) {
    if (previous_result.activated) {
      // The request is already activated, we can start from scratch.
      accumulated_events = [];
    } else {
      // Abort this request, and start a new one with all the events.
      signal.abort();
    }
  }

  accumulated_events.push(event);
  result = fetchLater("https://report.example.com", {
    method: "POST",
    body: JSON.stringify(accumulated_events),
    headers: { "Content-Type": "application/json" },
    activateAfter: 5000,
    abort_signal
  });
}
```

Any of the following calls to [`fetchLater()`](#dom-window-fetchlater "#dom-window-fetchlater") would throw:

```
// Only potentially trustworthy URLs are supported.
fetchLater("http://untrusted.example.com");

// The length of the deferred request has to be known when.
fetchLater("https://origin.example.com", {body: someDynamicStream});

// Deferred fetching only works on active windows.
const detachedWindow = iframe.contentWindow;
iframe.remove();
detachedWindow.fetchLater("https://origin.example.com");
```

See [deferred fetch quota examples](#deferred-fetch-quota-examples "#deferred-fetch-quota-examples") for examples
portraying how the deferred-fetch quota works.

### 5.7. Garbage collection

The user agent may [terminate](#fetch-controller-terminate "#fetch-controller-terminate") an ongoing fetch if that termination
is not observable through script.

"Observable through script" means observable through
[`fetch()`](#dom-global-fetch "#dom-global-fetch")’s arguments and return value. Other ways, such as communicating
with the server through a side-channel are not included.

The server being able to observe garbage collection has precedent, e.g., with
`WebSocket` and `XMLHttpRequest` objects.

The user agent can terminate the fetch because the termination cannot be observed.

```
fetch("https://www.example.com/")
```

The user agent cannot terminate the fetch because the termination can be observed through
the promise.

```
window.promise = fetch("https://www.example.com/")
```

The user agent can terminate the fetch because the associated body is not observable.

```
window.promise = fetch("https://www.example.com/").then(res => res.headers)
```

The user agent can terminate the fetch because the termination cannot be observed.

```
fetch("https://www.example.com/").then(res => res.body.getReader().closed)
```

The user agent cannot terminate the fetch because one can observe the termination by registering
a handler for the promise object.

```
window.promise = fetch("https://www.example.com/")
  .then(res => res.body.getReader().closed)
```

The user agent cannot terminate the fetch as termination would be observable via the registered
handler.

```
fetch("https://www.example.com/")
  .then(res => {
    res.body.getReader().closed.then(() => console.log("stream closed!"))
  })
```

(The above examples of non-observability assume that built-in properties and functions, such as
`body.getReader()`, have not been overwritten.)

6. `data:` URLs
---------------

For an informative description of `data:` URLs, see RFC 2397. This section replaces
that RFC’s normative processing requirements to be compatible with deployed content. [[RFC2397]](#biblio-rfc2397 "The \"data\" URL scheme")

A `data:` URL struct is a [struct](https://infra.spec.whatwg.org/#struct "https://infra.spec.whatwg.org/#struct") that consists of a
MIME type (a [MIME type](https://mimesniff.spec.whatwg.org/#mime-type "https://mimesniff.spec.whatwg.org/#mime-type")) and a
body (a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence")).

The `data:` URL processor takes a [URL](https://url.spec.whatwg.org/#concept-url "https://url.spec.whatwg.org/#concept-url")
dataURL and then runs these steps:

1. [Assert](https://infra.spec.whatwg.org/#assert "https://infra.spec.whatwg.org/#assert"): dataURL’s [scheme](https://url.spec.whatwg.org/#concept-url-scheme "https://url.spec.whatwg.org/#concept-url-scheme") is "`data`".

   - Let input be the result of running the [URL serializer](https://url.spec.whatwg.org/#concept-url-serializer "https://url.spec.whatwg.org/#concept-url-serializer") on
     dataURL with [*exclude fragment*](https://url.spec.whatwg.org/#url-serializer-exclude-fragment "https://url.spec.whatwg.org/#url-serializer-exclude-fragment") set to true.

     - Remove the leading "`data:`" from input.

       - Let position point at the start of input.

         - Let mimeType be the result of [collecting a sequence of code points](https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points "https://infra.spec.whatwg.org/#collect-a-sequence-of-code-points") that
           are not equal to U+002C (,), given position.

           - [Strip leading and trailing ASCII whitespace](https://infra.spec.whatwg.org/#strip-leading-and-trailing-ascii-whitespace "https://infra.spec.whatwg.org/#strip-leading-and-trailing-ascii-whitespace") from mimeType.

             This will only remove U+0020 SPACE [code points](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point"), if any.

             - If position is past the end of input, then return failure.

               - Advance position by 1.

                 - Let encodedBody be the remainder of input.

                   - Let body be the [percent-decoding](https://url.spec.whatwg.org/#string-percent-decode "https://url.spec.whatwg.org/#string-percent-decode") of encodedBody.

                     - If mimeType ends with U+003B (;), followed by zero or more U+0020 SPACE, followed by
                       an [ASCII case-insensitive](https://infra.spec.whatwg.org/#ascii-case-insensitive "https://infra.spec.whatwg.org/#ascii-case-insensitive") match for "`base64`", then:

                       1. Let stringBody be the [isomorphic decode](https://infra.spec.whatwg.org/#isomorphic-decode "https://infra.spec.whatwg.org/#isomorphic-decode") of body.

                          - Set body to the [forgiving-base64 decode](https://infra.spec.whatwg.org/#forgiving-base64-decode "https://infra.spec.whatwg.org/#forgiving-base64-decode") of stringBody.

                            - If body is failure, then return failure.

                              - Remove the last 6 [code points](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") from mimeType.

                                - Remove trailing U+0020 SPACE [code points](https://infra.spec.whatwg.org/#code-point "https://infra.spec.whatwg.org/#code-point") from mimeType, if any.

                                  - Remove the last U+003B (;) from mimeType.- If mimeType [starts with](https://infra.spec.whatwg.org/#string-starts-with "https://infra.spec.whatwg.org/#string-starts-with") "`;`", then prepend
                         "`text/plain`" to mimeType.

                         - Let mimeTypeRecord be the result of [parsing](https://mimesniff.spec.whatwg.org/#parse-a-mime-type "https://mimesniff.spec.whatwg.org/#parse-a-mime-type")
                           mimeType.

                           - If mimeTypeRecord is failure, then set mimeTypeRecord to
                             `text/plain;charset=US-ASCII`.

                             - Return a new [`data:` URL struct](#data-url-struct "#data-url-struct") whose
                               [MIME type](#data-url-struct-mime-type "#data-url-struct-mime-type") is mimeTypeRecord and
                               [body](#data-url-struct-body "#data-url-struct-body") is body.

Background reading
------------------

*This section and its subsections are informative only.*

### HTTP header layer division

For the purposes of fetching, there is an API layer (HTML’s `img`, CSS’s
`background-image`), early fetch layer, service worker layer, and network & cache
layer. ``Accept`` and ``Accept-Language`` are set in the early fetch layer
(typically by the user agent). Most other headers controlled by the user agent, such as
``Accept-Encoding``, ``Host``, and ``Referer``, are set in the
network & cache layer. Developers can set headers either at the API layer or in the service
worker layer (typically through a `Request` object). Developers have almost no control over
[forbidden request-headers](#forbidden-request-header "#forbidden-request-header"), but can control ``Accept`` and have the means to
constrain and omit ``Referer`` for instance.

### Atomic HTTP redirect handling

Redirects (a [response](#concept-response "#concept-response") whose [status](#concept-response-status "#concept-response-status") or
[internal response](#concept-internal-response "#concept-internal-response")’s (if any) [status](#concept-response-status "#concept-response-status") is a
[redirect status](#redirect-status "#redirect-status")) are not exposed to APIs. Exposing redirects might leak information not
otherwise available through a cross-site scripting attack.

A fetch to `https://example.org/auth` that includes a
`Cookie` marked `HttpOnly` could result in a redirect to
`https://other-origin.invalid/4af955781ea1c84a3b11`. This new URL contains a
secret. If we expose redirects that secret would be available through a cross-site
scripting attack.

### Basic safe CORS protocol setup

For resources where data is protected through IP authentication or a firewall
(unfortunately relatively common still), using the [CORS protocol](#cors-protocol "#cors-protocol") is
**unsafe**. (This is the reason why the [CORS protocol](#cors-protocol "#cors-protocol") had to be
invented.)

However, otherwise using the following [header](#concept-header "#concept-header") is
**safe**:

```
Access-Control-Allow-Origin: *
```

Even if a resource exposes additional information based on cookie or HTTP
authentication, using the above [header](#concept-header "#concept-header") will not reveal
it. It will share the resource with APIs such as
`XMLHttpRequest`, much like it is already shared with
`curl` and `wget`.

Thus in other words, if a resource cannot be accessed from a random device connected to
the web using `curl` and `wget` the aforementioned
[header](#concept-header "#concept-header") is not to be included. If it can be accessed
however, it is perfectly fine to do so.

### CORS protocol and HTTP caches

If [CORS protocol](#cors-protocol "#cors-protocol") requirements are more complicated than setting
`[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` to `*` or a static
[origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin"), ``Vary`` is to be used.
[[HTML]](#biblio-html "HTML Standard") [[HTTP]](#biblio-http "HTTP Semantics") [[HTTP-CACHING]](#biblio-http-caching "HTTP Caching")

```
Vary: Origin
```

In particular, consider what happens if ``Vary`` is *not* used and a server is
configured to send `[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` for a certain
resource only in response to a [CORS request](#cors-request "#cors-request"). When a user agent receives a response to a
non-[CORS request](#cors-request "#cors-request") for that resource (for example, as the result of a [navigation
request](#navigation-request "#navigation-request")), the response will lack `[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")`
and the user agent will cache that response. Then, if the user agent subsequently encounters a
[CORS request](#cors-request "#cors-request") for the resource, it will use that cached response from the previous
non-[CORS request](#cors-request "#cors-request"), without `[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")`.

But if ``Vary: Origin`` is used in the same scenario described above, it will cause
the user agent to [fetch](#concept-fetch "#concept-fetch") a response that includes
`[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")`, rather than using the cached response
from the previous non-[CORS request](#cors-request "#cors-request") that lacks
`[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")`.

However, if `[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` is set to
`*` or a static [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin") for a particular resource, then configure the server
to always send `[`Access-Control-Allow-Origin`](#http-access-control-allow-origin "#http-access-control-allow-origin")` in responses for the
resource — for non-[CORS requests](#cors-request "#cors-request") as well as [CORS
requests](#cors-request "#cors-request") — and do not use ``Vary``.

### WebSockets

As part of establishing a connection, the `WebSocket` object initiates a special kind of
[fetch](#concept-fetch "#concept-fetch") (using a [request](#concept-request "#concept-request") whose [mode](#concept-request-mode "#concept-request-mode") is
"`websocket`") which allows it to share in many fetch policy decisions, such
HTTP Strict Transport Security (HSTS). Ultimately this results in fetch calling into
WebSockets to obtain a dedicated connection. [[WEBSOCKETS]](#biblio-websockets "WebSockets Standard")
[[HSTS]](#biblio-hsts "HTTP Strict Transport Security (HSTS)")

Fetch used to define
[obtain a WebSocket connection](https://websockets.spec.whatwg.org/#concept-websocket-connection-obtain "https://websockets.spec.whatwg.org/#concept-websocket-connection-obtain") and
[establish a WebSocket connection](https://websockets.spec.whatwg.org/#concept-websocket-establish "https://websockets.spec.whatwg.org/#concept-websocket-establish") directly, but
both are now defined in WebSockets. [[WEBSOCKETS]](#biblio-websockets "WebSockets Standard")

Using fetch in other standards
------------------------------

In its essence [fetching](#concept-fetch "#concept-fetch") is an exchange of a [request](#concept-request "#concept-request") for a
[response](#concept-response "#concept-response"). In reality it is rather complex mechanism for standards to adopt and use
correctly. This section aims to give some advice.

Always ask domain experts for review.

This is a work in progress.

### Setting up a request

The first step in [fetching](#concept-fetch "#concept-fetch") is to create a [request](#concept-request "#concept-request"), and populate its
[items](https://infra.spec.whatwg.org/#struct-item "https://infra.spec.whatwg.org/#struct-item").

Start by setting the [request](#concept-request "#concept-request")’s [URL](#concept-request-url "#concept-request-url") and [method](#concept-request-method "#concept-request-method"),
as defined by HTTP. If your ``POST`` or ``PUT`` [request](#concept-request "#concept-request") needs a
body, you set [request](#concept-request "#concept-request")’s [body](#concept-request-body "#concept-request-body") to a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"), or to
a new [body](#concept-body "#concept-body") whose [stream](#concept-body-stream "#concept-body-stream") is a `ReadableStream` you created. [[HTTP]](#biblio-http "HTTP Semantics")

Choose your [request](#concept-request "#concept-request")’s [destination](#concept-request-destination "#concept-request-destination") using the guidance in the
[destination table](#destination-table "#destination-table"). [Destinations](#concept-request-destination "#concept-request-destination") affect
Content Security Policy and have other implications such as the ``Sec-Fetch-Dest``
header, so they are much more than informative metadata. If a new feature requires a
[destination](#concept-request-destination "#concept-request-destination") that’s not in the [destination table](#destination-table "#destination-table"),
please
[file an issue](https://github.com/whatwg/fetch/issues/new?title=What%20destination%20should%20my%20feature%20use "https://github.com/whatwg/fetch/issues/new?title=What%20destination%20should%20my%20feature%20use")
to discuss. [[CSP]](#biblio-csp "Content Security Policy Level 3")

Set your [request](#concept-request "#concept-request")’s [client](#concept-request-client "#concept-request-client") to the
[environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object") you’re operating in. Web-exposed APIs are generally defined with
Web IDL, for which every object that implements an [interface](https://webidl.spec.whatwg.org/#dfn-interface "https://webidl.spec.whatwg.org/#dfn-interface") has a
[relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object") you can use. For example, a [request](#concept-request "#concept-request") associated with an
[element](https://dom.spec.whatwg.org/#concept-element "https://dom.spec.whatwg.org/#concept-element") would set the [request](#concept-request "#concept-request")’s [client](#concept-request-client "#concept-request-client") to the element’s
[node document](https://dom.spec.whatwg.org/#concept-node-document "https://dom.spec.whatwg.org/#concept-node-document")’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object"). All features that are directly web-exposed
by JavaScript, HTML, CSS, or other `Document` subresources should have a
[client](#concept-request-client "#concept-request-client").

If your [fetching](#concept-fetch "#concept-fetch") is not directly web-exposed, e.g., it is sent in the background
without relying on a current `Window` or `Worker`, leave [request](#concept-request "#concept-request")’s
[client](#concept-request-client "#concept-request-client") as null and set the [request](#concept-request "#concept-request")’s [origin](#concept-request-origin "#concept-request-origin"),
[policy container](#concept-request-policy-container "#concept-request-policy-container"), [service-workers mode](#request-service-workers-mode "#request-service-workers-mode"), and
[referrer](#concept-request-referrer "#concept-request-referrer") to appropriate values instead, e.g., by copying them from the
[environment settings object](https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#environment-settings-object") ahead of time. In these more advanced cases, make sure the
details of how your fetch handles Content Security Policy and
[referrer policy](https://w3c.github.io/webappsec-referrer-policy/#referrer-policy "https://w3c.github.io/webappsec-referrer-policy/#referrer-policy") are fleshed out. Also make sure you handle concurrency, as callbacks
(see [Invoking fetch and processing responses](#fetch-elsewhere-fetch "#fetch-elsewhere-fetch")) would be posted on a [parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue"). [[REFERRER]](#biblio-referrer "Referrer Policy") [[CSP]](#biblio-csp "Content Security Policy Level 3")

Think through the way you intend to handle cross-origin resources. Some features may only work in
the [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin "https://html.spec.whatwg.org/multipage/browsers.html#same-origin"), in which case set your [request](#concept-request "#concept-request")’s [mode](#concept-request-mode "#concept-request-mode") to
"`same-origin`". Otherwise, new web-exposed features should almost always set their
[mode](#concept-request-mode "#concept-request-mode") to "`cors`". If your feature is not web-exposed, or you think
there is another reason for it to fetch cross-origin resources without CORS, please
[file an issue](https://github.com/whatwg/fetch/issues/new?title=Does%20my%20request%20require%20CORS "https://github.com/whatwg/fetch/issues/new?title=Does%20my%20request%20require%20CORS")
to discuss.

For cross-origin requests, also determines if [credentials](#credentials "#credentials") are to be included with
the requests, in which case set your [request](#concept-request "#concept-request")’s [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode") to
"`include`".

Figure out if your fetch needs to be reported to Resource Timing, and with which
[initiator type](#request-initiator-type "#request-initiator-type"). By passing an [initiator type](#request-initiator-type "#request-initiator-type") to the
[request](#concept-request "#concept-request"), reporting to Resource Timing will be done automatically once the
fetch is done and the [response](#concept-response "#concept-response") is fully downloaded. [[RESOURCE-TIMING]](#biblio-resource-timing "Resource Timing")

If your request requires additional HTTP headers, set its [header list](#concept-request-header-list "#concept-request-header-list") to
a [header list](#concept-header-list "#concept-header-list") that contains those headers, e.g., « (``My-Header-Name``,
``My-Header-Value``) ». Sending custom headers may have implications, such as requiring a
[CORS-preflight fetch](#cors-preflight-fetch-0 "#cors-preflight-fetch-0"), so handle with care.

If you want to override the default caching mechanism, e.g., disable caching for this
[request](#concept-request "#concept-request"), set the request’s [cache mode](#concept-request-cache-mode "#concept-request-cache-mode") to a value other than
"`default`".

Determine whether you want your request to support redirects. If you don’t, set its
[redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") to "`error`".

Browse through the rest of the parameters for [request](#concept-request "#concept-request") to see if something else is
relevant to you. The rest of the parameters are used less frequently, often for special purposes,
and they are documented in detail in the [§ 2.2.5 Requests](#requests "#requests") section of this standard.

### Invoking fetch and processing responses

Aside from a [request](#concept-request "#concept-request") the [fetch](#concept-fetch "#concept-fetch") operation takes several optional
arguments. For those arguments that take an algorithm: the algorithm will be called from a task (or
in a [parallel queue](https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue "https://html.spec.whatwg.org/multipage/infrastructure.html#parallel-queue") if [*useParallelQueue*](#fetch-useparallelqueue "#fetch-useparallelqueue") is true).

Once the [request](#concept-request "#concept-request") is set up, to determine which algorithms to pass to
[fetch](#concept-fetch "#concept-fetch"), determine how you would like to process the [response](#concept-response "#concept-response"), and in
particular at what stage you would like to receive a callback:

Upon completion: This is how most callers handle a [response](#concept-response "#concept-response"), for example [scripts](https://html.spec.whatwg.org/multipage/webappapis.html#fetch-a-classic-script "https://html.spec.whatwg.org/multipage/webappapis.html#fetch-a-classic-script") and [style resources](https://drafts.csswg.org/css-values-4/#fetch-a-style-resource "https://drafts.csswg.org/css-values-4/#fetch-a-style-resource"). The [response](#concept-response "#concept-response")’s [body](#concept-response-body "#concept-response-body") is read in its entirety into a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"), and then processed by the caller. To process a [response](#concept-response "#concept-response") upon completion, pass an algorithm as the [*processResponseConsumeBody*](#process-response-end-of-body "#process-response-end-of-body") argument of [fetch](#concept-fetch "#concept-fetch"). The given algorithm is passed a [response](#concept-response "#concept-response") and an argument representing the fully read [body](#concept-response-body "#concept-response-body") (of the [response](#concept-response "#concept-response")’s [internal response](#concept-internal-response "#concept-internal-response")). The second argument’s values have the following meaning: null: The [response](#concept-response "#concept-response")’s [body](#concept-response-body "#concept-response-body") is null, due to the response being a [network error](#concept-network-error "#concept-network-error") or having a [null body status](#null-body-status "#null-body-status"). failure: Attempting to [fully read](#body-fully-read "#body-fully-read") the contents of the [response](#concept-response "#concept-response")’s [body](#concept-response-body "#concept-response-body") failed, e.g., due to an I/O error. a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence"): [Fully reading](#body-fully-read "#body-fully-read") the contents of the [response](#concept-response "#concept-response")’s [internal response](#concept-internal-response "#concept-internal-response")’s [body](#concept-response-body "#concept-response-body") succeeded. A [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") containing the full contents will be passed also for a [request](#concept-request "#concept-request") whose [mode](#concept-request-mode "#concept-request-mode") is "`no-cors`". Callers have to be careful when handling such content, as it should not be accessible to the requesting [origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin "https://html.spec.whatwg.org/multipage/browsers.html#concept-origin"). For example, the caller may use contents of a "`no-cors`" [response](#concept-response "#concept-response") to display image contents directly to the user, but those image contents should not be directly exposed to scripts in the embedding document. 1. Let request be a [request](#concept-request "#concept-request") whose [URL](#concept-request-url "#concept-request-url") is `https://stuff.example.com/` and [client](#concept-request-client "#concept-request-client") is [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object"). - [Fetch](#concept-fetch "#concept-fetch") request, with [*processResponseConsumeBody*](#process-response-end-of-body "#process-response-end-of-body") set to the following steps given a [response](#concept-response "#concept-response") response and null, failure, or a [byte sequence](https://infra.spec.whatwg.org/#byte-sequence "https://infra.spec.whatwg.org/#byte-sequence") contents: 1. If contents is null or failure, then present an error to the user. - Otherwise, parse contents considering the metadata from response, and perform your own operations on it. Headers first, then chunk-by-chunk: In some cases, for example when playing video or progressively loading images, callers might want to stream the response, and process it one chunk at a time. The [response](#concept-response "#concept-response") is handed over to the fetch caller once the headers are processed, and the caller continues from there. To process a [response](#concept-response "#concept-response") chunk-by-chunk, pass an algorithm to the [*processResponse*](#process-response "#process-response") argument of [fetch](#concept-fetch "#concept-fetch"). The given algorithm is passed a [response](#concept-response "#concept-response") when the response’s headers have been received and is responsible for reading the [response](#concept-response "#concept-response")’s [body](#concept-response-body "#concept-response-body")’s [stream](#concept-body-stream "#concept-body-stream") in order to download the rest of the response. For convenience, you may also pass an algorithm to the [*processResponseEndOfBody*](#fetch-processresponseendofbody "#fetch-processresponseendofbody") argument, which is called once you have finished fully reading the response and its [body](#concept-response-body "#concept-response-body"). Note that unlike [*processResponseConsumeBody*](#process-response-end-of-body "#process-response-end-of-body"), passing the [*processResponse*](#process-response "#process-response") or [*processResponseEndOfBody*](#fetch-processresponseendofbody "#fetch-processresponseendofbody") arguments does not guarantee that the response will be fully read, and callers are responsible to read it themselves. The [*processResponse*](#process-response "#process-response") argument is also useful for handling the [response](#concept-response "#concept-response")’s [header list](#concept-response-header-list "#concept-response-header-list") and [status](#concept-response-status "#concept-response-status") without handling the [body](#concept-response-body "#concept-response-body") at all. This is used, for example, when handling responses that do not have an [ok status](#ok-status "#ok-status"). 1. Let request be a [request](#concept-request "#concept-request") whose [URL](#concept-request-url "#concept-request-url") is `https://stream.example.com/` and [client](#concept-request-client "#concept-request-client") is [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object"). - [Fetch](#concept-fetch "#concept-fetch") request, with [*processResponse*](#process-response "#process-response") set to the following steps given a [response](#concept-response "#concept-response") response: 1. If response is a [network error](#concept-network-error "#concept-network-error"), then present an error to the user. - Otherwise, if response’s [status](#concept-response-status "#concept-response-status") is not an [ok status](#ok-status "#ok-status"), present some fallback value to the user. - Otherwise, [get a reader](https://streams.spec.whatwg.org/#readablestream-get-a-reader "https://streams.spec.whatwg.org/#readablestream-get-a-reader") for [response](#concept-response "#concept-response")’s [body](#concept-response-body "#concept-response-body")’s [stream](#concept-body-stream "#concept-body-stream"), and process in an appropriate way for the MIME type identified by [extracting a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type") from response’s [headers list](#concept-response-header-list "#concept-response-header-list"). Ignore the response: In some cases, there is no need for a [response](#concept-response "#concept-response") at all, e.g., in the case of `navigator.sendBeacon()`. Processing a response and passing callbacks to [fetch](#concept-fetch "#concept-fetch") is optional, so omitting the callback would [fetch](#concept-fetch "#concept-fetch") without expecting a response. In such cases, the [response](#concept-response "#concept-response")’s [body](#concept-response-body "#concept-response-body")’s [stream](#concept-body-stream "#concept-body-stream") will be discarded, and the caller does not have to worry about downloading the contents unnecessarily. [Fetch](#concept-fetch "#concept-fetch") a [request](#concept-request "#concept-request") whose [URL](#concept-request-url "#concept-request-url") is `https://fire-and-forget.example.com/`, [method](#concept-request-method "#concept-request-method") is ``POST``, and [client](#concept-request-client "#concept-request-client") is [this](https://webidl.spec.whatwg.org/#this "https://webidl.spec.whatwg.org/#this")’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object "https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object").

Apart from the callbacks to handle responses, [fetch](#concept-fetch "#concept-fetch") accepts additional callbacks
for advanced cases. [*processEarlyHintsResponse*](#fetch-processearlyhintsresponse "#fetch-processearlyhintsresponse") is intended specifically for
[responses](#concept-response "#concept-response") whose [status](#concept-response-status "#concept-response-status") is 103, and is currently handled only by
navigations. [*processRequestBodyChunkLength*](#process-request-body "#process-request-body") and
[*processRequestEndOfBody*](#process-request-end-of-body "#process-request-end-of-body") notify the caller of request body uploading
progress.

Note that the [fetch](#concept-fetch "#concept-fetch") operation starts in the same thread from which it was called,
and then breaks off to run its internal operations [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel"). The aforementioned callbacks
are posted to a given [event loop](https://html.spec.whatwg.org/multipage/webappapis.html#event-loop "https://html.spec.whatwg.org/multipage/webappapis.html#event-loop") which is, by default, the
[client](#concept-request-client "#concept-request-client")’s [global object](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global "https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-global"). To process
responses [in parallel](https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel "https://html.spec.whatwg.org/multipage/infrastructure.html#in-parallel") and handle interactions with the main thread by yourself,
[fetch](#concept-fetch "#concept-fetch") with [*useParallelQueue*](#fetch-useparallelqueue "#fetch-useparallelqueue") set to true.

### Manipulating an ongoing fetch

To manipulate a [fetch](#concept-fetch "#concept-fetch") operation that has already started, use the
[fetch controller](#fetch-controller "#fetch-controller") returned by calling [fetch](#concept-fetch "#concept-fetch"). For example, you may
[abort](#fetch-controller-abort "#fetch-controller-abort") the [fetch controller](#fetch-controller "#fetch-controller") due the user or page logic, or
[terminate](#fetch-controller-terminate "#fetch-controller-terminate") it due to browser-internal circumstances.

In addition to terminating and aborting, callers may [report timing](#finalize-and-report-timing "#finalize-and-report-timing")
if this was not done automatically by passing the [initiator type](#request-initiator-type "#request-initiator-type"), or
[extract full timing info](#extract-full-timing-info "#extract-full-timing-info") and handle it on the caller side (this is
done only by navigations). The [fetch controller](#fetch-controller "#fetch-controller") is also used to
[process the next manual redirect](#fetch-controller-process-the-next-manual-redirect "#fetch-controller-process-the-next-manual-redirect") for [requests](#concept-request "#concept-request") with
[redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode") set to "`manual`".

Acknowledgments
---------------

Thanks to
Adam Barth,
Adam Lavin,
Alan Jeffrey,
Alexey Proskuryakov,
Andreas Kling,
Andrés Gutiérrez,
Andrew Sutherland,
Andrew Williams,
Ángel González,
Anssi Kostiainen,
Arkadiusz Michalski,
Arne Johannessen,
Artem Skoretskiy,
Arthur Barstow,
Arthur Sonzogni,
Asanka Herath,
Axel Rauschmayer,
Ben Kelly,
Benjamin Gruenbaum,
Benjamin Hawkes-Lewis,
Benjamin VanderSloot,
Bert Bos,
Björn Höhrmann,
Boris Zbarsky,
Brad Hill,
Brad Porter,
Bryan Smith,
Caitlin Potter,
Cameron McCormack,
Carlo Cannas,
白丞祐 (Cheng-You Bai),
Chirag S Kumar,
Chris Needham,
Chris Rebert,
Clement Pellerin,
Collin Jackson,
Daniel Robertson,
Daniel Veditz,
Dave Tapuska,
David Benjamin,
David Håsäther,
David Orchard,
Dean Jackson,
Devdatta Akhawe,
Domenic Denicola,
Dominic Farolino,
Dominique Hazaël-Massieux,
Doug Turner,
Douglas Creager,
Eero Häkkinen,
Ehsan Akhgari,
Emily Stark,
Eric Lawrence,
Eric Orth,
Feng Yu,
François Marier,
Frank Ellerman,
Frederick Hirsch,
Frederik Braun,
Gary Blackwood,
Gavin Carothers,
Glenn Maynard,
Graham Klyne,
Gregory Terzian,
Guohui Deng(邓国辉),
Hal Lockhart,
Hallvord R. M. Steen,
Harris Hancock,
Henri Sivonen,
Henry Story,
Hiroshige Hayashizaki,
Honza Bambas,
Ian Hickson,
Ilya Grigorik,
isonmad,
Jake Archibald,
James Graham,
Jamie Mansfield,
Janusz Majnert,
Jeena Lee,
Jeff Carpenter,
Jeff Hodges,
Jeffrey Yasskin,
Jensen Chappell,
Jeremy Roman,
Jesse M. Heines,
Jianjun Chen,
Jinho Bang,
Jochen Eisinger,
John Wilander,
Jonas Sicking,
Jonathan Kingston,
Jonathan Watt,
최종찬 (Jongchan Choi),
Jordan Stephens,
Jörn Zaefferer,
Joseph Pecoraro,
Josh Matthews,
jub0bs,
Julian Krispel-Samsel,
Julian Reschke,
송정기 (Jungkee Song),
Jussi Kalliokoski,
Jxck,
Kagami Sascha Rosylight,
Keita Suzuki,
Keith Yeung,
Kenji Baheux,
Lachlan Hunt,
Larry Masinter,
Liam Brummitt,
Linus Groh,
Louis Ryan,
Luca Casonato,
Lucas Gonze,
Łukasz Anforowicz,
呂康豪 (Kang-Hao Lu),
Maciej Stachowiak,
Malisa,
Manfred Stock,
Manish Goregaokar,
Marc Silbey,
Marcos Caceres,
Marijn Kruisselbrink,
Mark Nottingham,
Mark S. Miller,
Martin Dürst,
Martin O’Neal,
Martin Thomson,
Matt Andrews,
Matt Falkenhagen,
Matt Menke,
Matt Oshry,
Matt Seddon,
Matt Womer,
Mhano Harkness,
Michael Ficarra,
Michael Kohler,
Michael™ Smith,
Mike Pennisi,
Mike West,
Mohamed Zergaoui,
Mohammed Zubair Ahmed,
Moritz Kneilmann,
Ms2ger,
Nico Schlömer,
Nicolás Peña Moreno,
Nidhi Jaju,
Nikhil Marathe,
Nikki Bee,
Nikunj Mehta,
Noam Rosenthal,
Odin Hørthe Omdal,
Olli Pettay,
Ondřej Žára,
O. Opsec,
Patrick Meenan,
Perry Jiang,
Philip Jägenstedt,
R. Auburn,
Raphael Kubo da Costa,
Robert Linder,
Rondinelly,
Rory Hewitt,
Ross A. Baker,
Ryan Sleevi,
Sam Atkins,
Samy Kamkar,
Sébastien Cevey,
Sendil Kumar N,
Shao-xuan Kang,
Sharath Udupa,
Shivakumar Jagalur Matt,
Shivani Sharma,
Sigbjørn Finne,
Simon Pieters,
Simon Sapin,
Simon Wülker,
Srirama Chandra Sekhar Mogali,
Stephan Paul,
Steven Salat,
Sunava Dutta,
Surya Ismail,
Tab Atkins-Bittner,
Takashi Toyoshima,
吉野剛史 (Takeshi Yoshino),
Thomas Roessler,
Thomas Steiner,
Thomas Wisniewski,
Tiancheng "Timothy" Gu,
Tobie Langel,
Tom Schuster,
Tomás Aparicio,
triple-underscore,
保呂毅 (Tsuyoshi Horo),
Tyler Close,
Ujjwal Sharma,
Vignesh Shanmugam,
Vladimir Dzhuvinov,
Wayne Carr,
Xabier Rodríguez,
Yehuda Katz,
Yoav Weiss,
Yoshisato Yanagisawa,
Youenn Fablet,
Yoichi Osato,
平野裕 (Yutaka Hirano), and
Zhenbin Xu
for being awesome.

This standard is written by [Anne van Kesteren](https://annevankesteren.nl/ "https://annevankesteren.nl/")
([Apple](https://www.apple.com/ "https://www.apple.com/"), [annevk@annevk.nl](mailto:annevk@annevk.nl "mailto:annevk@annevk.nl")).

Intellectual property rights
----------------------------

Copyright © WHATWG (Apple, Google, Mozilla, Microsoft). This work is licensed under a [Creative Commons Attribution 4.0
International License](https://creativecommons.org/licenses/by/4.0/ "https://creativecommons.org/licenses/by/4.0/"). To the extent portions of it are incorporated into source code, such
portions in the source code are licensed under the [BSD 3-Clause License](https://opensource.org/licenses/BSD-3-Clause "https://opensource.org/licenses/BSD-3-Clause") instead.

This is the Living Standard. Those
interested in the patent-review version should view the
[Living Standard Review Draft](/review-drafts/2025-12/ "/review-drafts/2025-12/").



Index
-----

### Terms defined by this specification

* [""](#dom-requestdestination "#dom-requestdestination"), in § 5.4* [ABNF](#abnf "#abnf"), in § 2* [abort](#fetch-controller-abort "#fetch-controller-abort"), in § 2* [aborted](#fetch-params-aborted "#fetch-params-aborted"), in § 2* [aborted flag](#concept-response-aborted "#concept-response-aborted"), in § 2.2.6* [aborted network error](#concept-aborted-network-error "#concept-aborted-network-error"), in § 2.2.6* [Abort the fetch() call](#abort-fetch "#abort-fetch"), in § 5.6* [Access-Control-Allow-Credentials](#http-access-control-allow-credentials "#http-access-control-allow-credentials"), in § 3.3.3* [Access-Control-Allow-Headers](#http-access-control-allow-headers "#http-access-control-allow-headers"), in § 3.3.3* [Access-Control-Allow-Methods](#http-access-control-allow-methods "#http-access-control-allow-methods"), in § 3.3.3* [Access-Control-Allow-Origin](#http-access-control-allow-origin "#http-access-control-allow-origin"), in § 3.3.3* [Access-Control-Expose-Headers](#http-access-control-expose-headers "#http-access-control-expose-headers"), in § 3.3.3* [Access-Control-Max-Age](#http-access-control-max-age "#http-access-control-max-age"), in § 3.3.3* [Access-Control-Request-Headers](#http-access-control-request-headers "#http-access-control-request-headers"), in § 3.3.2* [Access-Control-Request-Method](#http-access-control-request-method "#http-access-control-request-method"), in § 3.3.2* [activateAfter](#dom-deferredrequestinit-activateafter "#dom-deferredrequestinit-activateafter"), in § 5.6* [activated](#dom-fetchlaterresult-activated "#dom-fetchlaterresult-activated"), in § 5.6* [activated getter steps](#fetchlaterresult-activated-getter-steps "#fetchlaterresult-activated-getter-steps"), in § 5.6* [add a range header](#concept-request-add-range-header "#concept-request-add-range-header"), in § 2.2.5* [algorithm](#webtransport-hash-algorithm "#webtransport-hash-algorithm"), in § 2.2.5* [ALPN negotiated protocol](#connection-timing-info-alpn-negotiated-protocol "#connection-timing-info-alpn-negotiated-protocol"), in § 2.6* append
                                            + [dfn for Headers](#concept-headers-append "#concept-headers-append"), in § 5.1+ [dfn for header list](#concept-header-list-append "#concept-header-list-append"), in § 2.2.2* [append a request `Cookie` header](#append-a-request-cookie-header "#append-a-request-cookie-header"), in § 3.1.1* [append a request `Origin` header](#append-a-request-origin-header "#append-a-request-origin-header"), in § 3.2* [append(name, value)](#dom-headers-append "#dom-headers-append"), in § 5.1* [appropriate network error](#appropriate-network-error "#appropriate-network-error"), in § 2.2.6* [arrayBuffer()](#dom-body-arraybuffer "#dom-body-arraybuffer"), in § 5.3* [as a body](#byte-sequence-as-a-body "#byte-sequence-as-a-body"), in § 2.2.4* [Atomic HTTP redirect handling](#atomic-http-redirect-handling "#atomic-http-redirect-handling"), in § Unnumbered section* ["audio"](#dom-requestdestination-audio "#dom-requestdestination-audio"), in § 5.4* ["audioworklet"](#dom-requestdestination-audioworklet "#dom-requestdestination-audioworklet"), in § 5.4* [authentication entry](#authentication-entry "#authentication-entry"), in § 2.3* ["auto"](#dom-requestpriority-auto "#dom-requestpriority-auto"), in § 5.4* [available deferred-fetch quota](#available-deferred-fetch-quota "#available-deferred-fetch-quota"), in § 4.12.1* [bad port](#bad-port "#bad-port"), in § 2.9* ["basic"](#dom-responsetype-basic "#dom-responsetype-basic"), in § 5.5* [basic filtered response](#concept-filtered-response-basic "#concept-filtered-response-basic"), in § 2.2.6* [blob()](#dom-body-blob "#dom-body-blob"), in § 5.3* [block bad port](#block-bad-port "#block-bad-port"), in § 2.9* [Body](#body "#body"), in § 5.3* body
                                                                                  + [attribute for Body](#dom-body-body "#dom-body-body"), in § 5.3+ [definition of](#concept-body "#concept-body"), in § 2.2.4+ [dfn for Body](#concept-body-body "#concept-body-body"), in § 5.3+ [dfn for body with type](#body-with-type-body "#body-with-type-body"), in § 2.2.4+ [dfn for data: URL struct](#data-url-struct-body "#data-url-struct-body"), in § 6+ [dfn for request](#concept-request-body "#concept-request-body"), in § 2.2.5+ [dfn for response](#concept-response-body "#concept-response-body"), in § 2.2.6+ [dict-member for RequestInit](#dom-requestinit-body "#dom-requestinit-body"), in § 5.4* [body info](#concept-response-body-info "#concept-response-body-info"), in § 2.2.6* [BodyInit](#bodyinit "#bodyinit"), in § 5.2* [bodyUsed](#dom-body-bodyused "#dom-body-bodyused"), in § 5.3* [body with type](#body-with-type "#body-with-type"), in § 2.2.4* [build a content range](#build-a-content-range "#build-a-content-range"), in § 2.2.2* [bytes()](#dom-body-bytes "#dom-body-bytes"), in § 5.3* [byte-serialized origin](#concept-cache-origin "#concept-cache-origin"), in § 4.9* [Byte-serializing a request origin](#byte-serializing-a-request-origin "#byte-serializing-a-request-origin"), in § 2.2.5* cache
                                                                                                    + [attribute for Request](#dom-request-cache "#dom-request-cache"), in § 5.4+ [dict-member for RequestInit](#dom-requestinit-cache "#dom-requestinit-cache"), in § 5.4* [cache entry](#cache-entry "#cache-entry"), in § 4.9* [cache entry match](#concept-cache-match "#concept-cache-match"), in § 4.9* [cache mode](#concept-request-cache-mode "#concept-request-cache-mode"), in § 2.2.5* [cache state](#concept-response-cache-state "#concept-response-cache-state"), in § 2.2.6* [canceled](#fetch-params-canceled "#fetch-params-canceled"), in § 2* [clamp and coarsen connection timing info](#clamp-and-coarsen-connection-timing-info "#clamp-and-coarsen-connection-timing-info"), in § 2.6* [clear cache entries](#concept-cache-clear "#concept-cache-clear"), in § 4.9* [client](#concept-request-client "#concept-request-client"), in § 2.2.5* clone
                                                                                                                      + [dfn for body](#concept-body-clone "#concept-body-clone"), in § 2.2.4+ [dfn for request](#concept-request-clone "#concept-request-clone"), in § 2.2.5+ [dfn for response](#concept-response-clone "#concept-response-clone"), in § 2.2.6* clone()
                                                                                                                        + [method for Request](#dom-request-clone "#dom-request-clone"), in § 5.4+ [method for Response](#dom-response-clone "#dom-response-clone"), in § 5.5* [collect an HTTP quoted string](#collect-an-http-quoted-string "#collect-an-http-quoted-string"), in § 2.2* [collecting an HTTP quoted string](#collect-an-http-quoted-string "#collect-an-http-quoted-string"), in § 2.2* [combine](#concept-header-list-combine "#concept-header-list-combine"), in § 2.2.2* [connection](#concept-connection "#concept-connection"), in § 2.6* [connection end time](#connection-timing-info-connection-end-time "#connection-timing-info-connection-end-time"), in § 2.6* [connection pool](#concept-connection-pool "#concept-connection-pool"), in § 2.6* [connection start time](#connection-timing-info-connection-start-time "#connection-timing-info-connection-start-time"), in § 2.6* [connection timing info](#connection-timing-info "#connection-timing-info"), in § 2.6* constructor()
                                                                                                                                          + [constructor for Headers](#dom-headers "#dom-headers"), in § 5.1+ [constructor for Response](#dom-response "#dom-response"), in § 5.5* [constructor(body)](#dom-response "#dom-response"), in § 5.5* [constructor(body, init)](#dom-response "#dom-response"), in § 5.5* [constructor(init)](#dom-headers "#dom-headers"), in § 5.1* [constructor(input)](#dom-request "#dom-request"), in § 5.4* [constructor(input, init)](#dom-request "#dom-request"), in § 5.4* [consume body](#concept-body-consume-body "#concept-body-consume-body"), in § 5.3* [contains](#header-list-contains "#header-list-contains"), in § 2.2.2* [content encoding](#response-body-info-content-encoding "#response-body-info-content-encoding"), in § 2* [content type](#response-body-info-content-type "#response-body-info-content-type"), in § 2* controller
                                                                                                                                                              + [dfn for fetch params](#fetch-params-controller "#fetch-params-controller"), in § 2+ [dfn for fetch record](#concept-fetch-record-fetch "#concept-fetch-record-fetch"), in § 2.4* [convert header names to a sorted-lowercase set](#convert-header-names-to-a-sorted-lowercase-set "#convert-header-names-to-a-sorted-lowercase-set"), in § 2.2.2* "cors"
                                                                                                                                                                  + [enum-value for RequestMode](#dom-requestmode-cors "#dom-requestmode-cors"), in § 5.4+ [enum-value for ResponseType](#dom-responsetype-cors "#dom-responsetype-cors"), in § 5.5* [CORS check](#concept-cors-check "#concept-cors-check"), in § 4.10* [CORS-exposed header-name list](#concept-response-cors-exposed-header-name-list "#concept-response-cors-exposed-header-name-list"), in § 2.2.6* [CORS filtered response](#concept-filtered-response-cors "#concept-filtered-response-cors"), in § 2.2.6* [CORS non-wildcard request-header name](#cors-non-wildcard-request-header-name "#cors-non-wildcard-request-header-name"), in § 2.2.2* [CORS-preflight cache](#concept-cache "#concept-cache"), in § 4.9* [CORS-preflight fetch](#cors-preflight-fetch-0 "#cors-preflight-fetch-0"), in § 4.8* [CORS-preflight request](#cors-preflight-request "#cors-preflight-request"), in § 3.3.2* [CORS protocol](#cors-protocol "#cors-protocol"), in § 3.3* [CORS request](#cors-request "#cors-request"), in § 3.3.2* [CORS-safelisted method](#cors-safelisted-method "#cors-safelisted-method"), in § 2.2.1* [CORS-safelisted request-header](#cors-safelisted-request-header "#cors-safelisted-request-header"), in § 2.2.2* [CORS-safelisted response-header name](#cors-safelisted-response-header-name "#cors-safelisted-response-header-name"), in § 2.2.2* [CORS-unsafe request-header byte](#cors-unsafe-request-header-byte "#cors-unsafe-request-header-byte"), in § 2.2.2* [CORS-unsafe request-header names](#cors-unsafe-request-header-names "#cors-unsafe-request-header-names"), in § 2.2.2* create
                                                                                                                                                                                                + [dfn for Request](#request-create "#request-create"), in § 5.4+ [dfn for Response](#response-create "#response-create"), in § 5.5* [create a connection](#create-a-connection "#create-a-connection"), in § 2.6* [create a new cache entry](#concept-cache-create-entry "#concept-cache-create-entry"), in § 4.9* [create an opaque timing info](#create-an-opaque-timing-info "#create-an-opaque-timing-info"), in § 2* creating
                                                                                                                                                                                                        + [dfn for Request](#request-create "#request-create"), in § 5.4+ [dfn for Response](#response-create "#response-create"), in § 5.5* [creating an opaque timing info](#create-an-opaque-timing-info "#create-an-opaque-timing-info"), in § 2* [Credentials](#credentials "#credentials"), in § 2* credentials
                                                                                                                                                                                                              + [attribute for Request](#dom-request-credentials "#dom-request-credentials"), in § 5.4+ [dfn for cache entry](#concept-cache-credentials "#concept-cache-credentials"), in § 4.9+ [dfn for connection](#connection-credentials "#connection-credentials"), in § 2.6+ [dict-member for RequestInit](#dom-requestinit-credentials "#dom-requestinit-credentials"), in § 5.4* [credentials mode](#concept-request-credentials-mode "#concept-request-credentials-mode"), in § 2.2.5* [Cross-Origin-Embedder-Policy allows credentials](#cross-origin-embedder-policy-allows-credentials "#cross-origin-embedder-policy-allows-credentials"), in § 2.2.5* [cross-origin isolated capability](#fetch-params-cross-origin-isolated-capability "#fetch-params-cross-origin-isolated-capability"), in § 2* [Cross-Origin-Resource-Policy](#http-cross-origin-resource-policy "#http-cross-origin-resource-policy"), in § 3.7* [cross-origin resource policy check](#cross-origin-resource-policy-check "#cross-origin-resource-policy-check"), in § 3.7* [cross-origin resource policy internal check](#cross-origin-resource-policy-internal-check "#cross-origin-resource-policy-internal-check"), in § 3.7* [cryptographic nonce metadata](#concept-request-nonce-metadata "#concept-request-nonce-metadata"), in § 2.2.5* [current URL](#concept-request-current-url "#concept-request-current-url"), in § 2.2.5* [data: URL processor](#data-url-processor "#data-url-processor"), in § 6* [data: URL struct](#data-url-struct "#data-url-struct"), in § 6* [dec-octet](#dec-octet "#dec-octet"), in § 3.2* [decoded size](#fetch-timing-info-decoded-body-size "#fetch-timing-info-decoded-body-size"), in § 2* "default"
                                                                                                                                                                                                                                        + [enum-value for RequestCache](#dom-requestcache-default "#dom-requestcache-default"), in § 5.4+ [enum-value for ResponseType](#dom-responsetype-default "#dom-responsetype-default"), in § 5.5* [default `User-Agent` value](#default-user-agent-value "#default-user-agent-value"), in § 2.2.2* [deferred-fetch](#dom-permissionspolicy-deferred-fetch "#dom-permissionspolicy-deferred-fetch"), in § 4.12.1* [deferred-fetch control document](#deferred-fetch-control-document "#deferred-fetch-control-document"), in § 4.12.1* [deferred-fetch-minimal](#dom-permissionspolicy-deferred-fetch-minimal "#dom-permissionspolicy-deferred-fetch-minimal"), in § 4.12.1* [deferred fetch record](#deferred-fetch-record "#deferred-fetch-record"), in § 2.4* [deferred fetch records](#fetch-group-deferred-fetch-records "#fetch-group-deferred-fetch-records"), in § 2.4* [deferred fetch task source](#deferred-fetch-task-source "#deferred-fetch-task-source"), in § 4.12* [DeferredRequestInit](#dictdef-deferredrequestinit "#dictdef-deferredrequestinit"), in § 5.6* [delete](#concept-header-list-delete "#concept-header-list-delete"), in § 2.2.2* [delete(name)](#dom-headers-delete "#dom-headers-delete"), in § 5.1* [deserialize a serialized abort reason](#deserialize-a-serialized-abort-reason "#deserialize-a-serialized-abort-reason"), in § 2* destination
                                                                                                                                                                                                                                                                + [attribute for Request](#dom-request-destination "#dom-request-destination"), in § 5.4+ [dfn for request](#concept-request-destination "#concept-request-destination"), in § 2.2.5* [destination type](#destination-type "#destination-type"), in § 2.2.5* [determine nosniff](#determine-nosniff "#determine-nosniff"), in § 3.6* [determine the environment](#request-determine-the-environment "#request-determine-the-environment"), in § 4.3* [determine the HTTP cache partition](#determine-the-http-cache-partition "#determine-the-http-cache-partition"), in § 2.8* determine the network partition key
                                                                                                                                                                                                                                                                          + [definition of](#determine-the-network-partition-key "#determine-the-network-partition-key"), in § 2.7+ [dfn for request](#request-determine-the-network-partition-key "#request-determine-the-network-partition-key"), in § 2.7* [determine the same-site mode](#determine-the-same-site-mode "#determine-the-same-site-mode"), in § 3.1.3* ["document"](#dom-requestdestination-document "#dom-requestdestination-document"), in § 5.4* [document `Accept` header value](#document-accept-header-value "#document-accept-header-value"), in § 2.2.2* [does not contain](#header-list-contains "#header-list-contains"), in § 2.2.2* [domain-label](#domain-label "#domain-label"), in § 3.2* [domain lookup end time](#connection-timing-info-domain-lookup-end-time "#connection-timing-info-domain-lookup-end-time"), in § 2.6* [domain lookup start time](#connection-timing-info-domain-lookup-start-time "#connection-timing-info-domain-lookup-start-time"), in § 2.6* [done flag](#done-flag "#done-flag"), in § 2.2.5* duplex
                                                                                                                                                                                                                                                                                            + [attribute for Request](#dom-request-duplex "#dom-request-duplex"), in § 5.4+ [dict-member for RequestInit](#dom-requestinit-duplex "#dom-requestinit-duplex"), in § 5.4* ["embed"](#dom-requestdestination-embed "#dom-requestdestination-embed"), in § 5.4* [encoded size](#fetch-timing-info-encoded-body-size "#fetch-timing-info-encoded-body-size"), in § 2* [end time](#fetch-timing-info-end-time "#fetch-timing-info-end-time"), in § 2* [environment default `User-Agent` value](#environment-default-user-agent-value "#environment-default-user-agent-value"), in § 2.2.2* "error"
                                                                                                                                                                                                                                                                                                      + [enum-value for RequestRedirect](#dom-requestredirect-error "#dom-requestredirect-error"), in § 5.4+ [enum-value for ResponseType](#dom-responsetype-error "#dom-responsetype-error"), in § 5.5* [error()](#dom-response-error "#dom-response-error"), in § 5.5* [extract](#concept-bodyinit-extract "#concept-bodyinit-extract"), in § 5.2* [extract a length](#header-list-extract-a-length "#header-list-extract-a-length"), in § 3.4* [extract a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type"), in § 3.5* [extract full timing info](#extract-full-timing-info "#extract-full-timing-info"), in § 2* [extract header list values](#extract-header-list-values "#extract-header-list-values"), in § 2.2.2* [extract header values](#extract-header-values "#extract-header-values"), in § 2.2.2* [extracting a length](#header-list-extract-a-length "#header-list-extract-a-length"), in § 3.4* [extracting a MIME type](#concept-header-extract-mime-type "#concept-header-extract-mime-type"), in § 3.5* [extracting header list values](#extract-header-list-values "#extract-header-list-values"), in § 2.2.2* [extracting header values](#extract-header-values "#extract-header-values"), in § 2.2.2* [fetch](#concept-fetch "#concept-fetch"), in § 4* [fetch controller](#fetch-controller "#fetch-controller"), in § 2* fetch group
                                                                                                                                                                                                                                                                                                                                  + [definition of](#concept-fetch-group "#concept-fetch-group"), in § 2.4+ [dfn for environment settings object](#environment-settings-object-fetch-group "#environment-settings-object-fetch-group"), in § 2.4* [fetch(input)](#dom-global-fetch "#dom-global-fetch"), in § 5.6* [fetch(input, init)](#dom-global-fetch "#dom-global-fetch"), in § 5.6* [fetchLater(input)](#dom-window-fetchlater "#dom-window-fetchlater"), in § 5.6* [fetchLater(input, init)](#dom-window-fetchlater "#dom-window-fetchlater"), in § 5.6* [FetchLaterResult](#fetchlaterresult "#fetchlaterresult"), in § 5.6* [fetch params](#fetch-params "#fetch-params"), in § 2* [fetch record](#fetch-record "#fetch-record"), in § 2.4* [fetch records](#concept-fetch-record "#concept-fetch-record"), in § 2.4* [fetch response handover](#fetch-finale "#fetch-finale"), in § 4.1* [fetch scheme](#fetch-scheme "#fetch-scheme"), in § 2.1* [fetch timing info](#fetch-timing-info "#fetch-timing-info"), in § 2* [fill](#concept-headers-fill "#concept-headers-fill"), in § 5.1* [filtered response](#concept-filtered-response "#concept-filtered-response"), in § 2.2.6* [final connection timing info](#fetch-timing-info-final-connection-timing-info "#fetch-timing-info-final-connection-timing-info"), in § 2* [final network-request start time](#fetch-timing-info-final-network-request-start-time "#fetch-timing-info-final-network-request-start-time"), in § 2* [final network-response start time](#fetch-timing-info-final-network-response-start-time "#fetch-timing-info-final-network-response-start-time"), in § 2* [final service worker start time](#fetch-timing-info-final-service-worker-start-time "#fetch-timing-info-final-service-worker-start-time"), in § 2* [first interim network-response start time](#fetch-timing-info-first-interim-network-response-start-time "#fetch-timing-info-first-interim-network-response-start-time"), in § 2* ["follow"](#dom-requestredirect-follow "#dom-requestredirect-follow"), in § 5.4* ["font"](#dom-requestdestination-font "#dom-requestdestination-font"), in § 5.4* [forbidden method](#forbidden-method "#forbidden-method"), in § 2.2.1* [forbidden request-header](#forbidden-request-header "#forbidden-request-header"), in § 2.2.2* [forbidden response-header name](#forbidden-response-header-name "#forbidden-response-header-name"), in § 2.2.2* ["force-cache"](#dom-requestcache-force-cache "#dom-requestcache-force-cache"), in § 5.4* [formData()](#dom-body-formdata "#dom-body-formdata"), in § 5.3* ["frame"](#dom-requestdestination-frame "#dom-requestdestination-frame"), in § 5.4* [fresh response](#concept-fresh-response "#concept-fresh-response"), in § 2.2.6* [full timing info](#fetch-controller-full-timing-info "#fetch-controller-full-timing-info"), in § 2* [fully read](#body-fully-read "#body-fully-read"), in § 2.2.4* [get](#concept-header-list-get "#concept-header-list-get"), in § 2.2.2* [get a structured field value](#concept-header-list-get-structured-header "#concept-header-list-get-structured-header"), in § 2.2.2* get, decode, and split
                                                                                                                                                                                                                                                                                                                                                                                                  + [dfn for header list](#concept-header-list-get-decode-split "#concept-header-list-get-decode-split"), in § 2.2.2+ [dfn for header value](#header-value-get-decode-and-split "#header-value-get-decode-and-split"), in § 2.2.2* [get(name)](#dom-headers-get "#dom-headers-get"), in § 5.1* [getSetCookie()](#dom-headers-getsetcookie "#dom-headers-getsetcookie"), in § 5.1* [get the MIME type](#concept-body-mime-type "#concept-body-mime-type"), in § 5.3* getting, decoding, and splitting
                                                                                                                                                                                                                                                                                                                                                                                                          + [dfn for header list](#concept-header-list-get-decode-split "#concept-header-list-get-decode-split"), in § 2.2.2+ [dfn for header value](#header-value-get-decode-and-split "#header-value-get-decode-and-split"), in § 2.2.2* [guard](#concept-headers-guard "#concept-headers-guard"), in § 5.1* [h16](#h16 "#h16"), in § 3.2* ["half"](#dom-requestduplex-half "#dom-requestduplex-half"), in § 5.4* [handle content codings](#handle-content-codings "#handle-content-codings"), in § 2.2.4* [has(name)](#dom-headers-has "#dom-headers-has"), in § 5.1* [header](#concept-header "#concept-header"), in § 2.2.2* header list
                                                                                                                                                                                                                                                                                                                                                                                                                        + [definition of](#concept-header-list "#concept-header-list"), in § 2.2.2+ [dfn for Headers](#concept-headers-header-list "#concept-headers-header-list"), in § 5.1+ [dfn for request](#concept-request-header-list "#concept-request-header-list"), in § 2.2.5+ [dfn for response](#concept-response-header-list "#concept-response-header-list"), in § 2.2.6* header name
                                                                                                                                                                                                                                                                                                                                                                                                                          + [definition of](#header-name "#header-name"), in § 2.2.2+ [dfn for cache entry](#concept-cache-header-name "#concept-cache-header-name"), in § 4.9* [header-name cache entry match](#concept-cache-match-header "#concept-cache-match-header"), in § 4.9* [Headers](#headers "#headers"), in § 5.1* headers
                                                                                                                                                                                                                                                                                                                                                                                                                                + [attribute for Request](#dom-request-headers "#dom-request-headers"), in § 5.4+ [attribute for Response](#dom-response-headers "#dom-response-headers"), in § 5.5+ [dfn for Request](#request-headers "#request-headers"), in § 5.4+ [dfn for Response](#response-headers "#response-headers"), in § 5.5+ [dict-member for RequestInit](#dom-requestinit-headers "#dom-requestinit-headers"), in § 5.4+ [dict-member for ResponseInit](#dom-responseinit-headers "#dom-responseinit-headers"), in § 5.5* [Headers()](#dom-headers "#dom-headers"), in § 5.1* [headers guard](#headers-guard "#headers-guard"), in § 5.1* [Headers(init)](#dom-headers "#dom-headers"), in § 5.1* [HeadersInit](#typedefdef-headersinit "#typedefdef-headersinit"), in § 5.1* [header value](#header-value "#header-value"), in § 2.2.2* [hex](#hex "#hex"), in § 3.2* ["high"](#dom-requestpriority-high "#dom-requestpriority-high"), in § 5.4* [history-navigation flag](#concept-request-history-navigation-flag "#concept-request-history-navigation-flag"), in § 2.2.5* [HTTP fetch](#concept-http-fetch "#concept-http-fetch"), in § 4.4* [HTTP header layer division](#http-header-layer-division "#http-header-layer-division"), in § Unnumbered section* [HTTP-network fetch](#concept-http-network-fetch "#concept-http-network-fetch"), in § 4.7* [HTTP-network-or-cache fetch](#concept-http-network-or-cache-fetch "#concept-http-network-or-cache-fetch"), in § 4.6* [HTTP newline byte](#http-newline-byte "#http-newline-byte"), in § 2.2* [HTTP-redirect fetch](#concept-http-redirect-fetch "#concept-http-redirect-fetch"), in § 4.5* [HTTP(S) scheme](#http-scheme "#http-scheme"), in § 2.1* [HTTP tab or space](#http-tab-or-space "#http-tab-or-space"), in § 2.2* [HTTP tab or space byte](#http-tab-or-space-byte "#http-tab-or-space-byte"), in § 2.2* [HTTP whitespace](#http-whitespace "#http-whitespace"), in § 2.2* [HTTP whitespace byte](#http-whitespace-byte "#http-whitespace-byte"), in § 2.2* ["iframe"](#dom-requestdestination-iframe "#dom-requestdestination-iframe"), in § 5.4* ["image"](#dom-requestdestination-image "#dom-requestdestination-image"), in § 5.4* ["include"](#dom-requestcredentials-include "#dom-requestcredentials-include"), in § 5.4* [incrementally read](#body-incrementally-read "#body-incrementally-read"), in § 2.2.4* [incrementally-read loop](#incrementally-read-loop "#incrementally-read-loop"), in § 2.2.4* [initialize a response](#initialize-a-response "#initialize-a-response"), in § 5.5* [initiator](#concept-request-initiator "#concept-request-initiator"), in § 2.2.5* [initiator type](#request-initiator-type "#request-initiator-type"), in § 2.2.5* integrity
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        + [attribute for Request](#dom-request-integrity "#dom-request-integrity"), in § 5.4+ [dict-member for RequestInit](#dom-requestinit-integrity "#dom-requestinit-integrity"), in § 5.4* [integrity metadata](#concept-request-integrity-metadata "#concept-request-integrity-metadata"), in § 2.2.5* [internal priority](#request-internal-priority "#request-internal-priority"), in § 2.2.5* [internal response](#concept-internal-response "#concept-internal-response"), in § 2.2.6* [invoke state](#deferred-fetch-record-invoke-state "#deferred-fetch-record-invoke-state"), in § 2.4* [isHistoryNavigation](#dom-request-ishistorynavigation "#dom-request-ishistorynavigation"), in § 5.4* [is local](#is-local "#is-local"), in § 2.1* [is offline](#is-offline "#is-offline"), in § 2* [isReloadNavigation](#dom-request-isreloadnavigation "#dom-request-isreloadnavigation"), in § 5.4* ["json"](#dom-requestdestination-json "#dom-requestdestination-json"), in § 5.4* [json()](#dom-body-json "#dom-body-json"), in § 5.3* [json(data)](#dom-response-json "#dom-response-json"), in § 5.5* [json(data, init)](#dom-response-json "#dom-response-json"), in § 5.5* keepalive
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  + [attribute for Request](#dom-request-keepalive "#dom-request-keepalive"), in § 5.4+ [dfn for BodyInit/extract](#keepalive "#keepalive"), in § 5.2+ [dfn for request](#request-keepalive-flag "#request-keepalive-flag"), in § 2.2.5+ [dict-member for RequestInit](#dom-requestinit-keepalive "#dom-requestinit-keepalive"), in § 5.4* key
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    + [dfn for cache entry](#concept-cache-key "#concept-cache-key"), in § 4.9+ [dfn for connection](#connection-key "#connection-key"), in § 2.6* [legacy extract an encoding](#legacy-extract-an-encoding "#legacy-extract-an-encoding"), in § 3.5* [length](#concept-body-total-bytes "#concept-body-total-bytes"), in § 2.2.4* [local scheme](#local-scheme "#local-scheme"), in § 2.1* [local-URLs-only flag](#local-urls-only-flag "#local-urls-only-flag"), in § 2.2.5* [location URL](#concept-response-location-url "#concept-response-location-url"), in § 2.2.6* ["low"](#dom-requestpriority-low "#dom-requestpriority-low"), in § 5.4* [lower-alpha](#lower-alpha "#lower-alpha"), in § 3.2* [lower-alphanum](#lower-alphanum "#lower-alphanum"), in § 3.2* [main fetch](#concept-main-fetch "#concept-main-fetch"), in § 4.1* ["manifest"](#dom-requestdestination-manifest "#dom-requestdestination-manifest"), in § 5.4* ["manual"](#dom-requestredirect-manual "#dom-requestredirect-manual"), in § 5.4* [max-age](#concept-cache-max-age "#concept-cache-max-age"), in § 4.9* method
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              + [attribute for Request](#dom-request-method "#dom-request-method"), in § 5.4+ [definition of](#concept-method "#concept-method"), in § 2.2.1+ [dfn for cache entry](#concept-cache-method "#concept-cache-method"), in § 4.9+ [dfn for request](#concept-request-method "#concept-request-method"), in § 2.2.5+ [dict-member for RequestInit](#dom-requestinit-method "#dom-requestinit-method"), in § 5.4* [method cache entry match](#concept-cache-match-method "#concept-cache-match-method"), in § 4.9* [MIME type](#data-url-struct-mime-type "#data-url-struct-mime-type"), in § 6* [minimal quota](#reserved-deferred-fetch-quota-minimal-quota "#reserved-deferred-fetch-quota-minimal-quota"), in § 4.12.1* mode
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      + [attribute for Request](#dom-request-mode "#dom-request-mode"), in § 5.4+ [dfn for request](#concept-request-mode "#concept-request-mode"), in § 2.2.5+ [dict-member for RequestInit](#dom-requestinit-mode "#dom-requestinit-mode"), in § 5.4* [name](#concept-header-name "#concept-header-name"), in § 2.2.2* ["navigate"](#dom-requestmode-navigate "#dom-requestmode-navigate"), in § 5.4* [navigation request](#navigation-request "#navigation-request"), in § 2.2.5* [network error](#concept-network-error "#concept-network-error"), in § 2.2.6* [network partition key](#network-partition-key "#network-partition-key"), in § 2.7* [new connection setting](#new-connection-setting "#new-connection-setting"), in § 2.6* [next manual redirect steps](#fetch-controller-next-manual-redirect-steps "#fetch-controller-next-manual-redirect-steps"), in § 2* ["no-cache"](#dom-requestcache-no-cache "#dom-requestcache-no-cache"), in § 5.4* ["no-cors"](#dom-requestmode-no-cors "#dom-requestmode-no-cors"), in § 5.4* [no-CORS-safelisted request-header](#no-cors-safelisted-request-header "#no-cors-safelisted-request-header"), in § 2.2.2* [no-CORS-safelisted request-header name](#no-cors-safelisted-request-header-name "#no-cors-safelisted-request-header-name"), in § 2.2.2* [non-subresource request](#non-subresource-request "#non-subresource-request"), in § 2.2.5* [non-zero-hex](#non-zero-hex "#non-zero-hex"), in § 3.2* normalize
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  + [dfn for header value](#concept-header-value-normalize "#concept-header-value-normalize"), in § 2.2.2+ [dfn for method](#concept-method-normalize "#concept-method-normalize"), in § 2.2.1* [normal quota](#reserved-deferred-fetch-quota-normal-quota "#reserved-deferred-fetch-quota-normal-quota"), in § 4.12.1* ["no-store"](#dom-requestcache-no-store "#dom-requestcache-no-store"), in § 5.4* [notify invoked](#deferred-fetch-record-notify-invoked "#deferred-fetch-record-notify-invoked"), in § 2.4* [null body status](#null-body-status "#null-body-status"), in § 2.2.3* ["object"](#dom-requestdestination-object "#dom-requestdestination-object"), in § 5.4* [obtain a connection](#concept-connection-obtain "#concept-connection-obtain"), in § 2.6* [ok](#dom-response-ok "#dom-response-ok"), in § 5.5* [ok status](#ok-status "#ok-status"), in § 2.2.3* ["omit"](#dom-requestcredentials-omit "#dom-requestcredentials-omit"), in § 5.4* ["only-if-cached"](#dom-requestcache-only-if-cached "#dom-requestcache-only-if-cached"), in § 5.4* ["opaque"](#dom-responsetype-opaque "#dom-responsetype-opaque"), in § 5.5* [opaque filtered response](#concept-filtered-response-opaque "#concept-filtered-response-opaque"), in § 2.2.6* ["opaqueredirect"](#dom-responsetype-opaqueredirect "#dom-responsetype-opaqueredirect"), in § 5.5* [opaque-redirect filtered response](#concept-filtered-response-opaque-redirect "#concept-filtered-response-opaque-redirect"), in § 2.2.6* [Origin](#http-origin "#http-origin"), in § 3.2* origin
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  + [dfn for connection](#connection-origin "#connection-origin"), in § 2.6+ [dfn for request](#concept-request-origin "#concept-request-origin"), in § 2.2.5* [origin-or-null](#origin-or-null "#origin-or-null"), in § 3.2* [override fetch](#concept-override-fetch "#concept-override-fetch"), in § 4.2* ["paintworklet"](#dom-requestdestination-paintworklet "#dom-requestdestination-paintworklet"), in § 5.4* [parse and store response `Set-Cookie` headers](#parse-and-store-response-set-cookie-headers "#parse-and-store-response-set-cookie-headers"), in § 3.1.2* [parse a single range header value](#simple-range-header-value "#simple-range-header-value"), in § 2.2.2* [parser metadata](#concept-request-parser-metadata "#concept-request-parser-metadata"), in § 2.2.5* [policy container](#concept-request-policy-container "#concept-request-policy-container"), in § 2.2.5* [populate request from client](#populate-request-from-client "#populate-request-from-client"), in § 4* [post-redirect start time](#fetch-timing-info-post-redirect-start-time "#fetch-timing-info-post-redirect-start-time"), in § 2* [potential destination](#concept-potential-destination "#concept-potential-destination"), in § 2.2.7* [potentially free deferred-fetch quota](#potentially-free-deferred-fetch-quota "#potentially-free-deferred-fetch-quota"), in § 4.12.1* [potentially override response for a request](#potentially-override-response-for-a-request "#potentially-override-response-for-a-request"), in § 4.2* [preloaded response candidate](#fetch-params-preloaded-response-candidate "#fetch-params-preloaded-response-candidate"), in § 2* [prevent no-cache cache-control header modification flag](#no-cache-prevent-cache-control "#no-cache-prevent-cache-control"), in § 2.2.5* priority
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                + [dfn for request](#request-priority "#request-priority"), in § 2.2.5+ [dict-member for RequestInit](#dom-requestinit-priority "#dom-requestinit-priority"), in § 5.4* [privileged no-CORS request-header name](#privileged-no-cors-request-header-name "#privileged-no-cors-request-header-name"), in § 2.2.2* [process a deferred fetch](#process-a-deferred-fetch "#process-a-deferred-fetch"), in § 4.12* [process deferred fetches](#process-deferred-fetches "#process-deferred-fetches"), in § 4.12* [process early hints response](#fetch-params-process-early-hints-response "#fetch-params-process-early-hints-response"), in § 2* [processEarlyHintsResponse](#fetch-processearlyhintsresponse "#fetch-processearlyhintsresponse"), in § 4* [process request body chunk length](#fetch-params-process-request-body "#fetch-params-process-request-body"), in § 2* [processRequestBodyChunkLength](#process-request-body "#process-request-body"), in § 4* [process request end-of-body](#fetch-params-process-request-end-of-body "#fetch-params-process-request-end-of-body"), in § 2* [processRequestEndOfBody](#process-request-end-of-body "#process-request-end-of-body"), in § 4* [process response](#fetch-params-process-response "#fetch-params-process-response"), in § 2* [processResponse](#process-response "#process-response"), in § 4* [process response consume body](#fetch-params-process-response-consume-body "#fetch-params-process-response-consume-body"), in § 2* [processResponseConsumeBody](#process-response-end-of-body "#process-response-end-of-body"), in § 4* [process response end-of-body](#fetch-params-process-response-end-of-body "#fetch-params-process-response-end-of-body"), in § 2* [processResponseEndOfBody](#fetch-processresponseendofbody "#fetch-processresponseendofbody"), in § 4* [process the next manual redirect](#fetch-controller-process-the-next-manual-redirect "#fetch-controller-process-the-next-manual-redirect"), in § 2* [proxy-authentication entry](#proxy-authentication-entry "#proxy-authentication-entry"), in § 2.3* [queue a cross-origin embedder policy CORP violation report](#queue-a-cross-origin-embedder-policy-corp-violation-report "#queue-a-cross-origin-embedder-policy-corp-violation-report"), in § 3.7* [queue a deferred fetch](#queue-a-deferred-fetch "#queue-a-deferred-fetch"), in § 4.12* [queue a fetch task](#queue-a-fetch-task "#queue-a-fetch-task"), in § 2* [quota reserved for deferred-fetch-minimal](#quota-reserved-for-deferred-fetch-minimal "#quota-reserved-for-deferred-fetch-minimal"), in § 4.12.1* [range-requested flag](#concept-response-range-requested-flag "#concept-response-range-requested-flag"), in § 2.2.6* [range status](#range-status "#range-status"), in § 2.2.3* [record connection timing info](#record-connection-timing-info "#record-connection-timing-info"), in § 2.6* redirect
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  + [attribute for Request](#dom-request-redirect "#dom-request-redirect"), in § 5.4+ [dict-member for RequestInit](#dom-requestinit-redirect "#dom-requestinit-redirect"), in § 5.4* [redirect count](#concept-request-redirect-count "#concept-request-redirect-count"), in § 2.2.5* [redirected](#dom-response-redirected "#dom-response-redirected"), in § 5.5* [redirect end time](#fetch-timing-info-redirect-end-time "#fetch-timing-info-redirect-end-time"), in § 2* [redirect mode](#concept-request-redirect-mode "#concept-request-redirect-mode"), in § 2.2.5* [redirect start time](#fetch-timing-info-redirect-start-time "#fetch-timing-info-redirect-start-time"), in § 2* [redirect status](#redirect-status "#redirect-status"), in § 2.2.3* [redirect taint](#response-redirect-taint "#response-redirect-taint"), in § 2.2.6* [redirect-taint](#concept-request-tainted-origin "#concept-request-tainted-origin"), in § 2.2.5* [redirect(url)](#dom-response-redirect "#dom-response-redirect"), in § 5.5* [redirect(url, status)](#dom-response-redirect "#dom-response-redirect"), in § 5.5* referrer
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        + [attribute for Request](#dom-request-referrer "#dom-request-referrer"), in § 5.4+ [dfn for request](#concept-request-referrer "#concept-request-referrer"), in § 2.2.5+ [dict-member for RequestInit](#dom-requestinit-referrer "#dom-requestinit-referrer"), in § 5.4* [referrer policy](#concept-request-referrer-policy "#concept-request-referrer-policy"), in § 2.2.5* referrerPolicy
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            + [attribute for Request](#dom-request-referrerpolicy "#dom-request-referrerpolicy"), in § 5.4+ [dict-member for RequestInit](#dom-requestinit-referrerpolicy "#dom-requestinit-referrerpolicy"), in § 5.4* ["reload"](#dom-requestcache-reload "#dom-requestcache-reload"), in § 5.4* [reload-navigation flag](#concept-request-reload-navigation-flag "#concept-request-reload-navigation-flag"), in § 2.2.5* [remove privileged no-CORS request-headers](#concept-headers-remove-privileged-no-cors-request-headers "#concept-headers-remove-privileged-no-cors-request-headers"), in § 5.1* render-blocking
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    + [dfn for fetch timing info](#fetch-timing-info-render-blocking "#fetch-timing-info-render-blocking"), in § 2+ [dfn for request](#request-render-blocking "#request-render-blocking"), in § 2.2.5* [replaces client id](#concept-request-replaces-client-id "#concept-request-replaces-client-id"), in § 2.2.5* ["report"](#dom-requestdestination-report "#dom-requestdestination-report"), in § 5.4* [report timing](#finalize-and-report-timing "#finalize-and-report-timing"), in § 2* [report timing steps](#fetch-controller-report-timing-steps "#fetch-controller-report-timing-steps"), in § 2* [Request](#request "#request"), in § 5.4* request
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                + [definition of](#concept-request "#concept-request"), in § 2.2.5+ [dfn for Request](#concept-request-request "#concept-request-request"), in § 5.4+ [dfn for deferred fetch record](#deferred-fetch-record-request "#deferred-fetch-record-request"), in § 2.4+ [dfn for fetch params](#fetch-params-request "#fetch-params-request"), in § 2+ [dfn for fetch record](#concept-fetch-record-request "#concept-fetch-record-request"), in § 2.4* [request-body-header name](#request-body-header-name "#request-body-header-name"), in § 2.2.2* [RequestCache](#requestcache "#requestcache"), in § 5.4* [RequestCredentials](#requestcredentials "#requestcredentials"), in § 5.4* [RequestDestination](#requestdestination "#requestdestination"), in § 5.4* [RequestDuplex](#enumdef-requestduplex "#enumdef-requestduplex"), in § 5.4* [request-includes-credentials](#response-request-includes-credentials "#response-request-includes-credentials"), in § 2.2.6* [RequestInfo](#requestinfo "#requestinfo"), in § 5.4* [RequestInit](#requestinit "#requestinit"), in § 5.4* [Request(input)](#dom-request "#dom-request"), in § 5.4* [Request(input, init)](#dom-request "#dom-request"), in § 5.4* [RequestMode](#requestmode "#requestmode"), in § 5.4* [RequestPriority](#enumdef-requestpriority "#enumdef-requestpriority"), in § 5.4* [RequestRedirect](#requestredirect "#requestredirect"), in § 5.4* [requireUnreliable](#obtain-a-connection-requireunreliable "#obtain-a-connection-requireunreliable"), in § 2.6* [reserved client](#concept-request-reserved-client "#concept-request-reserved-client"), in § 2.2.5* [reserved deferred-fetch quota](#reserved-deferred-fetch-quota "#reserved-deferred-fetch-quota"), in § 4.12.1* [reserve deferred-fetch quota](#reserve-deferred-fetch-quota "#reserve-deferred-fetch-quota"), in § 4.12.1* [resolve an origin](#resolve-an-origin "#resolve-an-origin"), in § 2.5* [Response](#response "#response"), in § 5.5* response
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        + [definition of](#concept-response "#concept-response"), in § 2.2.6+ [dfn for Response](#concept-response-response "#concept-response-response"), in § 5.5* [Response()](#dom-response "#dom-response"), in § 5.5* [Response(body)](#dom-response "#dom-response"), in § 5.5* [response body info](#response-body-info "#response-body-info"), in § 2* [Response(body, init)](#dom-response "#dom-response"), in § 5.5* [ResponseInit](#responseinit "#responseinit"), in § 5.5* [response tainting](#concept-request-response-tainting "#concept-request-response-tainting"), in § 2.2.5* [ResponseType](#responsetype "#responsetype"), in § 5.5* [resumed](#concept-fetch-resume "#concept-fetch-resume"), in § 4* [safely extract](#bodyinit-safely-extract "#bodyinit-safely-extract"), in § 5.2* "same-origin"
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            + [enum-value for RequestCredentials](#dom-requestcredentials-same-origin "#dom-requestcredentials-same-origin"), in § 5.4+ [enum-value for RequestMode](#dom-requestmode-same-origin "#dom-requestmode-same-origin"), in § 5.4* [scheme fetch](#concept-scheme-fetch "#concept-scheme-fetch"), in § 4.3* ["script"](#dom-requestdestination-script "#dom-requestdestination-script"), in § 5.4* [script-like](#request-destination-script-like "#request-destination-script-like"), in § 2.2.5* [Sec-Purpose](#http-sec-purpose "#http-sec-purpose"), in § 3.8* [secure connection start time](#connection-timing-info-secure-connection-start-time "#connection-timing-info-secure-connection-start-time"), in § 2.6* [serialize an integer](#serialize-an-integer "#serialize-an-integer"), in § 2* [serialize a response URL for reporting](#serialize-a-response-url-for-reporting "#serialize-a-response-url-for-reporting"), in § 2.2.5* [serialized abort reason](#fetch-controller-serialized-abort-reason "#fetch-controller-serialized-abort-reason"), in § 2* [serialized cookie default path](#serialized-cookie-default-path "#serialized-cookie-default-path"), in § 3.1.3* [serialized-domain](#serialized-domain "#serialized-domain"), in § 3.2* [serialized-host](#serialized-host "#serialized-host"), in § 3.2* [serialized-ipv4](#serialized-ipv4 "#serialized-ipv4"), in § 3.2* [serialized-ipv6](#serialized-ipv6 "#serialized-ipv6"), in § 3.2* [serialized-origin](#serialized-origin "#serialized-origin"), in § 3.2* [serialized-port](#serialized-port "#serialized-port"), in § 3.2* [serialized-scheme](#serialized-scheme "#serialized-scheme"), in § 3.2* [Serializing a request origin](#serializing-a-request-origin "#serializing-a-request-origin"), in § 2.2.5* [server-timing headers](#fetch-timing-info-server-timing-headers "#fetch-timing-info-server-timing-headers"), in § 2* [service-workers mode](#request-service-workers-mode "#request-service-workers-mode"), in § 2.2.5* service worker timing info
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    + [dfn for fetch timing info](#fetch-timing-info-service-worker-timing-info "#fetch-timing-info-service-worker-timing-info"), in § 2+ [dfn for response](#response-service-worker-timing-info "#response-service-worker-timing-info"), in § 2.2.6* [set](#concept-header-list-set "#concept-header-list-set"), in § 2.2.2* [set a structured field value](#concept-header-list-set-structured-header "#concept-header-list-set-structured-header"), in § 2.2.2* [set(name, value)](#dom-headers-set "#dom-headers-set"), in § 5.1* ["sharedworker"](#dom-requestdestination-sharedworker "#dom-requestdestination-sharedworker"), in § 5.4* [should response to request be blocked due to mime type](#should-response-to-request-be-blocked-due-to-mime-type? "#should-response-to-request-be-blocked-due-to-mime-type?"), in § 2.9* [should response to request be blocked due to nosniff](#should-response-to-request-be-blocked-due-to-nosniff? "#should-response-to-request-be-blocked-due-to-nosniff?"), in § 3.6* signal
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  + [attribute for Request](#dom-request-signal "#dom-request-signal"), in § 5.4+ [dfn for Request](#request-signal "#request-signal"), in § 5.4+ [dict-member for RequestInit](#dom-requestinit-signal "#dom-requestinit-signal"), in § 5.4* [sort and combine](#concept-header-list-sort-and-combine "#concept-header-list-sort-and-combine"), in § 2.2.2* [source](#concept-body-source "#concept-body-source"), in § 2.2.4* [stale response](#concept-stale-response "#concept-stale-response"), in § 2.2.6* [stale-while-revalidate response](#concept-stale-while-revalidate-response "#concept-stale-while-revalidate-response"), in § 2.2.6* [start time](#fetch-timing-info-start-time "#fetch-timing-info-start-time"), in § 2* [state](#fetch-controller-state "#fetch-controller-state"), in § 2* status
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                + [attribute for Response](#dom-response-status "#dom-response-status"), in § 5.5+ [definition of](#concept-status "#concept-status"), in § 2.2.3+ [dfn for response](#concept-response-status "#concept-response-status"), in § 2.2.6+ [dict-member for ResponseInit](#dom-responseinit-status "#dom-responseinit-status"), in § 5.5* [status message](#concept-response-status-message "#concept-response-status-message"), in § 2.2.6* statusText
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    + [attribute for Response](#dom-response-statustext "#dom-response-statustext"), in § 5.5+ [dict-member for ResponseInit](#dom-responseinit-statustext "#dom-responseinit-statustext"), in § 5.5* [stream](#concept-body-stream "#concept-body-stream"), in § 2.2.4* ["style"](#dom-requestdestination-style "#dom-requestdestination-style"), in § 5.4* [subresource request](#subresource-request "#subresource-request"), in § 2.2.5* [suspend](#concept-fetch-suspend "#concept-fetch-suspend"), in § 4* [TAO check](#concept-tao-check "#concept-tao-check"), in § 4.11* [task destination](#fetch-params-task-destination "#fetch-params-task-destination"), in § 2* [terminate](#fetch-controller-terminate "#fetch-controller-terminate"), in § 2* [terminated](#concept-fetch-group-terminate "#concept-fetch-group-terminate"), in § 2.4* ["text"](#dom-requestdestination-text "#dom-requestdestination-text"), in § 5.4* [text()](#dom-body-text "#dom-body-text"), in § 5.3* [timing allow failed flag](#timing-allow-failed "#timing-allow-failed"), in § 2.2.5* [timing allow passed flag](#concept-response-timing-allow-passed "#concept-response-timing-allow-passed"), in § 2.2.6* timing info
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              + [dfn for connection](#concept-connection-timing-info "#concept-connection-timing-info"), in § 2.6+ [dfn for fetch params](#fetch-params-timing-info "#fetch-params-timing-info"), in § 2* [top-level navigation initiator origin](#request-top-level-navigation-initiator-origin "#request-top-level-navigation-initiator-origin"), in § 2.2.5* [total request length](#total-request-length "#total-request-length"), in § 4.12* ["track"](#dom-requestdestination-track "#dom-requestdestination-track"), in § 5.4* [translate](#concept-potential-destination-translate "#concept-potential-destination-translate"), in § 2.2.7* [traversable for user prompts](#concept-request-window "#concept-request-window"), in § 2.2.5* type
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          + [attribute for Response](#dom-response-type "#dom-response-type"), in § 5.5+ [dfn for body with type](#body-with-type-type "#body-with-type-type"), in § 2.2.4+ [dfn for response](#concept-response-type "#concept-response-type"), in § 2.2.6* [unsafe-request flag](#unsafe-request-flag "#unsafe-request-flag"), in § 2.2.5* [unusable](#body-unusable "#body-unusable"), in § 5.3* URL
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                + [dfn for cache entry](#concept-cache-url "#concept-cache-url"), in § 4.9+ [dfn for request](#concept-request-url "#concept-request-url"), in § 2.2.5+ [dfn for response](#concept-response-url "#concept-response-url"), in § 2.2.6* url
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  + [attribute for Request](#dom-request-url "#dom-request-url"), in § 5.4+ [attribute for Response](#dom-response-url "#dom-response-url"), in § 5.5* URL list
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    + [dfn for request](#concept-request-url-list "#concept-request-url-list"), in § 2.2.5+ [dfn for response](#concept-response-url-list "#concept-response-url-list"), in § 2.2.6* [use-CORS-preflight flag](#use-cors-preflight-flag "#use-cors-preflight-flag"), in § 2.2.5* [useParallelQueue](#fetch-useparallelqueue "#fetch-useparallelqueue"), in § 4* [user-activation](#request-user-activation "#request-user-activation"), in § 2.2.5* [use-URL-credentials flag](#concept-request-use-url-credentials-flag "#concept-request-use-url-credentials-flag"), in § 2.2.5* [validate](#headers-validate "#headers-validate"), in § 5.1* value
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                + [dfn for WebTransport-hash](#webtransport-hash-value "#webtransport-hash-value"), in § 2.2.5+ [dfn for header](#concept-header-value "#concept-header-value"), in § 2.2.2* ["video"](#dom-requestdestination-video "#dom-requestdestination-video"), in § 5.4* [WebDriver id](#concept-webdriver-id "#concept-webdriver-id"), in § 2.2.5* [WebDriver navigation id](#request-webdriver-navigation-id "#request-webdriver-navigation-id"), in § 2.2.5* [WebTransport-hash](#concept-WebTransport-hash "#concept-WebTransport-hash"), in § 2.2.5* [webTransportHashes](#obtain-a-connection-webtransporthashes "#obtain-a-connection-webtransporthashes"), in § 2.6* WebTransport-hash list
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            + [definition of](#webtransport-hash-list "#webtransport-hash-list"), in § 2.2.5+ [dfn for request](#request-webtransport-hash-list "#request-webtransport-hash-list"), in § 2.2.5* [wildcard](#wildcard "#wildcard"), in § 3.3.4* [window](#dom-requestinit-window "#dom-requestinit-window"), in § 5.4* ["worker"](#dom-requestdestination-worker "#dom-requestdestination-worker"), in § 5.4* [X-Content-Type-Options](#http-x-content-type-options "#http-x-content-type-options"), in § 3.6* [XMLHttpRequestBodyInit](#typedefdef-xmlhttprequestbodyinit "#typedefdef-xmlhttprequestbodyinit"), in § 5.2* ["xslt"](#dom-requestdestination-xslt "#dom-requestdestination-xslt"), in § 5.4

### Terms defined by reference

* [] defines the following terms:
  + define an inherited policy for feature in container* [BEACON] defines the following terms:
    + sendBeacon()* [COOKIES] defines the following terms:
      + cookie default path+ garbage collect cookies+ parse and store a cookie+ retrieve cookies+ serialize cookies* [CSP] defines the following terms:
        + Report Content Security Policy violations for request+ Should request be blocked by Content Security Policy?+ Should response to request be blocked by Content Security Policy?* [CSS-VALUES-4] defines the following terms:
          + fetch a style resource* [DOM] defines the following terms:
            + AbortSignal+ Document+ abort reason+ aborted+ add+ create a dependent abort signal+ document+ element+ node document+ origin+ shadow-including inclusive descendant* [ECMASCRIPT] defines the following terms:
              + current realm+ realm+ Record* [ENCODING] defines the following terms:
                + encoding+ getting an encoding+ UTF-8+ UTF-8 decode+ UTF-8 decode without BOM+ UTF-8 encode* [FETCH-METADATA] defines the following terms:
                  + append the Fetch metadata headers for a request+ Sec-Fetch-Dest* [FILEAPI] defines the following terms:
                    + Blob+ File+ get stream+ name+ obtain a blob object+ size+ slice blob+ type* [HR-TIME-3] defines the following terms:
                      + DOMHighResTimeStamp+ coarsen time+ coarsened shared current time+ relative high resolution time+ unsafe shared current time* [HTML] defines the following terms:
                        + "coep" report type+ EventSource+ StructuredDeserialize+ StructuredSerialize+ Window+ WindowOrWorkerGlobalScope+ Worker+ active document+ allowed to use+ ancestor navigables+ API base URL+ ASCII serialization of an origin+ associated Document+ clone a policy container+ consume a preloaded resource+ container document+ creation URL+ credentialless+ cross-origin isolated capability+ current settings object+ descendant navigables+ DOM manipulation task source+ download the hyperlink+ embedder policy+ embedder policy value+ enqueue steps+ entry+ environment+ environment settings object+ event loop+ fetch a classic script+ form+ fully active+ global object+ global object (for environment settings object)+ has cross-site ancestor+ host+ id+ in parallel+ inclusive descendant navigables+ multipart/form-data boundary string+ multipart/form-data encoding algorithm+ navigable+ navigable (for Window)+ navigable container+ navigate+ navigating+ networking task source+ node navigable+ obtain a site+ opaque origin+ origin+ origin (for environment settings object)+ parallel queue+ parent+ policy container+ policy container (for environment settings object)+ queue a global task+ referrer policy+ relevant global object+ relevant realm+ relevant settings object+ report only reporting endpoint+ report only value+ reporting endpoint+ require-corp+ resource fetch algorithm+ same origin+ same site+ scheme+ schemelessly same site+ secure context+ serialization of an origin+ site+ starting a new parallel queue+ target browsing context+ task source+ top-level creation URL+ top-level origin+ top-level traversable+ traversable navigable+ traversable navigable (for navigable)+ tuple origin+ unsafe-none+ value+ visibility state* [HTTP] defines the following terms:
                          + field-name+ field-value+ method+ unsafe* [HTTP-CACHING] defines the following terms:
                            + Constructing Responses from Caches+ current age+ delta-seconds+ Freshening Stored Responses upon Validation+ freshness lifetime+ Invalidating Stored Responses+ Sending a Validation Request+ Storing Responses in Caches* [HTTP1] defines the following terms:
                              + reason-phrase* [INFRA] defines the following terms:
                                + abort when+ append (for list)+ append (for set)+ ASCII case-insensitive+ ASCII digit+ ASCII string+ ASCII whitespace+ assert+ break+ byte less than+ byte sequence+ byte-case-insensitive+ byte-lowercase+ byte-uppercase+ clone+ code point+ collect a sequence of code points+ collecting a sequence of code points+ contain+ continue+ exist+ for each (for list)+ for each (for map)+ forgiving-base64 decode+ if aborted+ implementation-defined+ is empty+ is not empty (for list)+ is not empty (for map)+ isomorphic decode+ isomorphic encode+ item (for list)+ item (for struct)+ length (for byte sequence)+ length (for string)+ list+ ordered set+ parse JSON from bytes+ position variable+ remove+ scalar value string+ serialize a JavaScript value to JSON bytes+ set+ size+ sorting+ starts with (for byte sequence)+ starts with (for string)+ string+ strip leading and trailing ASCII whitespace+ struct+ tuple* [MIMESNIFF] defines the following terms:
                                  + essence+ JavaScript MIME type+ MIME type+ minimize a supported MIME type+ parameters+ parse a MIME type+ serialize a MIME type+ serialize a MIME type to bytes* [MIX] defines the following terms:
                                    + Should fetching request be blocked as mixed content?+ Should response to request be blocked as mixed content?+ Upgrade a mixed content request to a potentially trustworthy URL, if appropriate* [PERMISSIONS-POLICY-1] defines the following terms:
                                      + default allowlist+ policy-controlled feature* [REFERRER] defines the following terms:
                                        + ReferrerPolicy+ Determine request's Referrer+ referrer policy+ Set request's referrer policy on redirect* [REPORTING] defines the following terms:
                                          + generate and queue a report* [RESOURCE-TIMING] defines the following terms:
                                            + mark resource timing* [RFC9651] defines the following terms:
                                              + parsing structured fields+ serializing structured fields+ structured field token+ structured field value+ structured header* [SECURE-CONTEXTS] defines the following terms:
                                                + potentially trustworthy URL* [SRI] defines the following terms:
                                                  + Do bytes match metadataList?+ should request be blocked by integrity policy* [STALE-WHILE-REVALIDATE] defines the following terms:
                                                    + stale-while-revalidate lifetime* [STREAMS] defines the following terms:
                                                      + ReadableStream+ ReadableStreamDefaultReader+ TransformStream+ cancel+ cancelAlgorithm+ chunk steps+ close+ close steps+ creating a proxy+ disturbed+ enqueue (for ReadableStream)+ enqueue (for TransformStream)+ error+ error steps+ errored+ flushAlgorithm+ get a reader+ getReader()+ getting a reader+ identity transform stream+ locked+ piped through+ pull from bytes+ pullAlgorithm+ read a chunk+ read all bytes+ read request+ readable+ set up+ set up with byte reading support+ teeing+ transformAlgorithm* [SW] defines the following terms:
                                                        + ServiceWorkerGlobalScope+ fetch+ Handle Fetch+ service worker timing info* [UPGRADE-INSECURE-REQUESTS] defines the following terms:
                                                          + Upgrade request to a potentially trustworthy URL, if appropriate* [URL] defines the following terms:
                                                            + URLSearchParams+ absolute-URL-with-fragment string+ blob URL entry+ domain+ equal+ exclude fragment+ fragment+ host+ host (for url)+ include credentials+ includes credentials+ IP address+ IPv6 address+ list+ origin+ password+ path+ percent-decode+ port+ public suffix+ registrable domain+ scheme+ set the password+ set the username+ URL+ URL parser+ URL path serializer+ URL serializer+ urlencoded parser+ urlencoded serializer+ username* [WEBCRYPTO] defines the following terms:
                                                              + generate a random UUID* [WEBDRIVER-BIDI] defines the following terms:
                                                                + WebDriver BiDi before request sent+ WebDriver BiDi clone network request body+ WebDriver BiDi clone network response body+ WebDriver BiDi emulated language+ WebDriver BiDi emulated User-Agent+ WebDriver BiDi fetch error+ WebDriver BiDi network is offline+ WebDriver BiDi response completed+ WebDriver BiDi response started* [WEBIDL] defines the following terms:
                                                                  + AbortError+ ArrayBuffer+ BufferSource+ ByteString+ DOMException+ DOMString+ Exposed+ NewObject+ Promise+ QuotaExceededError+ RangeError+ SameObject+ SecureContext+ SyntaxError+ TypeError+ USVString+ Uint8Array+ a new promise+ a promise rejected with+ any+ boolean+ create (for ArrayBuffer)+ create (for ArrayBufferView)+ exception+ get a copy of the buffer source+ interface+ iterable+ new+ quota+ record+ reject+ requested+ resolve+ sequence+ this+ throw+ undefined+ unsigned short+ value pairs to iterate over* [WEBSOCKETS] defines the following terms:
                                                                    + WebSocket+ establish a WebSocket connection+ obtain a WebSocket connection* [WEBTRANSPORT] defines the following terms:
                                                                      + WebTransport+ WebTransport(url, options)+ custom certificate requirements+ obtain a WebTransport connection+ serverCertificateHashes+ verify a certificate hash* [XHR] defines the following terms:
                                                                        + FormData+ XMLHttpRequest+ XMLHttpRequestUpload+ entry list

References
----------

### Normative References

[ABNF]: D. Crocker, Ed.; P. Overell. [Augmented BNF for Syntax Specifications: ABNF](https://www.rfc-editor.org/rfc/rfc5234 "https://www.rfc-editor.org/rfc/rfc5234"). January 2008. Internet Standard. URL: [https://www.rfc-editor.org/rfc/rfc5234](https://www.rfc-editor.org/rfc/rfc5234 "https://www.rfc-editor.org/rfc/rfc5234") [BEACON]: Ilya Grigorik; Alois Reitbauer. [Beacon](https://w3c.github.io/beacon/ "https://w3c.github.io/beacon/"). URL: [https://w3c.github.io/beacon/](https://w3c.github.io/beacon/ "https://w3c.github.io/beacon/") [COOKIES]: Johann Hofmann; Anne van Kesteren. [Cookies: HTTP State Management Mechanism](https://httpwg.org/http-extensions/draft-ietf-httpbis-layered-cookies.html "https://httpwg.org/http-extensions/draft-ietf-httpbis-layered-cookies.html"). URL: [https://httpwg.org/http-extensions/draft-ietf-httpbis-layered-cookies.html](https://httpwg.org/http-extensions/draft-ietf-httpbis-layered-cookies.html "https://httpwg.org/http-extensions/draft-ietf-httpbis-layered-cookies.html") [CSP]: Mike West; Antonio Sartori. [Content Security Policy Level 3](https://w3c.github.io/webappsec-csp/ "https://w3c.github.io/webappsec-csp/"). URL: [https://w3c.github.io/webappsec-csp/](https://w3c.github.io/webappsec-csp/ "https://w3c.github.io/webappsec-csp/") [CSS-VALUES-4]: Tab Atkins Jr.; Elika Etemad. [CSS Values and Units Module Level 4](https://drafts.csswg.org/css-values-4/ "https://drafts.csswg.org/css-values-4/"). URL: [https://drafts.csswg.org/css-values-4/](https://drafts.csswg.org/css-values-4/ "https://drafts.csswg.org/css-values-4/") [DOM]: Anne van Kesteren. [DOM Standard](https://dom.spec.whatwg.org/ "https://dom.spec.whatwg.org/"). Living Standard. URL: [https://dom.spec.whatwg.org/](https://dom.spec.whatwg.org/ "https://dom.spec.whatwg.org/") [ECMASCRIPT]: [ECMAScript Language Specification](https://tc39.es/ecma262/multipage/ "https://tc39.es/ecma262/multipage/"). URL: [https://tc39.es/ecma262/multipage/](https://tc39.es/ecma262/multipage/ "https://tc39.es/ecma262/multipage/") [ENCODING]: Anne van Kesteren. [Encoding Standard](https://encoding.spec.whatwg.org/ "https://encoding.spec.whatwg.org/"). Living Standard. URL: [https://encoding.spec.whatwg.org/](https://encoding.spec.whatwg.org/ "https://encoding.spec.whatwg.org/") [FETCH-METADATA]: Mike West. [Fetch Metadata Request Headers](https://w3c.github.io/webappsec-fetch-metadata/ "https://w3c.github.io/webappsec-fetch-metadata/"). URL: [https://w3c.github.io/webappsec-fetch-metadata/](https://w3c.github.io/webappsec-fetch-metadata/ "https://w3c.github.io/webappsec-fetch-metadata/") [FILEAPI]: Marijn Kruisselbrink. [File API](https://w3c.github.io/FileAPI/ "https://w3c.github.io/FileAPI/"). URL: [https://w3c.github.io/FileAPI/](https://w3c.github.io/FileAPI/ "https://w3c.github.io/FileAPI/") [HR-TIME-3]: Yoav Weiss. [High Resolution Time](https://w3c.github.io/hr-time/ "https://w3c.github.io/hr-time/"). URL: [https://w3c.github.io/hr-time/](https://w3c.github.io/hr-time/ "https://w3c.github.io/hr-time/") [HSTS]: J. Hodges; C. Jackson; A. Barth. [HTTP Strict Transport Security (HSTS)](https://www.rfc-editor.org/rfc/rfc6797 "https://www.rfc-editor.org/rfc/rfc6797"). November 2012. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc6797](https://www.rfc-editor.org/rfc/rfc6797 "https://www.rfc-editor.org/rfc/rfc6797") [HTML]: Anne van Kesteren; et al. [HTML Standard](https://html.spec.whatwg.org/multipage/ "https://html.spec.whatwg.org/multipage/"). Living Standard. URL: [https://html.spec.whatwg.org/multipage/](https://html.spec.whatwg.org/multipage/ "https://html.spec.whatwg.org/multipage/") [HTTP]: R. Fielding, Ed.; M. Nottingham, Ed.; J. Reschke, Ed.. [HTTP Semantics](https://httpwg.org/specs/rfc9110.html "https://httpwg.org/specs/rfc9110.html"). June 2022. Internet Standard. URL: [https://httpwg.org/specs/rfc9110.html](https://httpwg.org/specs/rfc9110.html "https://httpwg.org/specs/rfc9110.html") [HTTP-CACHING]: R. Fielding, Ed.; M. Nottingham, Ed.; J. Reschke, Ed.. [HTTP Caching](https://httpwg.org/specs/rfc9111.html "https://httpwg.org/specs/rfc9111.html"). June 2022. Internet Standard. URL: [https://httpwg.org/specs/rfc9111.html](https://httpwg.org/specs/rfc9111.html "https://httpwg.org/specs/rfc9111.html") [HTTP1]: R. Fielding, Ed.; M. Nottingham, Ed.; J. Reschke, Ed.. [HTTP/1.1](https://httpwg.org/specs/rfc9112.html "https://httpwg.org/specs/rfc9112.html"). June 2022. Internet Standard. URL: [https://httpwg.org/specs/rfc9112.html](https://httpwg.org/specs/rfc9112.html "https://httpwg.org/specs/rfc9112.html") [HTTP3]: M. Bishop, Ed.. [HTTP/3](https://httpwg.org/specs/rfc9114.html "https://httpwg.org/specs/rfc9114.html"). June 2022. Proposed Standard. URL: [https://httpwg.org/specs/rfc9114.html](https://httpwg.org/specs/rfc9114.html "https://httpwg.org/specs/rfc9114.html") [HTTP3-DATAGRAM]: D. Schinazi; L. Pardue. [HTTP Datagrams and the Capsule Protocol](https://www.rfc-editor.org/rfc/rfc9297 "https://www.rfc-editor.org/rfc/rfc9297"). August 2022. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc9297](https://www.rfc-editor.org/rfc/rfc9297 "https://www.rfc-editor.org/rfc/rfc9297") [IANA-HTTP-PARAMS]: [Hypertext Transfer Protocol (HTTP) Parameters](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml "https://www.iana.org/assignments/http-parameters/http-parameters.xhtml"). URL: [https://www.iana.org/assignments/http-parameters/http-parameters.xhtml](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml "https://www.iana.org/assignments/http-parameters/http-parameters.xhtml") [INFRA]: Anne van Kesteren; Domenic Denicola. [Infra Standard](https://infra.spec.whatwg.org/ "https://infra.spec.whatwg.org/"). Living Standard. URL: [https://infra.spec.whatwg.org/](https://infra.spec.whatwg.org/ "https://infra.spec.whatwg.org/") [MIMESNIFF]: Gordon P. Hemsley. [MIME Sniffing Standard](https://mimesniff.spec.whatwg.org/ "https://mimesniff.spec.whatwg.org/"). Living Standard. URL: [https://mimesniff.spec.whatwg.org/](https://mimesniff.spec.whatwg.org/ "https://mimesniff.spec.whatwg.org/") [MIX]: Emily Stark; Mike West; Carlos IbarraLopez. [Mixed Content](https://w3c.github.io/webappsec-mixed-content/ "https://w3c.github.io/webappsec-mixed-content/"). URL: [https://w3c.github.io/webappsec-mixed-content/](https://w3c.github.io/webappsec-mixed-content/ "https://w3c.github.io/webappsec-mixed-content/") [PERMISSIONS-POLICY-1]: Ian Clelland. [Permissions Policy](https://w3c.github.io/webappsec-permissions-policy/ "https://w3c.github.io/webappsec-permissions-policy/"). URL: [https://w3c.github.io/webappsec-permissions-policy/](https://w3c.github.io/webappsec-permissions-policy/ "https://w3c.github.io/webappsec-permissions-policy/") [REFERRER]: Jochen Eisinger; Emily Stark. [Referrer Policy](https://w3c.github.io/webappsec-referrer-policy/ "https://w3c.github.io/webappsec-referrer-policy/"). URL: [https://w3c.github.io/webappsec-referrer-policy/](https://w3c.github.io/webappsec-referrer-policy/ "https://w3c.github.io/webappsec-referrer-policy/") [REPORTING]: Douglas Creager; Ian Clelland; Mike West. [Reporting API](https://w3c.github.io/reporting/ "https://w3c.github.io/reporting/"). URL: [https://w3c.github.io/reporting/](https://w3c.github.io/reporting/ "https://w3c.github.io/reporting/") [RESOURCE-TIMING]: Yoav Weiss; Noam Rosenthal. [Resource Timing](https://w3c.github.io/resource-timing/ "https://w3c.github.io/resource-timing/"). URL: [https://w3c.github.io/resource-timing/](https://w3c.github.io/resource-timing/ "https://w3c.github.io/resource-timing/") [RFC7405]: P. Kyzivat. [Case-Sensitive String Support in ABNF](https://www.rfc-editor.org/rfc/rfc7405 "https://www.rfc-editor.org/rfc/rfc7405"). December 2014. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc7405](https://www.rfc-editor.org/rfc/rfc7405 "https://www.rfc-editor.org/rfc/rfc7405") [RFC7578]: L. Masinter. [Returning Values from Forms: multipart/form-data](https://www.rfc-editor.org/rfc/rfc7578 "https://www.rfc-editor.org/rfc/rfc7578"). July 2015. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc7578](https://www.rfc-editor.org/rfc/rfc7578 "https://www.rfc-editor.org/rfc/rfc7578") [RFC9218]: K. Oku; L. Pardue. [Extensible Prioritization Scheme for HTTP](https://httpwg.org/specs/rfc9218.html "https://httpwg.org/specs/rfc9218.html"). June 2022. Proposed Standard. URL: [https://httpwg.org/specs/rfc9218.html](https://httpwg.org/specs/rfc9218.html "https://httpwg.org/specs/rfc9218.html") [RFC9651]: M. Nottingham; P-H. Kamp. [Structured Field Values for HTTP](https://www.rfc-editor.org/rfc/rfc9651 "https://www.rfc-editor.org/rfc/rfc9651"). September 2024. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc9651](https://www.rfc-editor.org/rfc/rfc9651 "https://www.rfc-editor.org/rfc/rfc9651") [SECURE-CONTEXTS]: Mike West. [Secure Contexts](https://w3c.github.io/webappsec-secure-contexts/ "https://w3c.github.io/webappsec-secure-contexts/"). URL: [https://w3c.github.io/webappsec-secure-contexts/](https://w3c.github.io/webappsec-secure-contexts/ "https://w3c.github.io/webappsec-secure-contexts/") [SRI]: Frederik Braun. [Subresource Integrity](https://w3c.github.io/webappsec-subresource-integrity/ "https://w3c.github.io/webappsec-subresource-integrity/"). URL: [https://w3c.github.io/webappsec-subresource-integrity/](https://w3c.github.io/webappsec-subresource-integrity/ "https://w3c.github.io/webappsec-subresource-integrity/") [STALE-WHILE-REVALIDATE]: M. Nottingham. [HTTP Cache-Control Extensions for Stale Content](https://httpwg.org/specs/rfc5861.html "https://httpwg.org/specs/rfc5861.html"). May 2010. Informational. URL: [https://httpwg.org/specs/rfc5861.html](https://httpwg.org/specs/rfc5861.html "https://httpwg.org/specs/rfc5861.html") [STREAMS]: Adam Rice; et al. [Streams Standard](https://streams.spec.whatwg.org/ "https://streams.spec.whatwg.org/"). Living Standard. URL: [https://streams.spec.whatwg.org/](https://streams.spec.whatwg.org/ "https://streams.spec.whatwg.org/") [SVCB]: B. Schwartz; M. Bishop; E. Nygren. [Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)](https://www.rfc-editor.org/rfc/rfc9460 "https://www.rfc-editor.org/rfc/rfc9460"). November 2023. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc9460](https://www.rfc-editor.org/rfc/rfc9460 "https://www.rfc-editor.org/rfc/rfc9460") [SW]: Monica CHINTALA; Yoshisato Yanagisawa. [Service Workers Nightly](https://w3c.github.io/ServiceWorker/ "https://w3c.github.io/ServiceWorker/"). URL: [https://w3c.github.io/ServiceWorker/](https://w3c.github.io/ServiceWorker/ "https://w3c.github.io/ServiceWorker/") [TLS]: E. Rescorla. [The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446 "https://www.rfc-editor.org/rfc/rfc8446"). August 2018. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc8446](https://www.rfc-editor.org/rfc/rfc8446 "https://www.rfc-editor.org/rfc/rfc8446") [UPGRADE-INSECURE-REQUESTS]: Mike West. [Upgrade Insecure Requests](https://w3c.github.io/webappsec-upgrade-insecure-requests/ "https://w3c.github.io/webappsec-upgrade-insecure-requests/"). URL: [https://w3c.github.io/webappsec-upgrade-insecure-requests/](https://w3c.github.io/webappsec-upgrade-insecure-requests/ "https://w3c.github.io/webappsec-upgrade-insecure-requests/") [URL]: Anne van Kesteren. [URL Standard](https://url.spec.whatwg.org/ "https://url.spec.whatwg.org/"). Living Standard. URL: [https://url.spec.whatwg.org/](https://url.spec.whatwg.org/ "https://url.spec.whatwg.org/") [WEBCRYPTO]: Daniel Huigens. [Web Cryptography Level 2](https://w3c.github.io/webcrypto/ "https://w3c.github.io/webcrypto/"). URL: [https://w3c.github.io/webcrypto/](https://w3c.github.io/webcrypto/ "https://w3c.github.io/webcrypto/") [WEBDRIVER-BIDI]: James Graham; Alex Rudenko; Maksim Sadym. [WebDriver BiDi](https://w3c.github.io/webdriver-bidi/ "https://w3c.github.io/webdriver-bidi/"). URL: [https://w3c.github.io/webdriver-bidi/](https://w3c.github.io/webdriver-bidi/ "https://w3c.github.io/webdriver-bidi/") [WEBIDL]: Edgar Chen; Timothy Gu. [Web IDL Standard](https://webidl.spec.whatwg.org/ "https://webidl.spec.whatwg.org/"). Living Standard. URL: [https://webidl.spec.whatwg.org/](https://webidl.spec.whatwg.org/ "https://webidl.spec.whatwg.org/") [WEBSOCKETS]: Adam Rice. [WebSockets Standard](https://websockets.spec.whatwg.org/ "https://websockets.spec.whatwg.org/"). Living Standard. URL: [https://websockets.spec.whatwg.org/](https://websockets.spec.whatwg.org/ "https://websockets.spec.whatwg.org/") [WEBTRANSPORT]: Nidhi Jaju; Victor Vasiliev; Jan-Ivar Bruaroey. [WebTransport](https://w3c.github.io/webtransport/ "https://w3c.github.io/webtransport/"). URL: [https://w3c.github.io/webtransport/](https://w3c.github.io/webtransport/ "https://w3c.github.io/webtransport/") [WEBTRANSPORT-HTTP3]: V. Vasiliev. [WebTransport over HTTP/3](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3 "https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3"). URL: [https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3 "https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3") [XHR]: Anne van Kesteren. [XMLHttpRequest Standard](https://xhr.spec.whatwg.org/ "https://xhr.spec.whatwg.org/"). Living Standard. URL: [https://xhr.spec.whatwg.org/](https://xhr.spec.whatwg.org/ "https://xhr.spec.whatwg.org/")

### Non-Normative References

[HTTPVERBSEC1]: [Multiple vendors' web servers enable HTTP TRACE method by default.](https://www.kb.cert.org/vuls/id/867593 "https://www.kb.cert.org/vuls/id/867593"). URL: [https://www.kb.cert.org/vuls/id/867593](https://www.kb.cert.org/vuls/id/867593 "https://www.kb.cert.org/vuls/id/867593") [HTTPVERBSEC2]: [Microsoft Internet Information Server (IIS) vulnerable to cross-site scripting via HTTP TRACK method.](https://www.kb.cert.org/vuls/id/288308 "https://www.kb.cert.org/vuls/id/288308"). URL: [https://www.kb.cert.org/vuls/id/288308](https://www.kb.cert.org/vuls/id/288308 "https://www.kb.cert.org/vuls/id/288308") [HTTPVERBSEC3]: [HTTP proxy default configurations allow arbitrary TCP connections.](https://www.kb.cert.org/vuls/id/150227 "https://www.kb.cert.org/vuls/id/150227"). URL: [https://www.kb.cert.org/vuls/id/150227](https://www.kb.cert.org/vuls/id/150227 "https://www.kb.cert.org/vuls/id/150227") [NAVIGATION-TIMING]: Zhiheng Wang. [Navigation Timing](https://www.w3.org/TR/navigation-timing/ "https://www.w3.org/TR/navigation-timing/"). 17 December 2012. REC. URL: [https://www.w3.org/TR/navigation-timing/](https://www.w3.org/TR/navigation-timing/ "https://www.w3.org/TR/navigation-timing/") [ORIGIN]: A. Barth. [The Web Origin Concept](https://www.rfc-editor.org/rfc/rfc6454 "https://www.rfc-editor.org/rfc/rfc6454"). December 2011. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc6454](https://www.rfc-editor.org/rfc/rfc6454 "https://www.rfc-editor.org/rfc/rfc6454") [RFC1035]: P. Mockapetris. [Domain names - implementation and specification](https://www.rfc-editor.org/rfc/rfc1035 "https://www.rfc-editor.org/rfc/rfc1035"). November 1987. Internet Standard. URL: [https://www.rfc-editor.org/rfc/rfc1035](https://www.rfc-editor.org/rfc/rfc1035 "https://www.rfc-editor.org/rfc/rfc1035") [RFC2397]: L. Masinter. [The "data" URL scheme](https://www.rfc-editor.org/rfc/rfc2397 "https://www.rfc-editor.org/rfc/rfc2397"). August 1998. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc2397](https://www.rfc-editor.org/rfc/rfc2397 "https://www.rfc-editor.org/rfc/rfc2397") [RFC3986]: T. Berners-Lee; R. Fielding; L. Masinter. [Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986 "https://www.rfc-editor.org/rfc/rfc3986"). January 2005. Internet Standard. URL: [https://www.rfc-editor.org/rfc/rfc3986](https://www.rfc-editor.org/rfc/rfc3986 "https://www.rfc-editor.org/rfc/rfc3986") [RFC5952]: S. Kawamura; M. Kawashima. [A Recommendation for IPv6 Address Text Representation](https://www.rfc-editor.org/rfc/rfc5952 "https://www.rfc-editor.org/rfc/rfc5952"). August 2010. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc5952](https://www.rfc-editor.org/rfc/rfc5952 "https://www.rfc-editor.org/rfc/rfc5952") [RFC6960]: S. Santesson; et al. [X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP](https://www.rfc-editor.org/rfc/rfc6960 "https://www.rfc-editor.org/rfc/rfc6960"). June 2013. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc6960](https://www.rfc-editor.org/rfc/rfc6960 "https://www.rfc-editor.org/rfc/rfc6960") [RFC7301]: S. Friedl; et al. [Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension](https://www.rfc-editor.org/rfc/rfc7301 "https://www.rfc-editor.org/rfc/rfc7301"). July 2014. Proposed Standard. URL: [https://www.rfc-editor.org/rfc/rfc7301](https://www.rfc-editor.org/rfc/rfc7301 "https://www.rfc-editor.org/rfc/rfc7301") [RFC7918]: A. Langley; N. Modadugu; B. Moeller. [Transport Layer Security (TLS) False Start](https://www.rfc-editor.org/rfc/rfc7918 "https://www.rfc-editor.org/rfc/rfc7918"). August 2016. Informational. URL: [https://www.rfc-editor.org/rfc/rfc7918](https://www.rfc-editor.org/rfc/rfc7918 "https://www.rfc-editor.org/rfc/rfc7918") [RFC8470]: M. Thomson; M. Nottingham; W. Tarreau. [Using Early Data in HTTP](https://httpwg.org/specs/rfc8470.html "https://httpwg.org/specs/rfc8470.html"). September 2018. Proposed Standard. URL: [https://httpwg.org/specs/rfc8470.html](https://httpwg.org/specs/rfc8470.html "https://httpwg.org/specs/rfc8470.html") [RFC9163]: E. Stark. [Expect-CT Extension for HTTP](https://www.rfc-editor.org/rfc/rfc9163 "https://www.rfc-editor.org/rfc/rfc9163"). June 2022. Experimental. URL: [https://www.rfc-editor.org/rfc/rfc9163](https://www.rfc-editor.org/rfc/rfc9163 "https://www.rfc-editor.org/rfc/rfc9163")

IDL Index
---------

```
typedef (sequence<sequence<ByteString>> or record<ByteString, ByteString>) HeadersInit;

[Exposed=(Window,Worker)]
interface Headers {
  constructor(optional HeadersInit init);

  undefined append(ByteString name, ByteString value);
  undefined delete(ByteString name);
  ByteString? get(ByteString name);
  sequence<ByteString> getSetCookie();
  boolean has(ByteString name);
  undefined set(ByteString name, ByteString value);
  iterable<ByteString, ByteString>;
};

typedef (Blob or BufferSource or FormData or URLSearchParams or USVString) XMLHttpRequestBodyInit;

typedef (ReadableStream or XMLHttpRequestBodyInit) BodyInit;
interface mixin Body {
  readonly attribute ReadableStream? body;
  readonly attribute boolean bodyUsed;
  [NewObject] Promise<ArrayBuffer> arrayBuffer();
  [NewObject] Promise<Blob> blob();
  [NewObject] Promise<Uint8Array> bytes();
  [NewObject] Promise<FormData> formData();
  [NewObject] Promise<any> json();
  [NewObject] Promise<USVString> text();
};
typedef (Request or USVString) RequestInfo;

[Exposed=(Window,Worker)]
interface Request {
  constructor(RequestInfo input, optional RequestInit init = {});

  readonly attribute ByteString method;
  readonly attribute USVString url;
  [SameObject] readonly attribute Headers headers;

  readonly attribute RequestDestination destination;
  readonly attribute USVString referrer;
  readonly attribute ReferrerPolicy referrerPolicy;
  readonly attribute RequestMode mode;
  readonly attribute RequestCredentials credentials;
  readonly attribute RequestCache cache;
  readonly attribute RequestRedirect redirect;
  readonly attribute DOMString integrity;
  readonly attribute boolean keepalive;
  readonly attribute boolean isReloadNavigation;
  readonly attribute boolean isHistoryNavigation;
  readonly attribute AbortSignal signal;
  readonly attribute RequestDuplex duplex;

  [NewObject] Request clone();
};
Request includes Body;

dictionary RequestInit {
  ByteString method;
  HeadersInit headers;
  BodyInit? body;
  USVString referrer;
  ReferrerPolicy referrerPolicy;
  RequestMode mode;
  RequestCredentials credentials;
  RequestCache cache;
  RequestRedirect redirect;
  DOMString integrity;
  boolean keepalive;
  AbortSignal? signal;
  RequestDuplex duplex;
  RequestPriority priority;
  any window; // can only be set to null
};

enum RequestDestination { "", "audio", "audioworklet", "document", "embed", "font", "frame", "iframe", "image", "json", "manifest", "object", "paintworklet", "report", "script", "sharedworker", "style", "text", "track", "video", "worker", "xslt" };
enum RequestMode { "navigate", "same-origin", "no-cors", "cors" };
enum RequestCredentials { "omit", "same-origin", "include" };
enum RequestCache { "default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached" };
enum RequestRedirect { "follow", "error", "manual" };
enum RequestDuplex { "half" };
enum RequestPriority { "high", "low", "auto" };

[Exposed=(Window,Worker)]
interface Response {
  constructor(optional BodyInit? body = null, optional ResponseInit init = {});

  [NewObject] static Response error();
  [NewObject] static Response redirect(USVString url, optional unsigned short status = 302);
  [NewObject] static Response json(any data, optional ResponseInit init = {});

  readonly attribute ResponseType type;

  readonly attribute USVString url;
  readonly attribute boolean redirected;
  readonly attribute unsigned short status;
  readonly attribute boolean ok;
  readonly attribute ByteString statusText;
  [SameObject] readonly attribute Headers headers;

  [NewObject] Response clone();
};
Response includes Body;

dictionary ResponseInit {
  unsigned short status = 200;
  ByteString statusText = "";
  HeadersInit headers;
};

enum ResponseType { "basic", "cors", "default", "error", "opaque", "opaqueredirect" };

partial interface mixin WindowOrWorkerGlobalScope {
  [NewObject] Promise<Response> fetch(RequestInfo input, optional RequestInit init = {});
};

dictionary DeferredRequestInit : RequestInit {
  DOMHighResTimeStamp activateAfter;
};

[Exposed=Window]
interface FetchLaterResult {
  readonly attribute boolean activated;
};

partial interface Window {
  [NewObject, SecureContext] FetchLaterResult fetchLater(RequestInfo input, optional DeferredRequestInit init = {});
};
```

**✔**MDN

[Headers/Headers](https://developer.mozilla.org/en-US/docs/Web/API/Headers/Headers "The Headers() constructor creates a new Headers object.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[Headers/append](https://developer.mozilla.org/en-US/docs/Web/API/Headers/append "The append() method of the Headers interface appends a new value onto an existing header inside a Headers object, or adds the header if it does not already exist.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[Headers/delete](https://developer.mozilla.org/en-US/docs/Web/API/Headers/delete "The delete() method of the Headers interface deletes a header from the current Headers object.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[Headers/get](https://developer.mozilla.org/en-US/docs/Web/API/Headers/get "The get() method of the Headers interface returns a byte string of all the values of a header within a Headers object with a given name. If the requested header doesn't exist in the Headers object, it returns null.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[Headers/getSetCookie](https://developer.mozilla.org/en-US/docs/Web/API/Headers/getSetCookie "The getSetCookie() method of the Headers interface returns an array containing the values of all Set-Cookie headers associated with a response. This allows Headers objects to handle having multiple Set-Cookie headers, which wasn't possible prior to its implementation.")

In all current engines.

Firefox112+Safari17+Chrome113+


---

Opera?Edge113+


---

Edge (Legacy)?IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js19.7.0+


**✔**MDN

[Headers/has](https://developer.mozilla.org/en-US/docs/Web/API/Headers/has "The has() method of the Headers interface returns a boolean stating whether a Headers object contains a certain header.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[Headers/set](https://developer.mozilla.org/en-US/docs/Web/API/Headers/set "The set() method of the Headers interface sets a new value for an existing header inside a Headers object, or adds the header if it does not already exist.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[Headers](https://developer.mozilla.org/en-US/docs/Web/API/Headers "The Headers interface of the Fetch API allows you to perform various actions on HTTP request and response headers. These actions include retrieving, setting, adding to, and removing headers from the list of the request's headers.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[Request/Request](https://developer.mozilla.org/en-US/docs/Web/API/Request/Request "The Request() constructor creates a new Request object.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera27+Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile27+


**✔**MDN

[Request/arrayBuffer](https://developer.mozilla.org/en-US/docs/Web/API/Request/arrayBuffer "The arrayBuffer() method of the Request interface reads the request body and returns it as a promise that resolves with an ArrayBuffer.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?

[Response/arrayBuffer](https://developer.mozilla.org/en-US/docs/Web/API/Response/arrayBuffer "The arrayBuffer() method of the Response interface takes a Response stream and reads it to completion. It returns a promise that resolves with an ArrayBuffer.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/blob](https://developer.mozilla.org/en-US/docs/Web/API/Request/blob "The blob() method of the Request interface reads the request body and returns it as a promise that resolves with a Blob.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?

[Response/blob](https://developer.mozilla.org/en-US/docs/Web/API/Response/blob "The blob() method of the Response interface takes a Response stream and reads it to completion. It returns a promise that resolves with a Blob.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


MDN

[Request/body](https://developer.mozilla.org/en-US/docs/Web/API/Request/body "The read-only body property of the Request interface contains a ReadableStream with the body contents that have been added to the request. Note that a request using the GET or HEAD method cannot have a body and null is returned in these cases.")

FirefoxNoneSafari11.1+Chrome105+


---

Opera?Edge105+


---

Edge (Legacy)?IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?

[Response/body](https://developer.mozilla.org/en-US/docs/Web/API/Response/body "The body read-only property of the Response interface is a ReadableStream of the body contents.")

In all current engines.

Firefox65+Safari10.1+Chrome43+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/bodyUsed](https://developer.mozilla.org/en-US/docs/Web/API/Request/bodyUsed "The read-only bodyUsed property of the Request interface is a boolean value that indicates whether the request body has been read yet.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?

[Response/bodyUsed](https://developer.mozilla.org/en-US/docs/Web/API/Response/bodyUsed "The bodyUsed read-only property of the Response interface is a boolean value that indicates whether the body has been read yet.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/cache](https://developer.mozilla.org/en-US/docs/Web/API/Request/cache "The cache read-only property of the Request interface contains the cache mode of the request. It controls how the request will interact with the browser's HTTP cache.")

In all current engines.

Firefox48+Safari10.1+Chrome64+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/clone](https://developer.mozilla.org/en-US/docs/Web/API/Request/clone "The clone() method of the Request interface creates a copy of the current Request object.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/credentials](https://developer.mozilla.org/en-US/docs/Web/API/Request/credentials "The credentials read-only property of the Request interface indicates whether the user agent should send or receive cookies from the other domain in the case of cross-origin requests.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/destination](https://developer.mozilla.org/en-US/docs/Web/API/Request/destination "The destination read-only property of the Request interface returns a string describing the type of content being requested.")

In all current engines.

Firefox61+Safari10.1+Chrome65+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/formData](https://developer.mozilla.org/en-US/docs/Web/API/Request/formData "The formData() method of the Request interface reads the request body and returns it as a promise that resolves with a FormData object.")

In all current engines.

Firefox39+Safari14.1+Chrome60+


---

Opera?Edge79+


---

Edge (Legacy)?IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?

[Response/formData](https://developer.mozilla.org/en-US/docs/Web/API/Response/formData "The formData() method of the Response interface takes a Response stream and reads it to completion. It returns a promise that resolves with a FormData object.")

In all current engines.

Firefox39+Safari14.1+Chrome60+


---

Opera?Edge79+


---

Edge (Legacy)?IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/headers](https://developer.mozilla.org/en-US/docs/Web/API/Request/headers "The headers read-only property of the Request interface contains the Headers object associated with the request.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/integrity](https://developer.mozilla.org/en-US/docs/Web/API/Request/integrity "The integrity read-only property of the Request interface contains the subresource integrity value of the request.")

In all current engines.

Firefox51+Safari10.1+Chrome46+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/json](https://developer.mozilla.org/en-US/docs/Web/API/Request/json "The json() method of the Request interface reads the request body and returns it as a promise that resolves with the result of parsing the body text as JSON.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?

[Response/json](https://developer.mozilla.org/en-US/docs/Web/API/Response/json "The json() method of the Response interface takes a Response stream and reads it to completion. It returns a promise which resolves with the result of parsing the body text as JSON.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/method](https://developer.mozilla.org/en-US/docs/Web/API/Request/method "The method read-only property of the Request interface contains the request's method (GET, POST, etc.)")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/mode](https://developer.mozilla.org/en-US/docs/Web/API/Request/mode "The mode read-only property of the Request interface contains the mode of the request (e.g., cors, no-cors, same-origin, navigate or websocket.) This is used to determine if cross-origin requests lead to valid responses, and which properties of the response are readable.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/redirect](https://developer.mozilla.org/en-US/docs/Web/API/Request/redirect "The redirect read-only property of the Request interface contains the mode for how redirects are handled.")

In all current engines.

Firefox43+Safari10.1+Chrome46+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/referrer](https://developer.mozilla.org/en-US/docs/Web/API/Request/referrer "The referrer read-only property of the Request interface is set by the user agent to be the referrer of the Request. (e.g., client, no-referrer, or a URL.)")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/referrerPolicy](https://developer.mozilla.org/en-US/docs/Web/API/Request/referrerPolicy "The referrerPolicy read-only property of the Request interface returns the referrer policy, which governs what referrer information, sent in the Referer header, should be included with the request.")

In all current engines.

Firefox47+Safari10.1+Chrome52+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet7.2+Opera Mobile?


**✔**MDN

[Request/signal](https://developer.mozilla.org/en-US/docs/Web/API/Request/signal "The read-only signal property of the Request interface returns the AbortSignal associated with the request.")

In all current engines.

Firefox57+Safari12.1+Chrome66+


---

Opera?Edge79+


---

Edge (Legacy)16+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/text](https://developer.mozilla.org/en-US/docs/Web/API/Request/text "The text() method of the Request interface reads the request body and returns it as a promise that resolves with a String. The response is always decoded using UTF-8.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?

[Response/text](https://developer.mozilla.org/en-US/docs/Web/API/Response/text "The text() method of the Response interface takes a Response stream and reads it to completion. It returns a promise that resolves with a String. The response is always decoded using UTF-8.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Request/url](https://developer.mozilla.org/en-US/docs/Web/API/Request/url "The url read-only property of the Request interface contains the URL of the request.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile27+


**✔**MDN

[Request](https://developer.mozilla.org/en-US/docs/Web/API/Request "The Request interface of the Fetch API represents a resource request.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[Response/Response](https://developer.mozilla.org/en-US/docs/Web/API/Response/Response "The Response() constructor creates a new Response object.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response/clone](https://developer.mozilla.org/en-US/docs/Web/API/Response/clone "The clone() method of the Response interface creates a clone of a response object, identical in every way, but stored in a different variable.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response/error\_static](https://developer.mozilla.org/en-US/docs/Web/API/Response/error_static "The error() static method of the Response interface returns a new Response object associated with a network error.")

In all current engines.

Firefox39+Safari10.1+Chrome43+


---

Opera?Edge79+


---

Edge (Legacy)16+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response/headers](https://developer.mozilla.org/en-US/docs/Web/API/Response/headers "The headers read-only property of the Response interface contains the Headers object associated with the response.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


MDN

[Response/json\_static](https://developer.mozilla.org/en-US/docs/Web/API/Response/json_static "The json() static method of the Response interface returns a Response that contains the provided JSON data as body, and a Content-Type header which is set to application/json. The response status, status message, and additional headers can also be set.")

Firefox115+SafariNoneChrome105+


---

Opera?Edge105+


---

Edge (Legacy)?IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response/ok](https://developer.mozilla.org/en-US/docs/Web/API/Response/ok "The ok read-only property of the Response interface contains a Boolean stating whether the response was successful (status in the range 200-299) or not.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response/redirect\_static](https://developer.mozilla.org/en-US/docs/Web/API/Response/redirect_static "The redirect() static method of the Response interface returns a Response resulting in a redirect to the specified URL.")

In all current engines.

Firefox39+Safari10.1+Chrome44+


---

Opera?Edge79+


---

Edge (Legacy)16+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response/redirected](https://developer.mozilla.org/en-US/docs/Web/API/Response/redirected "The read-only redirected property of the Response interface indicates whether or not the response is the result of a request you made which was redirected.")

In all current engines.

Firefox49+Safari10.1+Chrome57+


---

Opera?Edge79+


---

Edge (Legacy)16+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView60+Samsung Internet8.0+Opera Mobile?


**✔**MDN

[Response/status](https://developer.mozilla.org/en-US/docs/Web/API/Response/status "The status read-only property of the Response interface contains the HTTP status codes of the response.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response/statusText](https://developer.mozilla.org/en-US/docs/Web/API/Response/statusText "The statusText read-only property of the Response interface contains the status message corresponding to the HTTP status code in Response.status.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response/type](https://developer.mozilla.org/en-US/docs/Web/API/Response/type "The type read-only property of the Response interface contains the type of the response. It can be one of the following:")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response/url](https://developer.mozilla.org/en-US/docs/Web/API/Response/url "The url read-only property of the Response interface contains the URL of the response. The value of the url property will be the final URL obtained after any redirects.")

In all current engines.

Firefox39+Safari10.1+Chrome40+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**✔**MDN

[Response](https://developer.mozilla.org/en-US/docs/Web/API/Response "The Response interface of the Fetch API represents the response to a request.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[fetch](https://developer.mozilla.org/en-US/docs/Web/API/fetch "The global fetch() method starts the process of fetching a resource from the network, returning a promise which is fulfilled once the response is available.")

In all current engines.

Firefox39+Safari10.1+Chrome42+


---

Opera?Edge79+


---

Edge (Legacy)14+IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


---

Node.js18.0.0+


**✔**MDN

[Headers/Access-Control-Allow-Credentials](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials "The Access-Control-Allow-Credentials response header tells browsers whether to expose the response to the frontend JavaScript code when the request's credentials mode (Request.credentials) is include.")

In all current engines.

Firefox3.5+Safari4+Chrome4+


---

Opera12+Edge79+


---

Edge (Legacy)12+IE10+


---

Firefox for Android?iOS Safari?Chrome for AndroidYesAndroid WebView2+Samsung Internet?Opera Mobile12+


**✔**MDN

[Headers/Access-Control-Allow-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers "The Access-Control-Allow-Headers response header is used in response to a preflight request which includes the Access-Control-Request-Headers to indicate which HTTP headers can be used during the actual request.")

In all current engines.

Firefox3.5+Safari4+Chrome4+


---

Opera12+Edge79+


---

Edge (Legacy)12+IE10+


---

Firefox for Android?iOS Safari?Chrome for AndroidYesAndroid WebView2+Samsung Internet?Opera Mobile12+


**✔**MDN

[Headers/Access-Control-Allow-Methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods "The Access-Control-Allow-Methods response header specifies one or more methods allowed when accessing a resource in response to a preflight request.")

In all current engines.

Firefox3.5+Safari4+Chrome4+


---

Opera12+Edge79+


---

Edge (Legacy)12+IE10+


---

Firefox for Android?iOS Safari?Chrome for AndroidYesAndroid WebView2+Samsung Internet?Opera Mobile12+


**✔**MDN

[Headers/Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin "The Access-Control-Allow-Origin response header indicates whether the response can be shared with requesting code from the given origin.")

In all current engines.

Firefox3.5+Safari4+Chrome4+


---

Opera12+Edge79+


---

Edge (Legacy)12+IE10+


---

Firefox for Android?iOS Safari?Chrome for AndroidYesAndroid WebView2+Samsung Internet?Opera Mobile12+


**✔**MDN

[Headers/Access-Control-Expose-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers "The Access-Control-Expose-Headers response header allows a server to indicate which response headers should be made available to scripts running in the browser, in response to a cross-origin request.")

In all current engines.

Firefox3.5+Safari4+Chrome4+


---

Opera12+Edge79+


---

Edge (Legacy)12+IE10+


---

Firefox for Android?iOS Safari?Chrome for AndroidYesAndroid WebView2+Samsung Internet?Opera Mobile12+


**✔**MDN

[Headers/Access-Control-Max-Age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age "The Access-Control-Max-Age response header indicates how long the results of a preflight request (that is the information contained in the Access-Control-Allow-Methods and Access-Control-Allow-Headers headers) can be cached.")

In all current engines.

Firefox3.5+Safari4+Chrome4+


---

Opera12+Edge79+


---

Edge (Legacy)12+IE10+


---

Firefox for Android?iOS Safari?Chrome for AndroidYesAndroid WebView2+Samsung Internet?Opera Mobile12+


**✔**MDN

[Headers/Access-Control-Request-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Headers "The Access-Control-Request-Headers request header is used by browsers when issuing a preflight request to let the server know which HTTP headers the client might send when the actual request is made (such as with setRequestHeader()). The complementary server-side header of Access-Control-Allow-Headers will answer this browser-side header.")

In all current engines.

Firefox3.5+Safari4+Chrome4+


---

Opera12+Edge79+


---

Edge (Legacy)12+IE10+


---

Firefox for Android?iOS Safari?Chrome for AndroidYesAndroid WebView2+Samsung Internet?Opera Mobile12+


**✔**MDN

[Headers/Access-Control-Request-Method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Method "The Access-Control-Request-Method request header is used by browsers when issuing a preflight request, to let the server know which HTTP method will be used when the actual request is made. This header is necessary as the preflight request is always an OPTIONS and doesn't use the same method as the actual request.")

In all current engines.

Firefox3.5+Safari4+Chrome4+


---

Opera12+Edge79+


---

Edge (Legacy)12+IE10+


---

Firefox for Android?iOS Safari?Chrome for AndroidYesAndroid WebView2+Samsung Internet?Opera Mobile12+


**✔**MDN

[Headers/Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy "The HTTP Cross-Origin-Resource-Policy response header conveys a desire that the browser blocks no-cors cross-origin/cross-site requests to the given resource.")

In all current engines.

Firefox74+Safari12+Chrome73+


---

OperaNoneEdge79+


---

Edge (Legacy)NoneIENone


---

Firefox for AndroidNoneiOS Safari?Chrome for Android?Android WebView?Samsung Internet11.0+Opera MobileNone


**✔**MDN

[Headers/Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin "The Origin request header indicates the origin (scheme, hostname, and port) that caused the request. For example, if a user agent needs to request resources included in a page, or fetched by scripts that it executes, then the origin of the page may be included in the request.")

In all current engines.

Firefox70+SafariYesChromeYes


---

Opera?EdgeYes


---

Edge (Legacy)12+IEYes


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera Mobile?


**⚠**MDN

[Headers/Sec-Purpose](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Purpose "The Sec-Purpose fetch metadata request header indicates the purpose for which the requested resource will be used, when that purpose is something other than immediate use by the user-agent.")

In only one current engine.

Firefox115+SafariNoneChromeNone


---

Opera?EdgeNone


---

Edge (Legacy)?IENone


---

Firefox for Android?iOS Safari?Chrome for Android?Android WebView?Samsung Internet?Opera MobileNone


**✔**MDN

[Headers/X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options "The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in the Content-Type headers should be followed and not be changed. The header allows you to avoid MIME type sniffing by saying that the MIME types are deliberately configured.")

In all current engines.

Firefox50+Safari11+Chrome64+


---

OperaYesEdge79+


---

Edge (Legacy)12+IE8+


---

Firefox for Android?iOS Safari?Chrome for Android64+Android WebView?Samsung Internet?Opera MobileYes
