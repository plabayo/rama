# Review: recent rate, PAC, JavaScript, and extension work

Reviewed current branch state at `675841c97` (including `7abd04ac4`,
`8c898b04b`, and `1590e5982`). Commit messages and comments were treated as
leads only; conclusions below come from the current source, callers, focused
tests, primary reference implementations, and the final workspace gates.

The reviewed branch now contains the fixes identified below. “Remaining” means
the behavior still exists after those fixes; “fixed in this audit” describes a
change made while validating the four scoped commits.

## Findings (severity ordered)

### High — fixed after the audit: fetched scripts no longer parse on the host stack

`FetchPacScript` can pass a remotely obtained script to the JavaScript worker.
With the original Boa backend, a 900,001-byte unary chain reached recursive
parser/compiler code before any runtime guard and overflowed the worker's native
stack, aborting the whole proxy process.

`rama-js` now runs a pinned StarlingMonkey/SpiderMonkey component inside
Wasmtime (`rama-js/src/engine/starling.rs:34`). The component has no ambient
WASI imports. Wasmtime applies a bounded Wasm stack, deterministic fuel, epoch
interruption, and a per-store memory limit before any untrusted source is parsed
(`rama-js/src/engine/starling.rs:55`, `rama-js/src/engine/starling.rs:184`,
`rama-js/src/engine/starling.rs:376`). A guest stack, fuel, time, or memory trap
poisons that runtime, not the host process.

Concrete regression: 100,000-deep parenthesis, binary, unary, and member chains
are each evaluated in a fresh runtime and the process then successfully
evaluates `40 + 2` (`rama-js/tests/containment.rs:4`). Excessive guest allocation
is separately forced past the 64 MiB store limit and asserted to return
`LimitExceeded` while poisoning only that runtime
(`rama-js/tests/containment.rs:22`). This is a real execution boundary rather
than a lexical source heuristic.

Residual: Wasmtime and the component remain trusted native dependencies; a bug
in that trusted computing base can still affect the process. Rust host callbacks
also execute outside Wasm and cannot be interrupted or memory-accounted by
guest limits.

### Medium — remaining: capacity eviction resets a keyed rate budget

`KeyedRatePolicy` uses a bounded Moka cache and creates a full `RateLimiter` on
a miss (`rama-net/src/rate/keyed.rs:159`, `rama-net/src/rate/keyed.rs:168`). Idle
eviction is delayed for at least a full-burst refill, but capacity eviction has
no such connection to the bucket's debt (`rama-net/src/rate/keyed.rs:25`).

Concrete failure: configure `max_keys = 8`, drain key A's burst, then send from
eight or more other attacker-selected keys before A refills. Capacity pressure
evicts A; its next request recreates a full bucket and is admitted immediately.
With client-IP keys, rotating IPv6 `/64`s or forwarded identities makes the
reset repeatable. Memory remains bounded, but the rate policy is bypassable
when the key space is attacker-controlled.

This tradeoff is documented in the code, but it is still an enforcement
limitation. A strict bounded design needs bounded debt/tombstones, admission
control for new keys, or a rejection policy at capacity; simply retaining all
buckets would exchange the bypass for unbounded memory.

IPv6 handling itself is correct: `ClientIpRateKey` canonicalizes IPv4-mapped
IPv6 before applying the IPv6 prefix (`rama-net/src/rate/key.rs:183`). Thus
`::ffff:192.0.2.1` and `192.0.2.1` share the exact IPv4 key, while ordinary IPv6
addresses aggregate to the configured prefix (default `/64`).

### Medium — fixed in this audit: final reads escaped shared bandwidth accounting

The read side originally delivered bytes and recorded debt that was paid only
before a later read. Dropping the wrapper after the final successful read left
that debt unpaid.

Concrete failure: two streams share a 100-byte burst. Stream A reads its final
50 bytes and is dropped; stream B can immediately acquire all 100 bytes, so 150
bytes pass in one burst. The fix reserves before polling the inner reader,
settles the exact byte count before returning the bytes, and refunds a
data-less `Pending`, EOF, or error (`rama-net/src/stream/layer/throttle/io.rs:263`).
`final_read_spends_shared_budget_before_delivery` covers the drop-after-read
case (`rama-net/src/stream/layer/throttle/io.rs:477`).

There is no lost-waker path: when budget is unavailable the timer is polled;
when the inner reader returns `Pending`, that reader has registered the task's
waker and the temporary grant is settled before yielding. EOF may consequently
wait for one grant before it can be discovered; the grant is refunded.

The `ReadBuf` unsafe block is sound (`rama-net/src/stream/layer/throttle/io.rs:265`):
`take(cap)` borrows only the parent's unfilled region, the inner `AsyncRead`
contract initializes every byte it adds to `limited.filled()`, and the parent
then marks and advances exactly that observed count. It neither assumes the
whole cap initialized nor aliases the filled prefix.

The write side now returns unused reservations immediately on `Pending` and
reacquires after the inner writer's waker fires
(`rama-net/src/stream/layer/throttle/io.rs:308`). This removes the original
arbitrarily long held-reservation/refund window and is covered by the shared
pending-writer tests. A theoretical shared-budget race remains if an inner
`poll_read`/`poll_write` itself blocks long enough for another thread to spend
refill between reservation and settlement; conforming poll implementations
must return promptly, but the token bucket has no transactional reservation
primitive. The practical exploitability of that sub-poll race is **UNVERIFIED**.

### Medium — fixed in this audit: `PacedSink::send` did not pay its final item

`start_send` recorded debt, but only the next `poll_ready` repaid it. The normal
`SinkExt::send` sequence ends with `poll_flush`, so a one-shot sink could be
dropped without charging its last item.

Concrete failure: repeatedly construct one-shot sinks sharing a 100-unit
limiter, send a 100-unit datagram through each, then drop each sink. Every send
completed immediately because no next `poll_ready` occurred. `poll_ready`,
`poll_flush`, and `poll_close` now all repay debt
(`rama-core/src/stream/paced.rs:208`, `rama-core/src/stream/paced.rs:245`), with
the shared final-send regression at `rama-core/src/stream/paced.rs:418`.

A caller that invokes `start_send` directly and drops without ever flushing is
still outside the enforceable async path: `Drop` cannot wait. Normal `SinkExt`
send/flush/close use is accounted.

### Medium — fixed in this audit: cancelling an oversized acquire could mint shared capacity

The old cancellation guard refunded all chunks acquired by a pending
`RateLimiter::acquire`. It did not account for refill spent by another user
while those chunks were held.

Concrete failure with rate 10/s and burst 10: drain the bucket; an
`acquire(20)` takes its first 10 at +1 s; another clone spends the five units
refilled by +1.5 s; cancelling the first future then refunded 10, producing a
full bucket despite the concurrent spend. The fix keeps completed chunks spent
for requests larger than the burst (`rama-utils/src/rate/limiter.rs:90`). A
single-chunk acquire remains cancellation-safe because it consumes nothing
until its final grant. The concurrency regression is at
`rama-utils/src/rate/limiter.rs:193`.

The token-bucket arithmetic itself is correct. Products of two `u64` values fit
in `u128`; refill is stored in period-scaled units without rounding drift;
`div_ceil` makes `RetryAt` the first grantable nanosecond; saturating addition
then the capacity clamp handles extreme elapsed times
(`rama-utils/src/rate/bucket.rs:88`, `rama-utils/src/rate/bucket.rs:127`). The
property tests check the rate bound, retry tightness, and burst bound
(`rama-utils/src/rate/bucket.rs:291`). There is no FIFO waiter queue, so fairness
and starvation freedom are not promised; starvation under an adversarial
scheduler is **UNVERIFIED** rather than an arithmetic defect.

### Low — fixed in this audit: redirect `Drop` had ambiguous, inconsistent semantics

`RedirectExtensionsBehaviour::Drop` previously skipped the first-hop fork but
started later hops empty. An inner layer could therefore write into the caller's
extension store even when no redirect occurred, while later attempts lost both
the caller's values and configuration needed by the stack.

Concrete failure: caller extension state has no `Route`; hop 1 inserts
`Route("a.example")`; the request returns or redirects; the caller observes the
inner layer's per-hop value. Conversely, a redirected hop that needs a
caller-supplied connector or TLS extension cannot run under `Drop`.

The mode and its setters were removed. Forking is now the sole behavior: every
hop reads through to the caller's extensions, and every hop's own inserts remain
private (`rama-http/src/layer/follow_redirect/mod.rs:279`,
`rama-http/src/layer/follow_redirect/mod.rs:353`). Caller isolation and per-hop
decision tests cover both halves (`rama-http/src/layer/follow_redirect/mod.rs:592`,
`rama-http/src/layer/follow_redirect/mod.rs:701`). A caller-supplied extension
that must not cross origins has to carry/enforce its own scope; an append-only
fork cannot selectively subtract it.

Retry extension behavior is correct in the current tree. The policy clone is
taken before the first attempt is forked; every attempt forks from the same
caller parent, so inner-attempt writes neither leak nor reach the next attempt,
while policy changes made to its cloned request survive when the policy returns
that request (`rama-http/src/layer/retry/mod.rs:136`). Redirect composition has
dedicated tests as well.

### Low — remaining: source loading has global-eval rather than Script semantics

The private component currently evaluates source with indirect global `eval`
(`rama-js/engine/starling/runtime.js:591`). Most observable behavior matches a
global Script, including global `var` and function declarations, but two lexical
details differ. A top-level `let`/`const` environment does not survive into a
later `eval` call, and function declarations created by eval are configurable.

Concrete PAC divergence: load
`function FindProxyForURL(){return "DIRECT"}; delete globalThis.FindProxyForURL`.
A browser's Script global declaration creates a non-configurable property, so
the deletion fails and the script remains usable. Rama's eval-created property
is deleted; the resolver's post-load probe then rejects the script as missing
its entry point (`rama-pac/src/resolver.rs:544`,
`rama-pac/src/resolver.rs:584`). Ordinary PAC functions, including closures over
top-level lexical declarations made in the same source, work correctly.

The generic API also diverges if a caller executes `let x = 1` and expects a
later, separate `eval("x")` to see that lexical binding. Fixing this faithfully
requires exposing SpiderMonkey's Script compilation/evaluation path through the
component; declaration scanning or freezing every newly observed function
would be another heuristic and would change valid JavaScript behavior.

### Low — defensible divergence: `shExpMatch` is not exact ECMAScript `RegExp`

Reference mode performs the Netscape transform—escape `.`, replace `*` with
`.*`, replace `?` with `.`, anchor—and deliberately leaves other regexp
metacharacters live (`rama-pac/src/env/predicate.rs:274`). It then compiles with
`regex-automata`, not ECMAScript `RegExp`, to cap program/cache size and avoid
uninterruptible backtracking (`rama-pac/src/env/predicate.rs:283`).

Concrete divergence: Chromium/Mozilla JavaScript evaluates
`shExpMatch("😀", "?")` as false because a non-`u` JavaScript dot consumes one
UTF-16 code unit and the emoji is a surrogate pair; rama's dot consumes one
Unicode scalar and returns true. Lookarounds/backreferences supported by a JS
regexp are rejected by the Rust engine. A script using such a result to choose
`DIRECT` versus a proxy can route differently.

Classification: **(b) defensible/hardened**, not a hidden claim of exact
fidelity. The docs now state the dialect and UTF-16 limitation explicitly at
`rama-pac/src/env/predicate.rs:137`. `PacShExpMatch::Literal` remains the safer
fully literal alternative.

### Low — fixed in this audit: `isInNet` rejected reference-valid leading zeroes

The reference validates each dotted group as one to three decimal digits and
then applies JavaScript numeric conversion. Rust's `Ipv4Addr::from_str`
rejects leading-zero spelling.

Concrete failure: `isInNet("10.1.2.3", "010.001.000.000", "255.255.0.0")`
should be true but returned false before DNS/mask comparison. Pattern and mask
now pass through the PAC-specific decimal parser
(`rama-pac/src/env/predicate.rs:58`, `rama-pac/src/env/mod.rs:553`), with unit
and public-environment regressions.

### Informational — the supplied fuzz result was Boa collector lifetime, not a value leak

The artifact bytes `LVsK` decode to the three bytes `-[\n`, which Arbitrary
maps to `Input::String("🦀")`. The old harness constructed and dropped a fresh
Boa context for every libFuzzer input. Boa GC 0.21.1 was thread-local and kept a
small unreachable UTF-16 allocation in collector bookkeeping until collection;
LeakSanitizer inspected the process before thread-local teardown.

The production boundary no longer links Boa or its collector. The fuzz target
now exercises Rust → Wasm guest → Rust host → Wasm guest → Rust and needs no
engine-specific collection hook (`fuzz/fuzz_targets/js_value_boundary.rs:1`).
The exact artifact was recreated from its reported bytes and passed a one-run
macOS cargo-fuzz execution against the Wasm backend. The original
x86_64-unknown-linux-gnu ASan/LSan run remains **UNVERIFIED** on this host; the
old allocation stack is absent, but the report does not substitute that fact
for a Linux sanitizer result.

### URI-layer verification (no additional finding under the documented contract)

`data:` parsing follows RFC 2397's default media type, parameters-only form,
percent decoding, fragment removal, and inline payload semantics
(`rama-net/src/uri/data.rs:73`). The HTTP layer accepts only GET/HEAD and
materializes the decoded payload (`rama-http/src/layer/uri/data.rs:70`). A
parsed `Uri` is capped at 65,534 bytes (`rama-net/src/uri/mod.rs:210`), so the
HTTP path has a hard raw-size bound; direct `DataUri::parse(&str)` is linear in
caller-owned input and has no separate cap. Remote PAC responses have an
independent default 1 MiB maximum and 30-second whole-fetch timeout
(`rama-pac/src/provider_http.rs:37`).

`file:` authorities follow RFC 8089: empty/`localhost` are local, non-local
authorities are rejected on non-Windows and become UNC on Windows; decoded path
separators are rejected (`rama-net/src/uri/file.rs:46`,
`rama-net/src/uri/file.rs:127`). The layer canonicalizes dot segments and uses
the filesystem helpers (`rama-http/src/layer/uri/file.rs:122`). With a trusted,
non-attacker-writable jail root, lexical and static symlink traversal are
blocked. The default has no jail and can read any absolute path, but the module
is explicitly client-only and warns that server mounting becomes an arbitrary
file read (`rama-http/src/layer/uri/file.rs:12`). Files are streamed rather
than collected.

The jail is not a capability/openat2 design. If an attacker can mutate the jail
tree concurrently, swapping a symlink between canonicalization, open, and the
post-open path check can race the boundary; this precondition is documented at
`rama-utils/src/fs/mod.rs:5`. Under that unsupported setup the concrete wrong
result is an outside file handle returned from an apparently in-jail URI.

## PAC conformance table

Reference baseline: Mozilla's current
[`ascii_pac_utils.js`](https://searchfox.org/mozilla-central/source/netwerk/base/ascii_pac_utils.js)
and native [`ProxyAutoConfig.cpp`](https://searchfox.org/mozilla-central/source/netwerk/base/ProxyAutoConfig.cpp),
plus Chromium's vendored
[`pac_js_library.h`](https://chromium.googlesource.com/chromium/src/+/refs/tags/140.0.7296.0/services/proxy_resolver/pac_js_library.h)
and native V8 bindings. Classifications are: **(a)** bug, **(b)** deliberate or
defensible hardening/normalization, **(c)** matches reference (including cases
where the first review's naive reading was wrong).

| Function | Result against reference | Classification and consequence |
|---|---|---|
| `isInNet` | Matches the classic algorithm after the leading-zero fix: validate dotted decimal, resolve only the host when needed, apply pattern/mask bitwise; non-contiguous masks remain valid. Malformed typed inputs return false rather than exposing host conversion errors. | **(c)** for valid calls; malformed-input handling is **(b)**. The prior leading-zero behavior was **(a)** and is fixed. |
| `dnsDomainIs` | Core suffix test matches. Rama additionally strips trailing dots and compares ASCII case-insensitively; the reference JavaScript is a literal case-sensitive suffix. | **(b)** DNS-canonical hardening. Example divergence: upper-case host versus lower-case domain returns true only in rama. |
| `localHostOrDomainIs` | Exact match or `host + "."` prefix matches the reference. Rama is ASCII case-insensitive. | **(b)** DNS-canonical hardening. |
| `shExpMatch` | Same source transform and anchoring, including live regexp metacharacters, but a bounded Rust regexp dialect and Unicode-scalar matching replace ECMAScript regexp/UTF-16 behavior. | **(b)** hardened, with the routing divergence described in Findings. It is not exact-reference. |
| `weekdayRange` | One/two weekday forms, optional trailing GMT, inclusive range, and start-after-end wrap all match. Rama also accepts case-insensitive weekday/GMT names and returns false for malformed arity. | **(c)** for valid forms; extra normalization is **(b)**. |
| `dateRange` | All documented 1/2/4/6-argument forms match. Day and month pairs and day-month tuples use the reference's final wrap branch; year-bearing absolute ranges do not wrap. | **(c)**. Definitive verdict: `dateRange("DEC", "JAN")` **does wrap in the real reference**, so rama's `in_wrapping_range` at `rama-pac/src/env/time.rs:55` is correct and the first review was wrong. Case-insensitive names/strict malformed handling are **(b)**. |
| `timeRange` | One hour matches equality; the two-hour form is an ordinary non-wrapping comparison; four/six-argument minute/second forms use the reference's wrapping range. Optional GMT matches. | **(c)** for valid forms; rejecting malformed/out-of-range shapes without JavaScript coercion surprises is **(b)**. |
| `myIpAddress`, `myIpAddressEx` | Loopback fallback and Ex semicolon list match the surface. Rama's default enumerates filtered interfaces and picks the first IPv4; Firefox/Chromium native implementations use hostname/resolver and route-sensitive policies, especially for multihomed hosts. Rama offers `Route` and `Fixed` alternatives. | **(b)** configurable platform policy, not exact-reference. It can choose a different interface on multihomed hosts. The old “matches browsers” doc claim was removed. |
| `dnsResolve`, `dnsResolveEx` | Classic returns one IPv4/null; Ex returns a semicolon list/empty string and supports both families. Rama orders A before AAAA, caps 64 addresses, caches per evaluation, and applies per-lookup/count/aggregate blocking budgets. | **(c)** surface and normal results; ordering and resource policy are **(b)**. DNS is synchronous from the script's perspective but bridges to async rama DNS by blocking the dedicated worker. |

`resolver.rs` otherwise preserves the browser execution shape: load a script
once, call `FindProxyForURLEx` when present/enabled or the classic entry point,
and rebuild only when provider bytes change. Its URL sanitization default is a
privacy hardening, not PAC helper semantics. Host-native failures are made
explicit errors when silently answering false would let a script exhaust a
budget to disable a rule.

## PAC-implementation comparison

| Implementation | Engine and isolation | CPU / native stack / memory / time | DNS | Fidelity | Remote PAC lifecycle |
|---|---|---|---|---|---|
| **rama-pac** | StarlingMonkey/SpiderMonkey in a private Wasm component hosted by Wasmtime; one `JsWorker` OS thread per active script. The guest has no ambient WASI capability. Wasm contains engine faults short of a Wasmtime/component TCB bug; Rust host callbacks remain in-process. | Wasmtime stack checks cover parser/compiler/runtime recursion; cumulative instruction fuel, epoch wall-clock interruption, a default 64 MiB store-memory limit, snapshot budgets, caller timeout, and a bounded unresolved-worker window. Guest traps poison one runtime. Rust host callbacks are outside guest CPU/memory interruption. | Async rama resolver is synchronously bridged on the worker; per-evaluation cache, 5 s per lookup, 64 unique lookups, 15 s aggregate blocking, 64 returned addresses. | Close classic helper coverage plus Microsoft Ex functions. Strong explicit budgets; deliberate regexp/Unicode and local-IP differences. | `FetchPacScript`: status check, 1 MiB, 30 s. Optional `PacScriptCacheLayer`: 12 h TTL, single-flight refresh, stale-on-error, 30 s failure backoff. No built-in OS/WPAD discovery, HTTP validator/revalidation policy, network-change trigger, or scheduled polling. |
| **Chromium** | Jitless V8 in the sandboxed out-of-process `proxy_resolver` utility service (Android is documented as in-process). The Mojo factory is tagged with the proxy/utility sandbox. | V8 carries a real native stack limit into parser/compiler checks and converts exhaustion into a JS stack-overflow exception. Jobs can terminate V8 execution on cancellation; a utility-process crash is contained. Exact per-PAC heap/CPU quotas were not established from the reviewed source and are **UNVERIFIED**. | Browser `HostResolver`, async IPC and network-isolation-keyed DNS cache. Tracing evaluation aborts/restarts around async DNS; max 20 unique resolves per execution, with a blocking fallback. | Canonical Chromium/Netscape helper baseline and browser-native Ex behavior. | Full system/manual PAC and WPAD pipeline, fetch/cache, network-change handling and polling: failures 8 s/32 s/2 min/4 h; success 12 h. |
| **Firefox** | SpiderMonkey `ProxyAutoConfig` on a dedicated serial PAC thread; current code can proxy work to the socket process, while the local context source also documents a parent-process mode. Ion is disabled. A thread alone is not a fault boundary. | `JS_NewContext` gets a heap maximum and `JS_SetNativeStackQuota` sets a 128 Ki-word quota, so SpiderMonkey reports “too much recursion” rather than reaching the guard page. A general per-evaluation PAC CPU deadline was not found and is **UNVERIFIED**. | Native asynchronous DNS with a timer; the PAC thread spins its event loop until completion. Firefox DNS cache/policy applies; multihomed local-IP selection can use resolved route source. | Mozilla `ascii_pac_utils.js` is the historical reference. | Browser PAC manager handles configured URL/WPAD, HTTP cache, reload, and exponential failure retry (source comments cite defaults from 5 s to 5 min). Exact success-refresh policy is **UNVERIFIED**. |
| **pacparser** | QuickJS in-process behind a process-global C runtime/context; no sandbox. | The current embedder calls `JS_NewRuntime`/`JS_NewContext` but does not install a memory limit or interrupt handler. QuickJS's own defaults still apply; pacparser adds no wall-clock/CPU policy. | Blocking `getaddrinfo`, up to ten results; no embedder timeout or cache. | Ships standard helpers and Microsoft extensions; practical compatibility, but not browser integration. | Library accepts a string or local file. It does not fetch, refresh, validate, or cache a remote PAC URL. |
| **go-pac (representative Go)** | goja in the caller process; serialized per PAC object; no process sandbox. | Default 1 MiB script cap, 5 s script interrupt, 2 s DNS timeout and 10 s HTTP timeout. No separate hard JS heap quota is documented. Go's guarded/growing goroutine stack avoids the exact fixed-native-stack model but is not a memory sandbox. | Host lookup with configured timeout; cache behavior is not documented and is **UNVERIFIED**. | Standard helpers, less mature conformance surface than browser reference suites. | Can discover an OS PAC URL and download it on construction. Automatic refresh/revalidation after construction is **UNVERIFIED**. |
| **proxydetox/paclib (notable Rust)** | Boa in-process on a dedicated Rust thread; no configured stack size or sandbox. | Reviewed source sets no Boa runtime limits, interrupt, wall timeout, source cap, or heap cap. A wedged evaluation blocks its worker. | Blocking `ToSocketAddrs`; five-minute in-engine cache, no lookup timeout. | Uses a bundled helper library but replaces `shExpMatch` with Rust `glob`, so it is materially less reference-faithful. | The surrounding proxy application loads configured PAC data; exact refresh/fetch-cache policy is **UNVERIFIED**. |

Primary implementation sources: Chromium
[`proxy_resolver.mojom`](https://chromium.googlesource.com/chromium/src/+/ea279e8b6c1f5d2afa57e3a76d8947852bbbfa99/services/proxy_resolver/public/mojom/proxy_resolver.mojom),
[`proxy_resolver_v8.cc`](https://chromium.googlesource.com/chromium/src/+/54bf0e07c2a7420e6b4a5f54367904b7d37f190e/services/proxy_resolver/proxy_resolver_v8.cc),
[`proxy_resolver_v8_tracing.cc`](https://chromium.googlesource.com/chromium/src/+/9b87875fdaaeb3964c4aabe8630b68be7f2b81e8/services/proxy_resolver/proxy_resolver_v8_tracing.cc),
and [poll policy](https://chromium.googlesource.com/chromium/src/+/refs/tags/137.0.7151.86/net/proxy_resolution/configured_proxy_resolution_service.cc);
Firefox [`ProxyAutoConfig.cpp`](https://searchfox.org/mozilla-central/source/netwerk/base/ProxyAutoConfig.cpp)
and [`nsPACMan.cpp`](https://searchfox.org/mozilla-central/source/netwerk/base/nsPACMan.cpp);
[pacparser site](https://pacparser.manugarg.com/) and
[`pacparser.c`](https://github.com/manugarg/pacparser/blob/main/src/pacparser.c);
[`go-pac`](https://pkg.go.dev/github.com/phlipse/go-pac@v0.1.1); and
[`proxydetox/paclib`](https://github.com/kiron1/proxydetox/tree/main/paclib).

Rama is stronger than the smaller in-process embedders on parser/compiler fault
containment, explicit guest memory/CPU/time limits, DNS/fetch/match/snapshot
budgets, and cache behavior. Unlike Chromium it still has no OS process sandbox:
Wasmtime and StarlingMonkey are one trusted in-process boundary, and a Rust host
callback runs outside it. Chromium and Firefox also remain stronger on browser
PAC discovery, OS integration, network-change handling, validator-aware fetch,
and mature refresh policy—table stakes rama intentionally does not yet supply.

## Stack-overflow decision

### What real embedders do

V8 exposes [`Isolate::SetStackLimit`](https://v8.github.io/api/head/classv8_1_1Isolate.html)
and threads the limit into its parser. Recursive parser paths call
`CheckStackOverflow`; crossing the limit records a stack-overflow parse error
instead of touching the native guard page
([`parser-base.h`](https://chromium.googlesource.com/v8/v8/+/4d0d31f41b8b4ff35ccbb1d0b5a1f4b51e270d8f/src/parsing/parser-base.h)).
Execution reports the familiar catchable `RangeError: Maximum call stack size
exceeded`. Chromium additionally runs the resolver factory in a sandboxed
utility service, so an engine failure does not normally take down the browser.

SpiderMonkey exposes
[`JS_SetNativeStackQuota`](https://searchfox.org/mozilla-central/source/js/src/jsapi.cpp).
Firefox explicitly sets it for the PAC context and allocates a bounded JS heap
before compiling the user script
([`ProxyAutoConfig.cpp`](https://searchfox.org/mozilla-central/source/netwerk/base/ProxyAutoConfig.cpp)).
It also serializes work on the PAC thread. The common pattern is therefore an
engine-enforced native-stack quota that turns recursion into an ordinary engine
error, plus a separate isolation boundary where the threat model warrants it;
a lexical source scan is not that mechanism.

A private allocator addresses a different resource: engine heap allocations.
The crash here consumes the worker thread's native call stack while recursive
Rust parser/compiler functions are executing. The system allocator is not
asked to extend that fixed thread stack, so an allocator byte limit cannot
observe or convert the guard-page fault into a `JsError`. A bounded engine heap
is still desirable, but it must accompany—not replace—native-stack checks.

### What Boa 0.21.1 provides

`Cargo.lock` resolves `boa_engine`, `boa_parser`, and `boa_gc` 0.21.1. Local
source inspection shows `RuntimeLimits::recursion_limit` compared only with
`vm.frames.len()` and `stack_size_limit` compared only with
`vm.stack.stack.len()` in `boa_engine/src/vm/mod.rs`. Parsing happens earlier in
`Script::parse`; the bytecompiler recursively calls `compile_expr` for unary,
binary, member, call, object, and other expression nodes without consulting
those runtime limits.

No upstream 0.21.1 API sets a native stack boundary for parse/compile or maps
that boundary to `JsError`. A reasonable upstream/fork point is a depth/stack
budget shared through `boa_parser` recursive descent and
`boa_engine::bytecompiler`, checked at each recursive entry and returned as a
normal parse/compile error. That is a multi-crate engine change, not a small
rama wrapper.

Boa 0.21.1 also does not expose a per-context allocator or a hard GC-heap
limit. `boa_gc` uses thread-local global collector state and ordinary `Box`
allocation; its internal byte threshold decides when to collect and grows with
the surviving set, so it is not a memory quota. A future engine API could make
heap allocation fallible against an embedder budget. Until then, an OS process
limit/subprocess is the only hard whole-engine memory boundary available to
rama without replacing or forking Boa—and it still would not turn recursive
native-stack exhaustion into a catchable JavaScript error.

### Chosen option: replace the private engine with a Wasm-contained one

The lexical `max_source_len`/`max_source_depth` scan and its shallow tests remain
deleted. A larger native worker stack was also removed: it could only move the
crash threshold and reserved 64 MiB of address space per worker without making
the property true. Maintaining a multi-crate Boa parser/compiler fork would have
added a second engine project to rama.

Instead, `rama-js` now checks in a pinned ComponentizeJS/StarlingMonkey artifact
and hosts it with Wasmtime. This changes no engine-agnostic value, host function,
namespace, or host-object type in the public API. Wasmtime is a private direct
dependency of `rama-js`; the temporary `starling-spike` feature is gone, and the
workspace dependency does not choose Wasmtime features on the crate's behalf.
Normal users need no Node.js or component build tool: Cargo packages the Wasm
artifact and compiles it to the host execution backend once per process. The
optional `JsRuntime::warm_up` moves that one-time work into application startup;
`rama-pac` does this when its resolver is built.

The checked-in component is 12,683,989 bytes raw. `cargo package --list`
confirms that it is included, and a tar/gzip approximation of the package files
was 4,208,942 bytes, below crates.io's 10 MiB archive limit. An exact
`cargo package` archive could not be produced because this workspace depends on
the not-yet-published `rama-core 0.3.1`; exact publishability is therefore
**UNVERIFIED**, while component compression itself is not currently the blocker.

`rama-js` selects Winch on ordinary desktop/server/mobile targets and Wasmtime's
Pulley interpreter on iOS, where creating executable pages for a JIT is not a
portable assumption. Wasmtime documents Pulley as its portable all-platform
baseline with Component Model parity; the tradeoff is materially slower guest
execution on iOS. Wasmtime itself currently classifies iOS as Tier 3, so iOS
runtime verification remains **UNVERIFIED** in this workspace.

This supplies the real property the source scan lacked:

- the recursive parser/compiler/interpreter executes on Wasm's checked stack;
- each store has a hard memory-growth limit, including the JavaScript heap;
- fuel bounds cumulative guest work and epochs interrupt it in wall-clock time;
- the component imports only rama's typed host-call interface, not ambient WASI;
- any such guest trap retires one runtime without unwinding through or
  overflowing the host's native parser stack.

The guarantee ends at the isolation boundary. Wasmtime and the component are
trusted native code, and arbitrary Rust callbacks execute in the host. A callback
which blocks forever still requires `JsWorker`'s caller timeout and can strand
that worker thread. Full Chromium-style OS sandboxing is not available to a
library without a helper executable/process contract, but Wasm gives rama an
in-process crash and resource boundary without imposing such deployment work on
crate users.

### Verification

- `cargo nextest run -p rama-js --all-features --no-fail-fast`: 97 passed.
- `cargo nextest run -p rama-pac --all-features --no-fail-fast`: 209 passed.
- `cargo nextest run --all-features --workspace`: 6,251 passed, 296 skipped.
- `cargo test --doc --all-features --workspace`: passed.
- `just fmt` and `just qq`: passed; `just qq` covered sort, format, all-target
  checks, no-std checks, clippy, docs, and extra checks.
- The supplied fuzz artifact passed a one-run macOS cargo-fuzz reproduction on
  the Wasm backend; the Linux LSan rerun remains **UNVERIFIED**.
- `rama-js` contains no PAC documentation, Boa dependency, Boa source, or
  engine type in its public API.

Protocol references used for the URI review:
[RFC 2397](https://www.rfc-editor.org/rfc/rfc2397) and
[RFC 8089](https://www.rfc-editor.org/rfc/rfc8089).
