# Graceful scopes

Rama shuts down in two phases, the same way in every component:

1. **Graceful** (cancelled): stop taking new work, finish what is in flight.
   An HTTP server sends a GOAWAY or closes after the current response, a listener
   stops accepting, a worker finishes the jobs it already accepted.
2. **Hard** (aborted): stop now. Whatever is still running is dropped.

Both phases live on a
[`Scope`](https://ramaproxy.org/docs/rama/graceful/struct.Scope.html), a node in a tree
of scopes. A phase flows from a parent to its children, never the other way around, and
the earliest cause wins. A process usually has one root scope, cancelled by Ctrl+C or
SIGTERM, with a grace that bounds how long the drain may take before the hard phase
starts on its own.

Every unit of work gets a scope of its own below the scope it runs in: a connection, a
request, a relay. That is where the knobs live, the same ones everywhere: a max age that
starts the graceful phase, a grace that bounds it, a hard max age, a signal that triggers
it, optionally after a delay. A
[`ScopeLayer`](https://ramaproxy.org/docs/rama/layer/struct.ScopeLayer.html) applies them
to any service. Work that belongs to more than one scope, say a connection that came in
through one executor and is served by another, gets a scope below all of them: it ends as
soon as any of them does.

Holding a scope keeps its drain open, and joining a scope waits until nobody holds it
anymore. Only running work holds. Every task an
[`Executor`](https://ramaproxy.org/docs/rama/rt/struct.Executor.html) spawns holds its
scope until it ends, so joining the root waits for all of them, while the executor itself
only observes, and so does a client, layer or service built with it: keeping one around
never holds up a shutdown. A weak scope only observes too: it is what travels with an
input in its extensions, so a request that is kept around never holds up a shutdown
either.

Once a scope is cancelled and nobody holds it anymore, it is closed and admits no new
work. An executor of a closed scope refuses to spawn and hands the refused task back to
its caller, together with the cause. Whoever holds a scope can always spawn on it.

Components follow one rule:

- protocols that can drain (HTTP/1, HTTP/2, HTTP/3, ttRPC) drain in the graceful phase
  and are dropped in the hard phase;
- byte and datagram relays cannot drain, so they keep relaying through the graceful
  phase and stop at the hard phase, together with everything else.

There is no other kind of cancel to learn.
