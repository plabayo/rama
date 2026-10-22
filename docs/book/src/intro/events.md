# 📡 Events and Spans

Rama crates emit typed events for the facts they own: a quic handshake that
completed, a connection that moved to another path, a request that finished.
Your application listens to the ones it cares about and records them however it
wants: logs, metrics, a database, a debugger.

On top of events rama has spans: a start event with a guaranteed end event.
Tools like [tracing] and [dial9] hang their own spans and operations on those.

Everything lives in [`rama::telemetry::event`][event docs] and is unstable for
now: names and types may still change between releases.

## Events

An event is a plain struct with pub fields, one type per fact:

```rust
#[derive(Clone, Event)]
pub struct QuicHandshakeCompleted {
    pub connection: ConnectionId,
    pub side: Side,
    pub accepted_0rtt: bool,
}
```

There is no message, level or target. A listener that only wants some events
filters on the fields itself.

A component emits through an [`Emitter`][Emitter]:

```rust
// once, in a long-lived component such as an endpoint or a server
let emitter = Emitter::<QuicHandshakeCompleted>::new();

// for every handshake
emitter.emit_with(|| QuicHandshakeCompleted { connection, side, accepted_0rtt });
```

An application listens on the [`EventDispatcher`][EventDispatcher]:

```rust
let _subscription = EventDispatcher::global().subscribe(
    |event: &Emitted<'_, QuicHandshakeCompleted>| {
        record(event.event().connection, event.at());
    },
);
```

A few rules make this cheap and predictable:

- **When nobody listens, an emit costs close to nothing.** The closure that
  builds the event does not even run.
- **Listeners run inline, where the event is emitted.** They must be fast and
  must never block. Heavy work goes to a channel or a task of your own.
- **Listeners can not change what happens.** They only see facts. If something
  has to act on a fact to change behaviour, it belongs in the service stack,
  not in an event.
- **The time of an event is only read when asked for**, through
  `Emitted::at`, and is shared by all listeners of that event.
- **Dropping the `Subscription` unsubscribes.**
- **Resolve an `Emitter` once per long-lived component**, not per request or
  connection: resolving takes a lock. The emitter itself is `Copy`.

### Think of events as table rows

The easiest way to think about events: each event type is a table, each field
a column, and each emit adds a row. Ids are the keys you join on.

```
quic_handshake_completed (connection, side, accepted_0rtt)
quic_path_changed        (connection, local, peer)
```

"Which connections that used 0-RTT later moved to another path" is then a join
on `connection`:

```sql
SELECT p.connection, p.peer
FROM quic_handshake_completed h
JOIN quic_path_changed p USING (connection)
WHERE h.accepted_0rtt;
```

Nobody has to write SQL, though a listener could write every event as a row
into SQLite and this would just work. The model explains how events look:

- **One type per fact, plain columns.** No message strings or metadata.
- **Filtering is a `WHERE` on columns**, done by the listener.
- **Relations are keys, not a tree.** A request carries the id of its
  connection like a foreign key. There is no parent and no "current span".
- **Tables stay normalized.** The event that starts a unit carries the columns
  you would filter on, later events only carry the key.

### Ids

All listeners of an event type see all events of that type, so an event must
say what it belongs to. It does that with typed ids, such as
[`ConnectionId`][ConnectionId] and [`RequestId`][RequestId] in `rama::net::id`.
A request event carries its own id and the id of its connection. Your own ids
are made with `rama_core::define_id!`.

Whoever creates a connection or request inserts its id in the extensions.
Everyone else reads it from there, so all events about one connection share
the same id, whichever crate emits them.

## Spans

A rama span is probably not what you expect if you know [tracing]. It is a
pair of events: a start event, and an end event that always comes. There are
no fields recorded later, no parent span and no "current span". Spans relate
to each other through ids, like plain events. In the table model a span is two
tables with the same key, and its duration is a join.

```rust
#[derive(Clone, Event, SpanStart)]
#[span(end = JobFinished)]
pub struct JobStarted {
    pub job: JobId,
    pub kind: JobKind,
}

#[derive(Clone, Event)]
pub struct JobFinished {
    pub job: JobId,
    pub ok: bool,
}
```

A span is opened through a [`SpanEmitter`][SpanEmitter], resolved once like an
`Emitter`:

```rust
let spans = SpanEmitter::<JobStarted>::new();

let span = spans.open_with(
    || JobStarted { job, kind },
    move || JobFinished { job, ok: false }, // on_drop
);
```

The second closure, `on_drop`, is the end event of a span that is dropped
without being closed, for example because its task was cancelled. That is what
makes the end event guaranteed.

Work runs in a span through [`SpanFutureExt`][SpanFutureExt] for futures, and
`observe_sync` for sync code:

```rust
// a future that owns the span, which ends through on_drop when it is done
tokio::spawn(run(job).observe(span));

// a future that borrows the span, which stays open
run(job).observe_ref(&span).await;

// a future that closes the span with something from its output
run(job)
    .observe_and_close(span, |mut end, result| {
        end.ok = result.is_ok();
        end
    })
    .await;

// sync work
span.observe_sync(|| prepare(job));

// close by hand
span.close_with(|mut end| {
    end.ok = true;
    end
});
```

The closures that close a span get the event `on_drop` would have sent, so
whatever `on_drop` captured is not captured twice.

A span with no listener and no span adapter is inactive: it builds no events,
and its work runs as it is.

### Span adapters

Listeners on `JobStarted` and `JobFinished` see a span as two events. Some
tools need more: a tracing span has to be *entered* around the work, and so
does a dial9 operation. A [`SpanAdapter`][SpanAdapter] carries a rama span over
into such a tool:

```rust
pub trait SpanAdapter<S: SpanStart>: Send + Sync + 'static {
    type State: Send + Sync + 'static;

    fn open(&self, start: &Emitted<'_, S>) -> Option<Self::State>;
    fn enter(&self, state: &Self::State, poll: &mut dyn FnMut());
    fn close(&self, state: Self::State, end: &Emitted<'_, S::End>);
}
```

For each span, `open` returns the state the adapter keeps, such as a
`tracing::Span`, or `None` to skip the span. `enter` wraps the work, and
`close` gets the state back together with the end event. An adapter is added
with `EventDispatcher::add_span_adapter`, and rama ships two:

- [`TracingSpans`][TracingSpans] carries a rama span over into a tracing span.
- [`Dial9Operations`][Dial9Operations] carries a rama span over into a dial9
  operation.

A crate only opens its rama span, and does not have to pick a tool. Whoever
wants a tracing span for it adds `TracingSpans`.

The order nests like a stack:

1. span adapters open
2. start listeners run
3. the work runs
4. end listeners run
5. span adapters close

Steps 2 to 4 run inside every span adapter. So a listener sees the span's
tracing span and dial9 operation as the current one.

Rama's default tracing listeners skip a span's start and end, because its
tracing span already shows them. You can still add your own, for example to
log them.

### Rama's own span adapters and listeners

Rama crates ship span adapters for the spans they open, and listeners for the
events they emit. Nothing is added by default: an application adds them where
it sets up tracing:

```rust
let _span_adapters = SpanAdapters::new(EventDispatcher::global())
    .with_group(rama::telemetry::DefaultSpanAdapters::tracing)
    .with_group(rama::telemetry::DefaultSpanAdapters::dial9) // with the dial9 feature
    .build();

let _listeners = Listeners::new(EventDispatcher::global())
    .with_group(rama::telemetry::DefaultListeners::tracing)
    .build();
```

The defaults in `rama::telemetry` cover every enabled rama crate. Each crate
also has its own, such as `rama::tcp::telemetry::DefaultSpanAdapters`, and each
span type its own adapters, such as `TcpServerConnectionOpened::tracing_spans()`,
so you can pick exactly what you want, or add your own with `.with(..)`.
Everything stays added until the value `build` returns is dropped.

## Tests

There is one global dispatcher per process. A test that listens gets its own
dispatcher with `#[event::isolated]`, placed above `#[tokio::test]` or
`#[test]`:

```rust
#[event::isolated]
#[tokio::test]
async fn emits_on_handshake(dispatcher: EventDispatcher) {
    let _subscription = dispatcher.subscribe(..);
    ..
}
```

The test body runs in that dispatcher's scope, and so does everything rama
spawns from it, so tests running in parallel do not see each other's events.
Dispatchers live for the process or for a test, never per request or
connection.

[tracing]: https://tracing.rs/tracing/
[dial9]: ../dial9.md
[event docs]: https://ramaproxy.org/docs/rama/telemetry/event/index.html
[Emitter]: https://ramaproxy.org/docs/rama/telemetry/event/struct.Emitter.html
[EventDispatcher]: https://ramaproxy.org/docs/rama/telemetry/event/struct.EventDispatcher.html
[SpanEmitter]: https://ramaproxy.org/docs/rama/telemetry/event/struct.SpanEmitter.html
[SpanFutureExt]: https://ramaproxy.org/docs/rama/telemetry/event/trait.SpanFutureExt.html
[SpanAdapter]: https://ramaproxy.org/docs/rama/telemetry/event/trait.SpanAdapter.html
[ConnectionId]: https://ramaproxy.org/docs/rama/net/id/struct.ConnectionId.html
[RequestId]: https://ramaproxy.org/docs/rama/net/id/struct.RequestId.html
[TracingSpans]: https://ramaproxy.org/docs/rama/telemetry/tracing/struct.TracingSpans.html
[Dial9Operations]: https://ramaproxy.org/docs/rama/telemetry/dial9/struct.Dial9Operations.html
