# ❓FAQ

## Why the name "rama"?

The name _rama_ is Japanese for llama and written as "ラマ".
This animal is used as a our mascot and spiritual inspiration of this proxy framework.
It was chosen to honor our connection with Peru, the homeland of this magnificent animal,
and translated into Japanese because we gratefully have built _rama_
upon the broad shoulders of [Tokio and its community](https://tokio.rs/).

Note that the Tokio runtime and its ecosystems sparked initial experimental versions of Rama,
but that we since then, after plenty of non-published iterations, have broken free from that ecosystem,
and are now supporting other ecosystems as well. In fact, by default we link not into any async runtime,
and rely only on the `std` library for for any future/async primitives.

## Can Tower be used?

Initially Rama was designed fully around the idea of Tower. The initial design of Rama took many
iterations and was R&D'd over a timespan of almost 2 years. We switched between `tower`,
`tower-async` (our own public fork of tower) and back to `tower` again...

It became clear however that the version of `tower` at the time was incompatible with the ideas
which we wanted it to have:

- We are not interested in the `poll_ready` code of tower,
  and in fact it would be harmful if something is used which makes use of it
  (Axum warns for it, but strictly it is possible...);
- We want to start to prepare for an `async`-ready future as soon as we can...

All in all, it was clear after several iterations that usage of tower did more
harm then it did good. It does mean that we cannot rely on the wide tower ecosystem, but so be it...
for the time being at least.
