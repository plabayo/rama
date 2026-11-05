# Patterns used inside rama

## Working around the orphan rule in specific cases
Rama is composed of many smaller, more focused crates. Splitting a large monolithic crate into several smaller ones offers many advantages, such as improved modularity and reusability, but it also comes with some drawbacks. The most significant among them is the limitation imposed by Rust's orphan rule. This rule *dictates* that in order to implement a trait for a type, either the trait or the type must be defined in the current crate. It does this for one very valid reason: trait coherence, which means there should be only one implementation for a trait for a specific type. This is needed to prevent conflicting implementations, to prevent that external crates with overlapping implementations cause unexpected behaviour, or that some crates suddenly break after a patch or minor update... There have been lots of discussions online already about relaxing the orphan rule, but so far nothing really has happened.

So how to satisfy the orphan rule under normal circumstances? Easy, you make sure you own either the trait or type. So if you want to implement an external trait, you have to create a local type for which you can implement it. This pattern is really useful and is used all through the rust ecosystem, and even has a name: the newtype pattern. It's not only used to satisfy the orphan rule, but here we will only be focusing on that.

Take three crates: a `traits` crate that defines an `IsAvailable` trait, a `types` crate that defines a `StoreItem` struct
and implements its own `Price` trait for it, and your own crate that depends on both. Your crate cannot implement `IsAvailable`
for `StoreItem`, because it owns neither. With the newtype pattern you wrap it in a local type, such as `LocalType(StoreItem)`,
and implement `IsAvailable` for that wrapper instead.

But this has a lot of disadvantages:
1. Creating local types is a tedious thing to do, with lots of boilerplate (generic local types help with this, but it's still a pain)
2. All traits from the StoreItem have to be re-implemented (here Price has to be implemented for LocalType)
3. If traits cannot be re-implemented (eg because of sealed traits) you lose that functionality
4. ...

There is however a clever trick you can do if you can change the trait definition, namely adding a marker generic
with a default: `IsAvailable<CrateMarker = ()>`.

- Implementations that already satisfy the orphan rule, such as one in the `traits` crate for its own `AlwaysAvailable` type,
  do not have to name the marker and use the default `()`.
- Your crate defines a local marker type, `MyCrateMarker`, and implements `IsAvailable<MyCrateMarker>` for `StoreItem`.
  The local marker makes the implementation pass the orphan rule.
- `StoreItem` stays the original type, so `Price` and its other traits keep working,
  and calls to `is_available` need no annotation as long as only one implementation exists.
- Functions that accept anything implementing the trait need the extra generic as well,
  taking an `impl IsAvailable<CrateMarker>` with `CrateMarker` as a generic parameter of the function.

This approach will be used by Rama in places where we wish to work around the orphan rule. One example of this is: implementing `From` for TLS types defined in `rama-tls` and doing this for external types without using the newtype pattern in crates such `rama-tls-boring` and `rama-tls-rustls`. For that exact use case we have introduced [`RamaFrom`](https://ramaproxy.org/docs/rama/conversion/trait.RamaFrom.html)
(and [`RamaInto`](https://ramaproxy.org/docs/rama/conversion/trait.RamaInto.html),
[`RamaTryFrom`](https://ramaproxy.org/docs/rama/conversion/trait.RamaTryFrom.html),
[`RamaTryInto`](https://ramaproxy.org/docs/rama/conversion/trait.RamaTryInto.html)), defined in
[`rama-core/src/conversion.rs`](https://github.com/plabayo/rama/blob/main/rama-core/src/conversion.rs).
The TLS crates implement them with their own markers, `RamaTlsBoringCrateMarker` and `RamaTlsRustlsCrateMarker`; see
[`rama-tls-boring/src/type_conversion.rs`](https://github.com/plabayo/rama/blob/main/rama-tls-boring/src/type_conversion.rs) and
[`rama-tls-rustls/src/type_conversion.rs`](https://github.com/plabayo/rama/blob/main/rama-tls-rustls/src/type_conversion.rs). This also means that community crates can provide other TLS implementations and types in adapter like crates.

This approach does have one drawback: a type can implement the trait more than once, once per `CrateMarker`. Each marker makes it a different trait, so coherence still holds, but a call such as `item.is_available()` becomes ambiguous and the compiler can no longer infer which implementation to use. It is fixed by specifying the generic `CrateMarker` manually. Under normal circumstances this should not happen, unless external crates introduce overlapping implementations. If they do, you as the end user have two options: remove one of the crates that is providing overlapping implementations, or manually specify the `CrateMarker` where the call is ambiguous.

For example, when the `types` crate implements `IsAvailable` for `StoreItem` itself (with the default `()` marker)
and your crate also implements `IsAvailable<MyCrateMarker>` for it, a plain `is_available` call on a `StoreItem` no longer compiles.
Use fully qualified syntax that names the marker, `IsAvailable::<()>` or `IsAvailable::<MyCrateMarker>`, to pick one.
