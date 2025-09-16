# Patterns used inside rama

## Working around the orphan rule in specific cases
Rama is composed of many smaller, more focused crates. Splitting a large monolithic crate into several smaller ones offers many advantages, such as improved modularity and reusability, but it also comes with some drawbacks. The most significant among them is the limitation imposed by Rust's orphan rule. This rule *dictates* that in order to implement a trait for a type, either the trait or the type must be defined in the current crate. It does this for one very valid reason: trait coherence, which means there should be only one implementation for a trait for a specific type. This is needed to prevent conflicting implementations, to prevent that external crates with overlapping implementations cause unexpected behaviour, or that some crates suddenly break after a patch or minor update... There have been lots of discussions online already about relaxing the orphan rule, but so far nothing really has happened.

So how to satisfy the orphan rule under normal circumstances? Easy, you make sure you own either the trait or type. So if you want to implement an external trait, you have to create a local type for which you can implement it. This pattern is really useful and is used all throught the rust ecosystem, and even has a name: the newtype pattern. It's not only used to satisfy the orphan rule, but here we will only be focussing on that.

```rust
crate traits {
    trait IsAvailable {
        fn is_available(&self) -> bool;
    }
}

crate types {
    pub struct StoreItem {
        pub is_available: bool,
        pub price: usize,
    }

    pub trait Price {
        fn price(&self) -> usize;
    }

    impl Price for StoreItem {
        fn price(&self) -> usize {
            self.price
        }
    }
}

use traits::IsAvailable;
use types::StoreItem;

// This will not work
// impl IsAvailable for StoreItem {
//     fn is_available(&self) -> bool {
//         self.is_available
//     }
// }

// Instead create a local wrapper
struct LocalType(StoreItem);

impl IsAvailable for LocalType {
    fn is_available(&self) -> bool {
        self.0.is_available
    }
}
```

But this has a lot of disadvantages:
1. Creating local types is a very tedicious thing to, do with lots of boilerplate (generic local types help with this, but it's still a pain)
2. All traits from the StoreItem have to be re-implemented (here Price has to be implemented for LocalType)
3. If traits cannot be re-implemented (eg because of sealed traits) you loose that functionality
4. ...

There is however a clever trick you can do if you can change the trait definition, namely adding a MarkerGeneric:

```rust
crate traits {
    trait IsAvailable<CrateMarker = ()> {
        fn is_available(&self) -> bool;
    }

    struct AlwaysAvailable;

    // When normal orphan rules apply we don't have to specify the `CrateMarker` generic
    impl IsAvailable for AlwaysAvailable {
        fn is_available(&self) -> bool {
            true
        }
    }
}

crate types {
    #[derive(Default)]
    pub struct StoreItem {
        pub is_available: bool,
        pub price: usize,
    }

    pub trait Price {
        fn price(&self) -> usize;
    }

    impl Price for StoreItem {
        fn price(&self) -> usize {
            self.price
        }
    }
}

use traits::{IsAvailable, AlwaysAvailable};
use types::StoreItem;

#[non_exhaustive]
struct MyCrateMarker;

// Orphan rule prevents us from implementing `IsAvailable` directly
// But by introducing the LOCAL MyCrateMarker we can implement it
impl IsAvailable<MyCrateMarker> for StoreItem {
    fn is_available(&self) -> bool {
        self.is_available
    }
}

fn test() {
    let always = AlwaysAvailable;
    let item = StoreItem::default();

    // This just works because there are no conflicts
    assert!(always.is_available());
    assert!(!item.is_available());

    // This also works because we still have the original type
    assert_eq!(!item.price(), 0);
}

// This does add a new generic in places where you want to accept anything that implement IsAvailable
fn generic_input<CrateMarker>(input: impl IsAvailable<CrateMarker>) -> bool {
    input.is_available()
}
```

This approach will be used by Rama in places where we wish to work around the orphan rule. One example of this is: implementing `From` for TLS types defined `rama-net` and doing this for external types without using the newtype pattern in crates such `rama-tls-boring` and `rama-tls-rustls`. For that exact use case we have introduced `RamaFrom` (and `RamaInto`, `RamaTryFrom`, `RamaTryFrom`). This also means that community crates can provide other TLS implementations and types in adapter like crates.

This approach does have one major issue: it's posssible to break coherence. This happens when a trait is implement twice for the same type. This sounds worse then it actually is, because it's easily fixed by manually specifying the generic `CrateMarker`. It's also important to note that under normal circumstances collisions should never happen (unless external crates do introduce overlapping implementations). If external crate do introduce overlapping implementations, you as the end user have two options: remove one of the crates that is providing overlapping implementations, or manually specifiy the CreateMarker where it's causing collisions:

```rust
crate traits {
    pub trait IsAvailable<CrateMarker = ()> {
        fn is_available(&self) -> bool;
    }
}

crate types {
    use traits::IsAvailable;

    #[derive(Default)]
    pub struct StoreItem {
        pub is_available: bool,
    }

    // We dont need to specify CrateMarker because this is a local type
    impl IsAvailable for StoreItem {
        fn is_available(&self) -> bool {
            true
        }
    }
}

use traits::IsAvailable;
use types::StoreItem;

#[non_exhaustive]
struct MyCrateMarker;

impl IsAvailable<MyCrateMarker> for StoreItem {
    fn is_available(&self) -> bool {
        !self.is_available
    }
}

fn test() {
    let item = StoreItem::default();

    // Because of conflicting implementations we now have to specify our CrateMarker
    assert!(IsAvailable::<()>::is_available(&item));
    assert!(!IsAvailable::<MyCrateMarker>::is_available(&item));
}
```