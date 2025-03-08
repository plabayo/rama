use rama_macros::paste;

paste! {
    fn [<env!("VAR"suffix)>]() {}
}

fn main() {}
