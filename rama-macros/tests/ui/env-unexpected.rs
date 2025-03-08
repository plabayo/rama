use rama_macros::paste;

paste! {
    fn [<env!("VAR" "VAR")>]() {}
}

fn main() {}
