use rama_macros::paste;

paste! {
    fn [<0 f>]() {}
}

paste! {
    fn [<f '"'>]() {}
}

paste! {
    fn [<f "'">]() {}
}

fn main() {}
