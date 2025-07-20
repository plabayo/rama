use turmoil::Builder;

fn main() {
    // NOTE:
    // To make your tests deterministic, you can use your own seeded `rng` provider when building
    // the simulation through `build_with_rng`.

    let mut sim = Builder::new().build();

    sim.host("server", || async { Ok(()) });

    sim.client("client", async { Ok(()) });
}
