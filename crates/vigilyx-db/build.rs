// The semantic seed is owned by the sibling engine crate. Keep these paths
// relative to this package so Cargo rechecks the current checkout, including
// when a persistent target cache is reused by an isolated source snapshot.
fn main() {
    for path in [
        "../../shared/schemas/engine_module_data_seed.json",
        "../vigilyx-engine/src/semantic/data/context.json",
        "../vigilyx-engine/src/semantic/data/scenarios.json",
        "../vigilyx-engine/src/semantic/data/relations.json",
        "../vigilyx-engine/src/semantic/data/scan.json",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
}
