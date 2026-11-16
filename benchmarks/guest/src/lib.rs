pub mod algorithms;
#[cfg(target_arch = "wasm32")]
include!(concat!(env!("OUT_DIR"), "/selection.rs"));
#[cfg(target_arch = "wasm32")]
wit_bindgen::generate!({path: "wit", world: "benchmark"});
#[cfg(target_arch = "wasm32")]
struct Workload;
#[cfg(target_arch = "wasm32")]
impl exports::elastic::hal::run::Guest for Workload {
    fn run() -> Vec<u8> {
        algorithms::execute(INDEX).into_bytes()
    }
}
#[cfg(target_arch = "wasm32")]
export!(Workload);
