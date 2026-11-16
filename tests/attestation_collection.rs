// Exercise the vendored collector's unit tests with the application's locked
// dependencies. The excluded vendor package has no independent Cargo.lock.
mod error {
    pub use elastic_tee_hal::error::{HalError, HalResult};
}

#[allow(dead_code)]
#[path = "../vendor/wasmhal/src/attestation.rs"]
mod attestation;
