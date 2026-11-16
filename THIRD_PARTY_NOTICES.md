# Third-party notices and project license status

The project-wide license is undecided. No license for the original project code
is added by this distribution. Keeping third-party license text does not apply
that license to the rest of the repository.

## Vendored Wasm HAL

`vendor/wasmhal/` retains its existing [MIT license](vendor/wasmhal/LICENSE),
including the copyright notice for the ELASTIC TEE HAL Contributors.
[vendor/SNAPSHOT.json](vendor/SNAPSHOT.json) records the supplied snapshot,
file hashes and local modifications. The upstream license is preserved verbatim.

## Vendored access-profile implementation

`vendor/hal-access-profile/` retains its source and
[upstream provenance](vendor/hal-access-profile/UPSTREAM.json). The supplied
snapshot has no separate license file for this component. This notice does not
assign it a license; its redistribution terms remain to be resolved with the
project-wide licensing decision.

## Dependencies and test fixtures

Cargo manifests and lockfiles identify Rust dependencies. Python dependencies
are listed in `requirements-signing.txt`. Their respective authors' license
terms apply; this repository does not relicense them.

The five original `.wasm` files in `tests/workloads/` are retained as functional
test fixtures. Their identities and checksums are recorded in `workloads.json`.
No separate license or source-build recipe was supplied for those binaries in
this snapshot. They are not assigned a new license here. The 15 computational
benchmark workloads have source under `benchmarks/guest/`.

The Trustee image is referenced by digest in `examples/trustee/prebuilt-image.json`;
it is not bundled. gVisor, Docker, Rust, Wasmtime and other external tools retain
their own license terms.
