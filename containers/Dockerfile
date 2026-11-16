# Build a Linux worker and its libraries together. Do not copy a Mac binary or
# an executable linked against the VM's potentially newer glibc into this image.
ARG RUST_IMAGE=rust:1.98.1-bookworm
FROM ${RUST_IMAGE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake pkg-config libssl-dev libtss2-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY wit ./wit
COPY wit-orchestration ./wit-orchestration
COPY vendor ./vendor
ARG CARGO_BUILD_JOBS=2
RUN cargo build --release --locked --bin hal-on-demand --jobs ${CARGO_BUILD_JOBS}

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libtss2-esys-3.0.2-0 libtss2-tctildr0 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /config /run/broker /run/worker /state
COPY --from=build /build/target/release/hal-on-demand /usr/local/bin/hal-on-demand
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/hal-on-demand"]
CMD ["--help"]
