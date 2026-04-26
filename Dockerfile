# SPDX-License-Identifier: MIT
# Copyright (c) 2026 idcat contributors

# Adapted from https://github.com/LukeMathWalker/cargo-chef
FROM rust:slim-trixie AS planner
COPY --from=nresare/cargo-chef:binonly /cargo-chef /bin/cargo-chef
WORKDIR /build

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:slim-trixie AS builder
WORKDIR /build
RUN apt update && apt install -y libssl-dev pkgconf
COPY --from=planner /bin/cargo-chef /bin/cargo-chef
COPY --from=planner /build/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --locked --release 

FROM gcr.io/distroless/cc-debian13:nonroot

COPY --from=builder /build/target/release/idcat /

ENTRYPOINT ["/idcat"]

