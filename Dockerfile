# syntax=docker/dockerfile:1
#
# Container image for the synchronicity tools — the three Linux binaries a
# deployment runs: `synch` (the CLI and the daemon), `synch-s3` (the
# S3-compatible gateway, §9.4) and `synch-dp` (the cloud data plane,
# `docs/CLOUD-DATAPLANE.md`). The control plane is a separate service in a
# separate language and keeps its own image (`control-plane/Dockerfile`).
#
# One image rather than three: the gateway is a control client of the daemon
# and the data plane embeds the same engine, so the three are deployed
# together far more often than apart, and a shared image is one tag to pin,
# one provenance attestation to verify, and one set of layers to pull. There
# is no ENTRYPOINT wrapper — every binary is on PATH and the first argument
# names the tool:
#
#   docker run --rm IMAGE synch --version
#   docker run --rm IMAGE synch-s3 --help
#   docker run --rm -e SYNCH_DP_CONTROL_URL=… IMAGE synch-dp
#
# Build context is the repository root:
#
#   docker build -t synch-tools .
#
ARG RUST_VERSION=1.94

# --- the binaries ------------------------------------------------------
#
# Pinned to $BUILDPLATFORM and cross-compiled, not emulated: a QEMU'd
# rustc building this workspace — aws-lc-rs, the bundled SQLite, the whole
# dependency graph — costs hours where `zig cc` as the cross-linker costs
# the same as a native build. `cargo-zigbuild` is the same cross-compiler
# release.yml uses for its Linux artifacts.
#
# glibc, pinned to the runtime image's 2.36 (bookworm), rather than the
# static musl the release tarballs carry: the three programs here are
# long-running servers, and musl's allocator under a many-threaded load is
# the one thing that would differ from the configuration every test in CI
# runs against. The pin is what keeps that honest — a target of
# `…-linux-gnu.2.36` links against 2.36 symbols whatever the builder's own
# glibc is, so the binaries cannot depend on something bookworm does not
# have.
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-bookworm AS build
ARG TARGETARCH

# `cargo-zigbuild` pinned like every other build input here; `ziglang` is
# the zig toolchain as a wheel, which is how release.yml installs it too.
# Bump the two together — cargo-zigbuild tracks zig's command line, which
# is not stable across zig releases.
ARG CARGO_ZIGBUILD_VERSION=0.23.3
ARG ZIG_VERSION=0.16.0
# The runtime image's glibc. Bump it with the runtime base, never above
# it: this is the oldest glibc the binaries are allowed to need.
ARG GLIBC_VERSION=2.36

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3-pip; \
    rm -rf /var/lib/apt/lists/*; \
    pip3 install --break-system-packages --no-cache-dir "ziglang==${ZIG_VERSION}"; \
    cargo install cargo-zigbuild --locked --version "${CARGO_ZIGBUILD_VERSION}"; \
    rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

WORKDIR /src

# Only what the workspace builds from. The control plane, the docs and the
# TLA+ specs are not inputs, and .dockerignore keeps them out of the
# context so editing them cannot invalidate this layer.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY vendor/ ./vendor/

# --locked: the image is built from the lockfile the tests ran against, and
# a build that would have to update it fails instead.
#
# The target cache is keyed by architecture: both platforms of a
# multi-arch build run this stage at once, and one shared target/ would
# serialize them behind the lock for no benefit — they share no artifacts.
# The binaries are then copied out of it, because a cache mount is not
# part of the layer it ran in. They land under the *unsuffixed* triple:
# the glibc version is an instruction to the linker, not a directory.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=synch-cargo-registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=synch-target-$TARGETARCH,sharing=locked \
    set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    cargo zigbuild --release --locked --target "$target.$GLIBC_VERSION" \
      --bin synch --bin synch-s3 --bin synch-dp; \
    mkdir -p /out; \
    cp "target/$target/release/synch" \
       "target/$target/release/synch-s3" \
       "target/$target/release/synch-dp" /out/

# --- runtime -----------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates is the one thing installed here, and it is not
# optional: every TLS client in this workspace verifies against the
# host's trust store rather than a bundle compiled in at build time
# (`synch_net::tls`), so an image without it fails on the first DoH
# lookup, relay dial or S3 request. Nothing else is needed — SQLite is
# compiled in and TLS is rustls, so the binaries link nothing but glibc.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 synch; \
    useradd --system --uid 10001 --gid 10001 --no-create-home \
      --home-dir /var/lib/synch --shell /usr/sbin/nologin synch

COPY --from=build --chmod=0755 /out/synch /out/synch-s3 /out/synch-dp \
  /usr/local/bin/

# Owned by the service user so that a fresh named volume mounted over
# either one inherits that ownership — the process is not root and cannot
# chown a root-owned directory it is handed.
#
# /var/lib/synch is the daemon's data directory: the database, the CAS and
# the control socket. /var/lib/synch-dp is the data plane's scratch, which
# is genuinely ephemeral — one directory per hosted tenant, restored from
# object storage after a reschedule (`docs/CLOUD-DATAPLANE.md` §4.2) — and
# gets a directory rather than a volume for exactly that reason.
RUN set -eux; \
    mkdir -p /var/lib/synch /var/lib/synch-dp; \
    chown 10001:10001 /var/lib/synch /var/lib/synch-dp

# Paths, not policy: these two say *where* state lives, and nothing about
# what this container is. Every setting that decides that — the membership
# domain, the CAS backend and its credentials, the data plane's control
# URL and token — stays unset and required, so a misconfigured container
# fails at startup instead of running as something nobody asked for.
#
# SYNCH_DATA_DIR in particular has to be set: without it the CLI asks the
# platform for a data directory, and a container with no HOME has none.
ENV SYNCH_DATA_DIR=/var/lib/synch \
    SYNCH_DP_BASE_DIR=/var/lib/synch-dp

VOLUME ["/var/lib/synch"]
USER 10001:10001
WORKDIR /var/lib/synch

# 9000/tcp is the gateway's default listen port (`synch-s3 serve`), which
# has to be pointed at 0.0.0.0 to be reachable from outside the container:
# it binds 127.0.0.1:9000 by default, deliberately, and `--listen` is how
# an operator says otherwise. The daemon's own QUIC endpoint takes an
# ephemeral UDP port unless `--bind` names one, so there is nothing fixed
# to declare for it.
EXPOSE 9000/tcp

# No ENTRYPOINT: this image ships three tools and the command names which
# one runs. `synch` alone is the useful default — it prints its usage.
CMD ["synch", "--help"]
