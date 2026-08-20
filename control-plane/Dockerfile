# syntax=docker/dockerfile:1
#
# Container image for the synchronicity control plane. Build context is
# `control-plane/`:
#
#   docker build -t controlplane control-plane
#
# The image ships the same pieces the systemd deployment does
# (ops/systemd/): the Gleam/OTP service as an Erlang shipment, the
# `csqlite` port program in `priv/`, the built SPA in `priv/web`, and the
# `synch` guide in `priv/skill`.
# It runs the primary and the replica alike — the role is `CP_ROLE`,
# and everything else is `CP_*` environment too (see README.md).
#
# Build-time versions track control-plane/.tool-versions and
# web/package.json. ERLANG_VERSION is the OTP patch the Docker library
# publishes, which trails asdf's by a release or two; bump both together
# when it catches up.
ARG ERLANG_VERSION=27.3.4.15
ARG GLEAM_VERSION=1.18.1
ARG NODE_VERSION=22
# gleam-lang/gleam's published .sha256 for each release tarball. Bump
# them with GLEAM_VERSION — a mismatch fails the build.
ARG GLEAM_SHA256_X86_64=4955a38c2e8c99457458e2471472ccd5ee3c45bd7637a315ce33bccf0dd75d9e
ARG GLEAM_SHA256_AARCH64=ea08a64846677f36da7f2e9163c4393dd9a9dee814d13a8fb28fbe7dcbf32f6d

# --- the dashboard SPA -------------------------------------------------
#
# JavaScript is architecture-independent, so this stage stays on the
# build platform: no emulated `npm ci` when building for arm64.
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm-slim AS web

WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npx tsc -b && npx vite build

# --- the Erlang shipment -----------------------------------------------
#
# `.beam` files are architecture-independent — the whole point of keeping
# SQLite in a separate OS process is that this project has no NIFs — so
# this stage also stays on the build platform. The one native artifact,
# `priv/csqlite`, is compiled per-architecture in the next stage.
FROM --platform=$BUILDPLATFORM erlang:${ERLANG_VERSION}-slim AS shipment
ARG GLEAM_VERSION
ARG GLEAM_SHA256_X86_64
ARG GLEAM_SHA256_AARCH64
ARG BUILDARCH

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    case "$BUILDARCH" in \
      amd64) gleam_arch=x86_64;  gleam_sha="$GLEAM_SHA256_X86_64" ;; \
      arm64) gleam_arch=aarch64; gleam_sha="$GLEAM_SHA256_AARCH64" ;; \
      *) echo "no gleam release for BUILDARCH=$BUILDARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gleam.tar.gz \
      "https://github.com/gleam-lang/gleam/releases/download/v${GLEAM_VERSION}/gleam-v${GLEAM_VERSION}-${gleam_arch}-unknown-linux-musl.tar.gz"; \
    echo "${gleam_sha}  /tmp/gleam.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gleam.tar.gz -C /usr/local/bin gleam; \
    rm /tmp/gleam.tar.gz; \
    gleam --version

WORKDIR /src

# Dependencies first: the manifest pins them, so this layer is reused
# across source edits.
COPY gleam.toml manifest.toml ./
RUN gleam deps download

COPY src/ ./src/
# The SPA is served out of priv/web (src/api/static.gleam), so it has to
# be in place before the export copies priv/ into the shipment. So do the
# trusted root and the CLI guide: tuf/trusted_root.gleam reads
# priv/tuf/sigstore_trusted_root.json and api/skill.gleam reads
# priv/skill/SKILL.md at runtime — tracked source files, so a plain COPY
# ships them (only the build-artifact paths under priv/ are dockerignored).
# image-smoke.sh asserts they are actually there, because a build that
# drops one still boots and serves and passes every other check.
COPY --from=web /src/web/dist/ ./priv/web/
COPY priv/tuf/ ./priv/tuf/
COPY priv/skill/ ./priv/skill/
RUN gleam export erlang-shipment

# --- the csqlite port program ------------------------------------------
#
# Native code, built for the target architecture against the same
# bookworm libsqlite3 the runtime stage installs. Cheap to emulate: one
# C file.
FROM debian:bookworm-slim AS csqlite

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends gcc libc6-dev make libsqlite3-dev; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY csqlite/ ./csqlite/
RUN make -C csqlite

# --- runtime -----------------------------------------------------------
FROM erlang:${ERLANG_VERSION}-slim AS runtime

# libsqlite3-0: csqlite links against the system SQLite, deliberately —
# it is shared with whatever replication tooling the operator runs
# beside us. ca-certificates: outbound TLS to the Rekor log, the
# Sigstore TUF repository, the DoH resolver and the OAuth providers.
# curl: the HEALTHCHECK below.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libsqlite3-0 ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 synch; \
    useradd --system --uid 10001 --gid 10001 --no-create-home \
      --home-dir /opt/synch-controlplane --shell /usr/sbin/nologin synch

COPY --from=shipment /src/build/erlang-shipment/ /opt/synch-controlplane/
COPY --from=csqlite --chmod=0755 /src/priv/csqlite \
  /opt/synch-controlplane/controlplane/priv/csqlite

# The database gets its own directory: each csqlite worker sandboxes
# itself to exactly that directory (Landlock on Linux), so the zone key
# must live somewhere else — mount it at /etc/synch-controlplane/ and
# point CP_KEY_FILE there on the primary.
#
# Both directories are owned by the service user so that a fresh named
# volume mounted over either one inherits that ownership — including
# /etc/synch-controlplane, so `docker run … keygen … /etc/synch-controlplane/csk.key`
# can write the key on first setup.
RUN set -eux; \
    mkdir -p /var/lib/synch-controlplane/db /etc/synch-controlplane; \
    chown -R 10001:10001 /var/lib/synch-controlplane /etc/synch-controlplane

# Only paths, not policy: every CP_* value that decides what the service
# *is* stays required and unset (CP_ROLE, CP_BASE_DOMAIN, CP_KEY_FILE,
# CP_SESSION_SECRET, ...). CP_KEY_FILE in particular must stay unset
# here — a replica refuses to start if it is set at all.
ENV CP_DB_PATH=/var/lib/synch-controlplane/db/cp.db

VOLUME ["/var/lib/synch-controlplane"]
USER 10001:10001
WORKDIR /opt/synch-controlplane

# Dashboard/API/DoH, and authoritative DNS. Binding 53 as a non-root
# user works under Docker, which sets net.ipv4.ip_unprivileged_port_start=0
# in the container. Runtimes that do not (Kubernetes) need either that
# sysctl or a high CP_DNS_LISTEN port behind a mapping.
EXPOSE 8080/tcp 53/udp 53/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${CP_HEALTHCHECK_PORT:-8080}/healthz" >/dev/null || exit 1

# The shipment's entrypoint takes `run <args...>`; the args are the
# service's own subcommands, so `docker run … keygen <apex> <file>`,
# `… rekor-publish`, `… migrate-check` and friends all work. It is run
# through an explicit `/bin/sh` because the generated script opens with
# SPDX comments and has no shebang on its first line — exec'ing it
# directly is an exec format error.
ENTRYPOINT ["/bin/sh", "/opt/synch-controlplane/entrypoint.sh", "run"]
CMD ["serve"]
