# Builds the synch-rekor port program and stages it in priv/.
#
# The source is a workspace crate (crates/synch-rekor-port), not a copy: the
# whole point of the port program is that the rekor wire formats have exactly
# one implementation, and it is the one the client and the monitor use. This
# Makefile only builds it and puts it where cp_port_ffi:priv_path/1 looks,
# mirroring csqlite/Makefile.

CARGO    ?= cargo
PROFILE  ?= release
# `dev` is the one profile whose directory is not its name.
PROFILE_DIR := $(if $(filter dev,$(PROFILE)),debug,$(PROFILE))
ROOT     := ../..
PRIV     := ../priv
TARGET   := $(PRIV)/synch-rekor

.PHONY: all clean check-cargo

all: check-cargo $(TARGET)

check-cargo:
	@command -v $(CARGO) >/dev/null 2>&1 || \
	  { echo 'error: cargo not found — install Rust (https://rustup.rs)' >&2; exit 1; }

# Phony on purpose: cargo is the incremental build system here, and it knows
# about the crate's sources and its dependencies. Re-running it is cheap and
# a stale binary is a divergence between what this service verifies with and
# what the client verifies with, which is the one thing this must not have.
.PHONY: $(TARGET)
$(TARGET):
	$(CARGO) build --profile $(PROFILE) --manifest-path $(ROOT)/Cargo.toml \
	  -p synch-rekor-port
	@mkdir -p $(PRIV)
	install -m 0755 $(ROOT)/target/$(PROFILE_DIR)/synch-rekor $(TARGET)

clean:
	rm -f $(TARGET)
