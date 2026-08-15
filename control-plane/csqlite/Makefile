# Builds the csqlite port program against the system libsqlite3.
# No vendoring: the distro package is the single SQLite on the host,
# shared with whatever replication tooling (e.g. litestream) the
# operator runs beside us.

CC      ?= cc
CFLAGS  ?= -O2
# The warning and hardening set is not optional and survives an
# environment-supplied CFLAGS: this program parses length-framed bytes
# and opens database files written by external tooling.
# (-U_FORTIFY_SOURCE first: some toolchains predefine it, and a
# redefinition warning would trip -Werror.)
override CFLAGS += -std=c11 -Wall -Wextra -Werror -fno-common \
  -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
PRIV    := ../priv
TARGET  := $(PRIV)/csqlite

.PHONY: all clean check-header

all: check-header $(TARGET)

check-header:
	@echo '#include <sqlite3.h>' | $(CC) -E -x c - >/dev/null 2>&1 || \
	  { echo 'error: sqlite3.h not found — install libsqlite3-dev (or equivalent)' >&2; exit 1; }

$(TARGET): wrapper.c
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) -o $@ wrapper.c $(LDFLAGS) -lsqlite3

clean:
	rm -f $(TARGET)
