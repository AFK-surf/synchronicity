# Builds the csqlite port program against the system libsqlite3.
# No vendoring: the distro package is the single SQLite on the host,
# shared with whatever replication tooling (e.g. litestream) the
# operator runs beside us.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -std=c11
PRIV    := ../priv
TARGET  := $(PRIV)/csqlite

.PHONY: all clean check-header

all: check-header $(TARGET)

check-header:
	@echo '#include <sqlite3.h>' | $(CC) -E -x c - >/dev/null 2>&1 || \
	  { echo 'error: sqlite3.h not found — install libsqlite3-dev (or equivalent)' >&2; exit 1; }

$(TARGET): wrapper.c
	@mkdir -p $(PRIV)
	$(CC) $(CFLAGS) -o $@ wrapper.c -lsqlite3

clean:
	rm -f $(TARGET)
