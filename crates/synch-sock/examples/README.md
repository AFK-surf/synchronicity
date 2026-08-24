# Socket examples

Six programs, each demonstrating one thing, each a program you could arm as it
stands. `docs/SOCKETS.md` is the design; this is what it looks like written
down.

Build one with the compiler inside the binary — nothing to install, no clang,
no BPF backend:

```sh
synch socket build echo.c -o echo.o
```

Then publish and arm it. A socket is a file in one of this node's spaces whose
content is that object; `add` declares the path to be a socket, and `arm`
prints what the program says it needs and asks you to approve it:

```sh
cp echo.o ~/synchronicity/code/echo.sock
synch socket add code/echo.sock
synch socket arm code/echo.sock
```

And call it from another node in the cluster:

```sh
synch connect nas:code/echo.sock
```

| | what it is for | what to read it for |
| --- | --- | --- |
| [`echo.c`](echo.c) | echoes the stream back | the smallest complete socket: a declaration hook, one poll loop, a clean end |
| [`whoami.c`](whoami.c) | reports the caller's identity | which facts come from the handshake and which are the caller's own text |
| [`tree-cat.c`](tree-cat.c) | serves one directory of the tree | validating caller input before it reaches a path, and cold reads as poll waits |
| [`http-status.c`](http-status.c) | a status page over HTTP | speaking a real protocol, and state that outlives the invocation |
| [`tcp-proxy.c`](tcp-proxy.c) | forwards to one upstream | declared egress, per-caller rate limits, and a bidirectional loop that ends correctly |
| [`token-gate.c`](token-gate.c) | checks a shared secret | config as a secret store, and a constant-time comparison |

Every one of them is compiled and run by `../tests/examples.rs` on each build,
against the same runtime that serves them in a daemon — so an example that
stopped working would fail the build rather than fail a reader.

## Three things about the machine you are writing for

1. **32 KiB of stack, no heap, no mutable globals.** A large buffer is a stack
   buffer, and the binding limit is the *frame* — 4 KiB per function — not the
   whole stack. State that must outlive the invocation goes in the socket map
   (`sy_map_*`). A `static` you write to will not link.

2. **Nothing blocks except `sy_poll`.** Every read and write returns
   immediately, with a short count or `SY_EAGAIN`. A short write is
   backpressure, not failure. Write an event loop; `sy_pump` and `sy_write_all`
   in the header are the two shapes almost every socket wants.

3. **Authorization is the handshake.** `sy_peer_origin`, `sy_peer_kind` and
   `sy_peer_has_space` read an identity iroh authenticated before the program
   started. `sy_conn_meta` is the caller's own text and is none of those
   things — `whoami.c` prints the two under separate headings for a reason.

## Building with clang instead

The embedded compiler is tinycc: small, fast, and not an optimizing compiler. A
program that outgrows it is armed exactly the same way — the runtime loads an
ELF object and does not care which compiler wrote it:

```sh
synch socket sdk > synch.h
clang -target bpf -O2 -g0 -mllvm -bpf-stack-size=4096 -I. -c echo.c -o echo.o
```
