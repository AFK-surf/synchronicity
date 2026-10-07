//! The trie's integration tests, in one binary.
//!
//! One binary rather than one per file: each would link the whole graph
//! again, and `cargo test` runs binaries one after another, so the deep
//! boundary tests could not overlap with anything. Filter by module to run
//! one subject, e.g. `cargo test -p synch-mpt --test integration -- deep_write_path::`;
//! the `#[ignore]`d stress tests run with `-- --ignored`.

mod complete_operation;
mod deep_write_path;
mod fanout_bomb;
mod hostile_structure;
mod ingest_boundary;
mod interrupted_walk;
mod properties;
mod publication_routing;
