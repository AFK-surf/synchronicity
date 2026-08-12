# synchronicity
omnipresent peer-to-peer file store

See [DESIGN.md](DESIGN.md) for the full architecture: iroh-based hierarchy-agnostic
networking, `mptsync` (Merkle-Patricia Trie anti-entropy) for metadata, bao/BLAKE3
hash-tree content addressing with verified random reads, static + DNSSEC-based
membership, per-node published versions, and SQLite-backed local metadata.
