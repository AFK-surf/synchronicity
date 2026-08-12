//! Formatting shared by the daemon's request handlers.
//!
//! These build the lines that cross the control socket; the CLI prints them
//! verbatim.

use synch_core::now_ns;
use synch_engine::{EntryRef, Node};

use crate::control::ControlError;

type Lines = Result<Vec<String>, ControlError>;

/// Renders an endpoint address, with its direct and relay paths.
pub fn addr(addr: &iroh::EndpointAddr) -> String {
    let parts: Vec<String> = addr
        .ip_addrs()
        .map(|a| a.to_string())
        .chain(addr.relay_urls().map(|u| u.to_string()))
        .collect();
    if parts.is_empty() {
        addr.id.to_z32()
    } else {
        format!("{} via {}", addr.id.to_z32(), parts.join(", "))
    }
}

/// The name of an entry kind, as `ls` and `status` print it.
pub fn kind_name(kind: synch_core::EntryKind) -> &'static str {
    match kind {
        synch_core::EntryKind::File => "file",
        synch_core::EntryKind::Dir => "dir",
        synch_core::EntryKind::Symlink => "symlink",
        synch_core::EntryKind::Tombstone => "deleted",
    }
}

/// A coarse "how long ago" rendering of a unix-nanosecond timestamp.
pub fn ago(timestamp: i64) -> String {
    if timestamp == 0 {
        return "never".into();
    }
    let seconds = (now_ns() - timestamp) / 1_000_000_000;
    match seconds {
        s if s < 0 => "just now".into(),
        s if s < 60 => format!("{s}s ago"),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

/// The `synch doctor` / `synch daemon status` report.
pub fn doctor(node: &Node) -> Lines {
    let report = node.doctor()?;
    let mut out = Vec::new();
    out.push(format!("origin: {}", report.origin));
    for (key, state) in &report.device_keys {
        out.push(format!("  key {} ({state})", key.to_z32()));
    }
    out.push(format!("address: {}", addr(&node.net().direct_addr())));
    for net in node.retiring_endpoints() {
        out.push(format!("retiring: {}", addr(&net)));
    }

    out.push(String::new());
    out.push("membership:".into());
    if report.domains.is_empty() {
        out.push("  (no DNSSEC domains configured; static trust only)".into());
    } else {
        for domain in &report.domains {
            out.push(format!("  domain {domain}"));
        }
    }
    let now = now_ns();
    for binding in &report.bindings {
        out.push(format!(
            "  {:<32} {} {:<7} {}",
            binding.origin.canonical(),
            binding.node_id.to_z32(),
            binding.source.as_str(),
            if binding.is_live(now) {
                "live"
            } else {
                "LAPSED"
            },
        ));
    }

    out.push(String::new());
    out.push("heads:".into());
    for head in &report.heads {
        out.push(format!(
            "  {:<32} seq {:<8} {:<12} {:<10} {} entries",
            head.origin.canonical(),
            head.complete_seq
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            match head.pending_seq {
                Some(seq) => format!("pending {seq}"),
                None => String::new(),
            },
            if head.servable { "servable" } else { "PARTIAL" },
            head.entries,
        ));
        if !head.bound {
            out.push(
                "    ! no live binding: this origin's data stays unavailable \
                 until it republishes under a bound key"
                    .into(),
            );
        }
    }

    if !report.unbound_origins.is_empty() {
        out.push(String::new());
        out.push("unbound origins (see §3.4):".into());
        for origin in &report.unbound_origins {
            out.push(format!("  {origin}"));
        }
    }

    out.push(String::new());
    if report.equivocations.is_empty() {
        out.push("equivocation: none detected".into());
    } else {
        out.push("EQUIVOCATION DETECTED:".into());
        for e in &report.equivocations {
            out.push(format!(
                "  {} signed {} roots at seq {}",
                e.origin,
                e.heads.len(),
                e.seq
            ));
            for head in &e.heads {
                out.push(format!(
                    "    root {} signed by {}",
                    head.root,
                    head.signed_by.to_z32()
                ));
            }
            out.push(
                "    likely cause: duplicate id assignment, or a restored database backup".into(),
            );
        }
    }

    if !report.lapsed.is_empty() {
        out.push(String::new());
        out.push(format!("lapsed bindings: {}", report.lapsed.len()));
    }

    out.push(String::new());
    out.push(format!(
        "storage: {} trie nodes, {} trie values, {} objects ({} complete)",
        report.trie.nodes, report.trie.values, report.blobs.0, report.blobs.1
    ));
    Ok(out)
}

/// The per-origin publish history of one path.
pub fn log(node: &Node, reference: &EntryRef) -> Lines {
    let origins = match &reference.origin {
        Some(origin) => vec![origin.clone()],
        None => node
            .store()
            .entries_for_path(&reference.space, &reference.path)?
            .into_iter()
            .map(|r| r.origin)
            .collect(),
    };
    let key = synch_core::file_key(&reference.space, &reference.path)
        .map_err(|e| ControlError::invalid(e.to_string()))?;
    let trie = synch_mpt::Trie::new(node.store().as_ref());
    let mut out = Vec::new();
    for origin in origins {
        out.push(origin.to_string());
        let mut roots = Vec::new();
        if let Some(head) = node.store().complete_head(&origin)? {
            roots.push((head.seq, head.root));
        }
        for head in node.store().head_history(&origin)? {
            roots.push((head.seq, head.root));
        }
        roots.sort_by_key(|r| std::cmp::Reverse(r.0));
        roots.dedup();
        let mut last: Option<Option<Vec<u8>>> = None;
        for (seq, root) in roots {
            // Old roots are retained for `root_retention`, so history is a
            // storage policy rather than a protocol constant.
            let value = trie.get(root, &key).ok().flatten();
            if last.as_ref() == Some(&value) {
                continue;
            }
            match &value {
                Some(bytes) => {
                    let entry = synch_engine::scanner::decode_entry(bytes)?;
                    out.push(format!(
                        "  seq {:<6} {:<10} {:>12}  {}",
                        seq,
                        kind_name(entry.kind),
                        entry.size,
                        entry
                            .content
                            .map(|h| h.to_hex()[..16].to_string())
                            .unwrap_or_else(|| "-".into())
                    ));
                }
                None => out.push(format!("  seq {seq:<6} (absent)")),
            }
            last = Some(value);
        }
    }
    Ok(out)
}
