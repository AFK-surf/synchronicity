//! Formatting shared by the daemon's request handlers.
//!
//! These build the lines that cross the control socket; the CLI prints them
//! verbatim.

use synch_core::{now_ns, EntryKind};
use synch_engine::{
    CompareReport, CompareStatus, EntryRef, Node, RekorPolicy, ResolverStatus, VersionPolicy,
    VersionSet,
};
use synch_store::EntryRow;

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

/// The mark a divergent path carries in a listing: the number of versions it
/// holds (§8, §14).
///
/// Deliberately a *count* rather than a flag — "two versions" is the fact, and
/// it is the number `synch status` will lay out.
pub fn divergence_mark(versions: usize) -> String {
    format!("\u{2442}{versions}")
}

/// One line of an origin-pinned listing: a single origin's entry.
pub fn entry_line(row: &EntryRow, mark: Option<&str>) -> String {
    format!(
        "{:>12}  {:<8}  {}{}",
        row.size,
        kind_name(row.kind),
        row.path,
        mark.map(|m| format!("  {m}")).unwrap_or_default()
    )
}

/// One path of the unified tree, as `synch ls` prints it.
///
/// The line describes the version the reader would get — the `newest` policy's
/// selection — and the mark says how many others there are. With `all`, every
/// version follows, indented, with its attestors.
pub fn unified_line(node: &Node, set: &VersionSet, all: bool) -> Lines {
    let selected = node.resolve_set(set, &VersionPolicy::Newest)?;
    let mark = set
        .is_divergent()
        .then(|| divergence_mark(set.version_count()));
    let mut out = vec![entry_line(&selected, mark.as_deref())];
    if all {
        out.extend(version_lines(set));
    }
    Ok(out)
}

/// Every version of a path, newest first — the body of `synch status`.
pub fn version_set(set: &VersionSet) -> Vec<String> {
    let mut out = vec![format!(
        "{}/{}  {} version(s){}",
        set.space,
        set.path,
        set.version_count(),
        if set.is_divergent() {
            format!("  {}", divergence_mark(set.version_count()))
        } else {
            String::new()
        }
    )];
    out.extend(version_lines(set));
    out
}

fn version_lines(set: &VersionSet) -> Vec<String> {
    set.versions
        .iter()
        .rev()
        .map(|version| {
            let attestors: Vec<String> = version.attestors.iter().map(|o| o.short()).collect();
            // A content-less kind is identified by its target rather than by
            // a root (§8), so that is what the line has to show. The store
            // words it; this only shortens a root to fit the column, because a
            // second copy of the wording is a second copy that drifts — the
            // two used to say "(unknown target)" and "(unknown)" for the same
            // thing.
            let identity = version.identity_text();
            let identity = match version.kind {
                EntryKind::Tombstone | EntryKind::Symlink => identity,
                _ if version.content.is_some() => identity[..16].to_string(),
                _ => identity,
            };
            format!(
                "    {:<18} {:<8} {:>12}  seq {:<6} {}",
                identity,
                kind_name(version.kind),
                version.size,
                version.seq,
                attestors.join(", ")
            )
        })
        .collect()
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

/// One membership domain's health, for `domain ls` and `doctor`.
///
/// Three failing domains must not read like three healthy ones: the line
/// carries the binding count, the refresh times, and the last failure —
/// the reason itself, not a pointer at the daemon log.
pub fn domain_health(health: &synch_engine::DomainHealth, now: i64) -> String {
    let mut line = format!("{}  {} binding(s)", health.domain, health.bindings);
    match &health.schedule {
        None => line.push_str("  not yet resolved by this daemon"),
        Some(schedule) => {
            if schedule.last_success > 0 {
                line.push_str(&format!("  refreshed {}", ago(schedule.last_success)));
            } else {
                line.push_str("  never refreshed successfully");
            }
            let due = schedule.due_at.saturating_sub(now) / 1_000_000_000;
            if due > 0 {
                line.push_str(&format!("  next in {due}s"));
            } else {
                line.push_str("  due now");
            }
            if let Some(error) = &schedule.last_error {
                line.push_str(&format!("  LAST ERROR: {error}"));
            }
        }
    }
    line
}

/// The trust configuration in force, in one line, for `synch daemon status`.
///
/// The policy first, because it is the one that decides whether an answer is
/// accepted at all, and every override after it: an override is a different
/// universe and the operator has to be able to see which one they are in.
pub fn trust_summary(status: &ResolverStatus) -> String {
    match status {
        ResolverStatus::Absent => "no membership resolver in this process".into(),
        ResolverStatus::Failed(why) => {
            format!("NO RESOLVER: {why} — membership cannot refresh")
        }
        ResolverStatus::Ready(config) => {
            let mut parts = vec![
                match config.rekor {
                    RekorPolicy::Require => "rekor require".to_string(),
                    RekorPolicy::Off => "rekor OFF".to_string(),
                },
                format!("doh {}", config.doh_url),
            ];
            parts.push(match &config.dnssec_anchor {
                None => "anchor icann-root".into(),
                Some(path) => format!("anchor REPLACED by {path}"),
            });
            parts.push(match (&config.rekor_key, &config.tuf_url) {
                (Some(path), _) => format!("log keys pinned by {path}, tuf refresh off"),
                (None, None) => "tuf refresh OFF".into(),
                (None, Some(url)) => format!("tuf {url}"),
            });
            parts.push(format!("{} log key(s) pinned", config.log_keys.len()));
            parts.join(" · ")
        }
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

    // The clock, before anything dated by it. An expiry check is `now <
    // expires_at`, so a node that cannot say when it is cannot say what is
    // still trusted — and that has to be the first thing an operator reads,
    // not an inference from a page of bindings.
    out.push(String::new());
    if !report.clock.trusted {
        out.push("CLOCK UNUSABLE (§3.2):".into());
        out.push(format!(
            "  the host clock reads {} ns since the epoch, which cannot date a trust decision",
            report.clock.reading
        ));
        out.push(
            "  no DNS binding is honored and membership is not extended while this holds; \
             static trust (`synch trust add`) consults no clock and is unaffected"
                .into(),
        );
        out.push("  set the system clock or give this host a time source".into());
    } else if report.clock.stepped_back {
        out.push("CLOCK STEPPED BACK (§3.2):".into());
        out.push(format!(
            "  the clock reads {} ns, behind the {} ns this node already recorded",
            report.clock.reading, report.clock.floor
        ));
        out.push(
            "  trust is dated by the higher value, so nothing that lapsed comes back; \
             expiries will look further away than they are until the clock catches up"
                .into(),
        );
    } else {
        out.push(format!(
            "clock: usable, floor {} ns recorded",
            report.clock.floor
        ));
    }

    out.push(String::new());
    out.push(format!("trust: {}", trust_summary(&report.trust)));
    if let ResolverStatus::Ready(config) = &report.trust {
        if config.rekor == RekorPolicy::Off {
            out.push(
                "  ! zone-key transparency is off: DNSSEC alone decides, and a substituted \
                 zone key leaves no public record"
                    .into(),
            );
        }
        if let Some(path) = &config.dnssec_anchor {
            out.push(format!(
                "  ! the ICANN root is replaced by {path}: nothing signed under the real root \
                 validates on this node"
            ));
        }
        if config.tuf_url.is_none() {
            out.push(
                "  ! TUF pin refresh is off: the log key set stops following Sigstore, so a \
                 shard rotation needs a new build or a new key file"
                    .into(),
            );
        }
        for key in &config.log_keys {
            out.push(format!("  log key {key}"));
        }
    }

    out.push(String::new());
    out.push("membership:".into());
    if report.domains.is_empty() {
        out.push("  (no DNSSEC domains configured; static trust only)".into());
    } else {
        let now = now_ns();
        for health in node.domain_health()? {
            out.push(format!("  domain {}", domain_health(&health, now)));
        }
    }
    // §3.2's malformed-set rule drops *every* binding an ambiguous key would
    // create, so the member it names does not appear in `trust ls` at all. This
    // is the only place that says why, on any refresh path.
    for (domain, key) in &report.ambiguous {
        out.push(format!(
            "  AMBIGUOUS in {domain}: {} appears under more than one id",
            key.to_z32()
        ));
        out.push(
            "    every binding it would create is dropped, so that member is not trusted at \
             all; the usual cause is one key published under two id= labels"
                .into(),
        );
    }
    for (domain, origin) in &report.self_origin_mismatch {
        out.push(format!(
            "  MISMATCH in {domain}: this node's device key is published as {origin}, but it \
             publishes as {}",
            report.origin
        ));
        out.push(
            "    peers bind the published id, so nothing this node publishes is accepted \
             until the record or `synch init --id` agrees"
                .into(),
        );
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

    if report.recovery.in_recovery {
        out.push(String::new());
        out.push("KEY-LOSS RECOVERY (§3.4):".into());
        out.push(format!(
            "  this node holds no head of its own for {}, but peers advertise one at seq {}",
            report.recovery.origin,
            report
                .recovery
                .observed_seq
                .map(|seq| seq.to_string())
                .unwrap_or_else(|| "-".into()),
        ));
        // Whose claim it is, because the claim is unauthenticated and the
        // operator is the one who has to judge it (§3.4, §12).
        out.push(format!(
            "  claimed by {}",
            report
                .recovery
                .observed_by
                .map(|key| key.to_z32())
                .unwrap_or_else(|| "(an unrecorded peer)".into()),
        ));
        out.push(format!(
            "  publishing is refused: a head at seq {} would be rejected by every peer",
            report.recovery.next_seq
        ));
        out.push(
            "  the claim is a peer's unverified summary, not a signed head: check that peer \
             before trusting the number"
                .into(),
        );
        out.push("  run `synch recover` to resume publishing above what peers have seen".into());
    } else if let Some(floor) = report.recovery.floor {
        out.push(String::new());
        out.push(format!(
            "recovered: publishing floor {floor}, highest seq peers advertised {} (claimed by {})",
            report
                .recovery
                .observed_seq
                .map(|seq| seq.to_string())
                .unwrap_or_else(|| "-".into()),
            report
                .recovery
                .observed_by
                .map(|key| key.to_z32())
                .unwrap_or_else(|| "an unrecorded peer".into()),
        ));
    }

    if !report.unreconciled.is_empty() {
        out.push(String::new());
        out.push("UNRECONCILED PRE-RECOVERY HISTORY (§3.4):".into());
        for entry in &report.unreconciled {
            out.push(format!(
                "  origin {} has unreconciled pre-recovery history at seq {}",
                entry.origin, entry.seq
            ));
            out.push(format!(
                "    root {} signed by {}, which is no longer bound to it",
                entry.root,
                entry.signed_by.to_z32()
            ));
            out.push(format!(
                "    current head {} does not supersede it; the origin's operator resolves \
                 the fork, never the protocol",
                entry
                    .current_seq
                    .map(|seq| format!("seq {seq}"))
                    .unwrap_or_else(|| "(none held)".into()),
            ));
        }
    }

    if !report.unbound_origins.is_empty() {
        out.push(String::new());
        out.push("origins held without a live binding (§3.4, §12):".into());
        for (origin, entries) in &report.unbound_origins {
            out.push(format!("  {origin}: {entries} entr(ies) still held"));
        }
        out.push(
            "  removal cuts off future participation only; what they published stays \
             replicated and ages out with ordinary retention"
                .into(),
        );
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

/// A name-status comparison between two origins, `git status --short` style.
pub fn compare(report: &CompareReport, json: bool) -> Vec<String> {
    if json {
        return vec![compare_json(report)];
    }
    let mut out = vec![format!(
        "comparing {}:  {} \u{2192} {}",
        report.space, report.from, report.to
    )];
    if report.changes.is_empty() {
        out.push("no differences".into());
        return out;
    }
    for change in &report.changes {
        out.push(format!("{}  {}", change.status.marker(), change.path));
    }
    out.push(String::new());
    out.push(format!(
        "{} changed  ({} created \u{00b7} {} modified \u{00b7} {} deleted)",
        report.changes.len(),
        report.created(),
        report.modified(),
        report.deleted(),
    ));
    out
}

/// The compare report as one line of JSON, for `--json`.
fn compare_json(report: &CompareReport) -> String {
    let status = |s: CompareStatus| match s {
        CompareStatus::Created => "created",
        CompareStatus::Modified => "modified",
        CompareStatus::Deleted => "deleted",
    };
    let changes: Vec<String> = report
        .changes
        .iter()
        .map(|c| {
            format!(
                "{{\"status\":\"{}\",\"path\":{}}}",
                status(c.status),
                json_string(&c.path)
            )
        })
        .collect();
    format!(
        "{{\"space\":{},\"from\":{},\"to\":{},\"changes\":[{}]}}",
        json_string(&report.space),
        json_string(&report.from.to_string()),
        json_string(&report.to.to_string()),
        changes.join(",")
    )
}

/// Escapes a string as a JSON string literal (quotes included). Paths can carry
/// quotes and backslashes, so hand-formatting JSON has to escape them.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_core::{EntryKind, FileEntry, Hash, OriginId};
    use synch_engine::CompareChange;
    use synch_store::VersionSet;

    fn row(origin: &str, content: &[u8], mtime: i64) -> EntryRow {
        let entry = FileEntry::file(3, mtime, Hash::new(content), 1);
        EntryRow {
            origin: OriginId::named(origin, "x.example").unwrap(),
            space: "media".into(),
            path: "f.txt".into(),
            kind: entry.kind,
            size: entry.size,
            mtime_ns: entry.mtime_ns,
            unix_mode: entry.unix_mode,
            content: entry.content,
            seq: entry.seq,
            prev: None,
            symlink_target: None,
        }
    }

    fn symlink_row(origin: &str, target: &str, mtime: i64) -> EntryRow {
        EntryRow {
            origin: OriginId::named(origin, "x.example").unwrap(),
            space: "media".into(),
            path: "f.txt".into(),
            kind: EntryKind::Symlink,
            size: target.len() as u64,
            mtime_ns: mtime,
            unix_mode: None,
            content: None,
            seq: 1,
            prev: None,
            symlink_target: Some(target.to_string()),
        }
    }

    /// A reading clock later than any time these tests publish.
    const READ_AT: i64 = i64::MAX;

    #[test]
    fn a_symlink_version_shows_its_target() {
        let set = VersionSet::from_entries(
            "media",
            "f.txt",
            vec![
                symlink_row("nas", "../a", 1),
                symlink_row("laptop", "../a", 2),
            ],
            READ_AT,
        );
        assert_eq!(set.version_count(), 1, "same target, same version");
        let lines = version_set(&set);
        assert!(lines[1].contains("-> ../a"), "{lines:?}");
        assert!(lines[1].contains("symlink"), "{lines:?}");
    }

    #[test]
    fn divergence_is_marked_with_its_version_count() {
        assert_eq!(divergence_mark(2), "⑂2");
        assert_eq!(divergence_mark(7), "⑂7");
    }

    fn sample_report() -> CompareReport {
        CompareReport {
            from: OriginId::named("nas", "x.example").unwrap(),
            to: OriginId::named("laptop", "x.example").unwrap(),
            space: "media".into(),
            changes: vec![
                CompareChange {
                    path: "a.jpg".into(),
                    status: CompareStatus::Modified,
                },
                CompareChange {
                    path: "new.txt".into(),
                    status: CompareStatus::Created,
                },
            ],
        }
    }

    #[test]
    fn compare_renders_name_status_lines_and_a_summary() {
        let lines = compare(&sample_report(), false);
        assert!(lines[0].contains("comparing media"), "{lines:?}");
        assert!(lines.iter().any(|l| l == "M  a.jpg"), "{lines:?}");
        assert!(lines.iter().any(|l| l == "A  new.txt"), "{lines:?}");
        assert!(
            lines
                .last()
                .unwrap()
                .contains("1 created \u{00b7} 1 modified \u{00b7} 0 deleted"),
            "{lines:?}"
        );
    }

    #[test]
    fn compare_with_no_changes_says_so() {
        let mut report = sample_report();
        report.changes.clear();
        let lines = compare(&report, false);
        assert!(lines.iter().any(|l| l == "no differences"), "{lines:?}");
    }

    #[test]
    fn compare_json_escapes_and_lists_changes() {
        let mut report = sample_report();
        report.changes.push(CompareChange {
            path: "weird\"name\\x.txt".into(),
            status: CompareStatus::Deleted,
        });
        let json = compare(&report, true);
        assert_eq!(json.len(), 1);
        assert!(json[0].starts_with("{\"space\":\"media\""), "{}", json[0]);
        assert!(
            json[0].contains("\"status\":\"deleted\",\"path\":\"weird\\\"name\\\\x.txt\""),
            "{}",
            json[0]
        );
    }

    #[test]
    fn an_agreed_path_carries_no_mark() {
        let set = VersionSet::from_entries(
            "media",
            "f.txt",
            vec![row("nas", b"same", 1), row("laptop", b"same", 2)],
            READ_AT,
        );
        assert!(!set.is_divergent());
        let lines = version_set(&set);
        assert!(lines[0].contains("1 version(s)"), "{lines:?}");
        assert!(!lines[0].contains('⑂'), "{lines:?}");
        // One version, both attestors named on it.
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("nas"), "{lines:?}");
        assert!(lines[1].contains("laptop"), "{lines:?}");
    }

    #[test]
    fn a_divergent_path_lists_every_version_newest_first() {
        let set = VersionSet::from_entries(
            "media",
            "f.txt",
            vec![row("nas", b"theirs", 100), row("laptop", b"ours", 200)],
            READ_AT,
        );
        let lines = version_set(&set);
        assert!(lines[0].contains("2 version(s)"), "{lines:?}");
        assert!(lines[0].contains("⑂2"), "{lines:?}");
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("laptop"), "the newest first: {lines:?}");
        assert!(lines[2].contains("nas"), "{lines:?}");
    }

    #[test]
    fn a_tombstone_version_says_so() {
        let mut deleted = row("nas", b"gone", 300);
        deleted.kind = EntryKind::Tombstone;
        deleted.content = None;
        let set = VersionSet::from_entries(
            "media",
            "f.txt",
            vec![row("laptop", b"live", 100), deleted],
            READ_AT,
        );
        let lines = version_set(&set);
        assert!(lines[1].contains("(deleted)"), "{lines:?}");
        assert!(lines[1].contains("deleted"), "{lines:?}");
    }
}
