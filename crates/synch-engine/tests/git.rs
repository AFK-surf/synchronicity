//! Git repositories synced between real nodes (`docs/GIT.md`).
//!
//! Every repository here is made by `git` itself, because git's on-disk
//! layout is the specification; a test is skipped where the binary is
//! absent. The nodes are in-process on loopback endpoints with static trust,
//! as in every other suite here.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use synch_engine::{AdoptTreeOptions, Node, VersionPolicy};
use synch_store::{PinHolder, ReplicaPolicy};

mod common;
use common::{off_runtime, shutdown, spawn_node as spawn, trust_all as introduce, Peer};

/// The space every test publishes into, and the repository's directory in it.
const SPACE: &str = "src";
const REPO: &str = "app";

/// Runs `git` in `dir` with a hermetic configuration, and returns its stdout.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=synch",
            "-c",
            "user.email=synch@example",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "gc.auto=0",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} in {}: {e}", dir.display()));
    assert!(
        output.status.success(),
        "git {args:?} in {}: {}{}",
        dir.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// True if `git` can be run at all; a suite that cannot make a repository
/// says so and passes.
fn have_git() -> bool {
    match Command::new("git").arg("--version").output() {
        Ok(out) if out.status.success() => true,
        _ => {
            eprintln!("git is not installed; skipping");
            false
        }
    }
}

/// A repository at `<space>/app` with one committed file.
fn init_repo(space: &Path) -> PathBuf {
    let repo = space.join(REPO);
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    std::fs::write(repo.join("README"), b"first\n").unwrap();
    git(&repo, &["add", "README"]);
    git(&repo, &["commit", "-q", "-m", "first"]);
    repo
}

/// Copies a directory tree, the way a second machine gets a repository.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Every live path this origin publishes in the space.
async fn published(node: &Node) -> Vec<String> {
    let (store, origin) = (node.store().clone(), node.origin().clone());
    off_runtime(move || store.published_paths(&origin, SPACE).unwrap()).await
}

/// A replica of the space with a checkout directory.
async fn add_checkout(peer: &Peer) -> PathBuf {
    let dir = peer.space.path().join("checkout");
    std::fs::create_dir_all(&dir).unwrap();
    let node = peer.node.clone();
    let path = dir.to_string_lossy().into_owned();
    off_runtime(move || {
        node.add_replica(SPACE, ReplicaPolicy::Current, None, None, Some(path))
            .unwrap()
    })
    .await;
    dir
}

/// Syncs, wants, fetches, and runs one checkout pass.
async fn converge(replica: &Node, publishers: &[&Node]) -> synch_engine::checkout::CheckoutReport {
    for publisher in publishers {
        replica.sync_with_peer(&publisher.node_id()).await.unwrap();
    }
    let sweeping = replica.clone();
    off_runtime(move || sweeping.sweep_replicas(None).unwrap()).await;
    replica.fetch_content_wants().await.unwrap();
    replica.sync_checkout(SPACE).await.unwrap()
}

/// A publisher sync followed by a tree adoption.
async fn adopt(
    adopter: &Node,
    publisher: &Node,
    options: AdoptTreeOptions,
) -> synch_engine::adopt_tree::AdoptTreeReport {
    adopter.sync_with_peer(&publisher.node_id()).await.unwrap();
    adopter
        .adopt_tree(SPACE, "", &VersionPolicy::Newest, options)
        .await
        .unwrap()
}

fn object_paths(paths: &[String]) -> Vec<&String> {
    paths
        .iter()
        .filter(|p| {
            synch_core::git::classify(p).is_some_and(|g| g.class == synch_core::GitClass::Object)
        })
        .collect()
}

/// A source containing a repository publishes the repository and none of the
/// files git makes only for itself: locks, temporary objects, the fsmonitor
/// socket, and the absolute-path pointers of a linked worktree. A socket
/// outside the repository is skipped on its own without failing the space
/// (#151).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repository_publishes_without_its_transient_and_machine_local_files() {
    if !have_git() {
        return;
    }
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let repo = init_repo(publisher.space.path());
    let git_dir = repo.join(".git");
    std::fs::write(git_dir.join("index.lock"), b"").unwrap();
    std::fs::write(git_dir.join("objects/tmp_obj_abc"), b"").unwrap();
    git(&repo, &["worktree", "add", "-q", "wt", "-b", "wt"]);
    #[cfg(unix)]
    {
        std::os::unix::net::UnixListener::bind(git_dir.join("fsmonitor--daemon.ipc")).unwrap();
        std::os::unix::net::UnixListener::bind(publisher.space.path().join("stray.sock")).unwrap();
    }
    std::fs::write(publisher.space.path().join("beside.txt"), b"beside").unwrap();

    publisher
        .node
        .add_filesystem_source(SPACE, publisher.space.path())
        .unwrap();
    let scanning = publisher.node.clone();
    let (report, head) = off_runtime(move || scanning.scan_and_publish().unwrap()).await;
    assert!(head.is_some(), "{report:?}");
    let paths = published(&publisher.node).await;
    for expected in [
        "app/.git/HEAD",
        "app/.git/refs/heads/main",
        "app/.git/index",
        "app/.git/config",
        "app/README",
        "beside.txt",
        "app/.git/worktrees/wt/HEAD",
    ] {
        assert!(
            paths.iter().any(|p| p == expected),
            "{expected} missing from {paths:?}"
        );
    }
    assert!(!object_paths(&paths).is_empty(), "objects are published");
    for excluded in [
        "app/.git/index.lock",
        "app/.git/objects/tmp_obj_abc",
        "app/.git/fsmonitor--daemon.ipc",
        "app/.git/worktrees/wt/gitdir",
        "app/wt/.git",
        "stray.sock",
    ] {
        assert!(
            !paths.iter().any(|p| p == excluded),
            "{excluded} was published"
        );
    }
    let skipped: Vec<&str> = report.skipped.iter().map(|(p, _)| p.as_str()).collect();
    assert!(
        skipped.contains(&"app/.git/worktrees/wt/gitdir"),
        "{skipped:?}"
    );
    assert!(skipped.contains(&"app/wt/.git"), "{skipped:?}");
    #[cfg(unix)]
    {
        let reason = report
            .skipped
            .iter()
            .find(|(p, _)| p == "stray.sock")
            .map(|(_, why)| why.as_str())
            .expect("the stray socket is skipped, not fatal");
        assert!(reason.contains("socket"), "{reason}");
    }
    shutdown(&[&publisher.node]).await;
}

/// A checkout never holds a ref to objects it does not have: with the refs'
/// bytes acquired ahead of the objects, the symbolic HEAD lands and the
/// branch is held; once the objects are there the branch follows, and git
/// finds a whole, clean repository.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_checkout_writes_objects_before_refs() {
    if !have_git() {
        return;
    }
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let replica = spawn("replica").await;
    introduce(&[&publisher, &replica]);
    let repo = init_repo(publisher.space.path());
    publisher
        .node
        .add_filesystem_source(SPACE, publisher.space.path())
        .unwrap();
    publisher.node.scan_publish_push().await.unwrap();
    let checkout = add_checkout(&replica).await;

    // The metadata arrives and the replica wants everything, but only the
    // two ref files are acquired so far.
    replica
        .node
        .sync_with_peer(&publisher.node.node_id())
        .await
        .unwrap();
    let sweeping = replica.node.clone();
    off_runtime(move || sweeping.sweep_replicas(None).unwrap()).await;
    for name in ["HEAD", "refs/heads/main"] {
        let bytes = std::fs::read(repo.join(".git").join(name)).unwrap();
        let store = replica.node.store().clone();
        off_runtime(move || {
            let root = store.ingest_bytes(&bytes, 1).unwrap();
            store
                .pin(&root, &PinHolder::Replica(SPACE.into()), 1)
                .unwrap();
        })
        .await;
    }
    let report = replica.node.sync_checkout(SPACE).await.unwrap();
    let git_dir = checkout.join(REPO).join(".git");
    assert!(
        git_dir.join("HEAD").is_file(),
        "a symbolic ref is never held: {report:?}"
    );
    assert!(
        !git_dir.join("refs/heads/main").exists(),
        "the branch waits for the objects: {report:?}"
    );
    assert_eq!(report.held, 1, "{report:?}");
    assert!(
        git_dir.join("objects").is_dir() && git_dir.join("refs").is_dir(),
        "the first write makes it a repository"
    );
    assert_eq!(
        git(
            &checkout.join(REPO),
            &["rev-parse", "--is-inside-work-tree"]
        ),
        "true"
    );

    let report = converge(&replica.node, &[&publisher.node]).await;
    assert_eq!(report.held, 0, "{report:?}");
    assert!(git_dir.join("refs/heads/main").is_file());
    let expected = git(&repo, &["rev-parse", "main"]);
    assert_eq!(git(&checkout.join(REPO), &["rev-parse", "main"]), expected);
    git(&checkout.join(REPO), &["fsck", "--strict"]);
    assert_eq!(
        git(&checkout.join(REPO), &["status", "--porcelain"]),
        "",
        "index and working tree are the publisher's"
    );
    shutdown(&[&publisher.node, &replica.node]).await;
}

/// `git gc` on the publisher packs the objects and the refs. The checkout
/// keeps every loose object, gains the pack, drops the packed loose refs
/// because for a ref the deletion is the newest state, and stays whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gc_on_the_publisher_never_removes_objects_from_a_checkout() {
    if !have_git() {
        return;
    }
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let replica = spawn("replica").await;
    introduce(&[&publisher, &replica]);
    let repo = init_repo(publisher.space.path());
    for i in 0..3 {
        std::fs::write(repo.join("README"), format!("edit {i}\n")).unwrap();
        git(&repo, &["commit", "-q", "-am", &format!("edit {i}")]);
    }
    publisher
        .node
        .add_filesystem_source(SPACE, publisher.space.path())
        .unwrap();
    publisher.node.scan_publish_push().await.unwrap();
    let checkout = add_checkout(&replica).await;
    converge(&replica.node, &[&publisher.node]).await;
    let mirror = checkout.join(REPO);
    git(&mirror, &["fsck", "--strict"]);
    let loose_before: Vec<String> = object_paths(&published(&publisher.node).await)
        .into_iter()
        .cloned()
        .collect();
    assert!(loose_before.iter().all(|p| !p.contains("/pack/")));

    git(&repo, &["gc", "-q", "--prune=now"]);
    assert!(
        !repo.join(".git/refs/heads/main").exists(),
        "gc packed the refs"
    );
    publisher.node.scan_publish_push().await.unwrap();
    let paths = published(&publisher.node).await;
    assert!(
        paths.iter().any(|p| p.ends_with(".pack")),
        "the pack is published: {paths:?}"
    );
    // Two passes: the pack lands on the first, the refs that were tombstoned
    // follow on the same pass, and the second confirms the state is stable.
    let first = converge(&replica.node, &[&publisher.node]).await;
    let second = replica.node.sync_checkout(SPACE).await.unwrap();
    assert_eq!(second.written, 0, "{second:?}");
    for path in &loose_before {
        assert!(
            checkout.join(path).is_file(),
            "{path} was removed by the gc elsewhere ({first:?})"
        );
    }
    assert!(
        !mirror.join(".git/refs/heads/main").exists(),
        "the packed loose ref is gone from the checkout too"
    );
    assert!(mirror.join(".git/packed-refs").is_file());
    assert_eq!(
        git(&mirror, &["rev-parse", "main"]),
        git(&repo, &["rev-parse", "main"])
    );
    git(&mirror, &["fsck", "--strict"]);
    shutdown(&[&publisher.node, &replica.node]).await;
}

/// Two loose objects at one path with different bytes are one version, and a
/// tree adoption of the repository reports nothing differing about them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_encodings_of_one_object_are_one_version() {
    if !have_git() {
        return;
    }
    let _blocking = synch_core::BlockingScope::enter();
    let a = spawn("a").await;
    let b = spawn("b").await;
    introduce(&[&a, &b]);
    let repo = init_repo(a.space.path());
    copy_dir(&repo, &b.space.path().join(REPO));
    a.node.add_filesystem_source(SPACE, a.space.path()).unwrap();
    b.node.add_filesystem_source(SPACE, b.space.path()).unwrap();
    a.node.scan_publish_push().await.unwrap();
    let objects: Vec<String> = object_paths(&published(&a.node).await)
        .into_iter()
        .cloned()
        .collect();
    let object = objects.first().expect("a committed repository has objects");
    // The same object, differently compressed: the bytes differ, the name
    // does not.
    let path = b.space.path().join(object);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0);
    std::fs::write(&path, bytes).unwrap();
    b.node.scan_publish_push().await.unwrap();
    b.node.sync_with_peer(&a.node.node_id()).await.unwrap();

    let (node, object_path) = (b.node.clone(), object.clone());
    let set = off_runtime(move || node.versions(SPACE, &object_path).unwrap()).await;
    assert_eq!(set.version_count(), 1, "{:?}", set.describe());
    assert_eq!(set.versions[0].attestors.len(), 2);
    let report = b
        .node
        .adopt_tree(
            SPACE,
            "",
            &VersionPolicy::Newest,
            AdoptTreeOptions::default(),
        )
        .await
        .unwrap();
    assert!(report.differing.is_empty(), "{report:?}");
    assert!(report.adopted == 0, "{report:?}");
    shutdown(&[&a.node, &b.node]).await;
}

/// Deleting a branch on one machine removes it from the checkout even while
/// the other machine still publishes its copy; a branch written after the
/// deletion wins it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_branch_leaves_the_checkout_and_a_later_write_wins_it_back() {
    if !have_git() {
        return;
    }
    let _blocking = synch_core::BlockingScope::enter();
    let a = spawn("a").await;
    let b = spawn("b").await;
    let replica = spawn("replica").await;
    introduce(&[&a, &b, &replica]);
    let repo_a = init_repo(a.space.path());
    git(&repo_a, &["branch", "feature"]);
    let repo_b = b.space.path().join(REPO);
    copy_dir(&repo_a, &repo_b);
    for peer in [&a, &b] {
        peer.node
            .add_filesystem_source(SPACE, peer.space.path())
            .unwrap();
        peer.node.scan_publish_push().await.unwrap();
    }
    let checkout = add_checkout(&replica).await;
    converge(&replica.node, &[&a.node, &b.node]).await;
    let feature = checkout.join(REPO).join(".git/refs/heads/feature");
    assert!(feature.is_file());

    git(&repo_a, &["branch", "-D", "feature"]);
    a.node.scan_publish_push().await.unwrap();
    let report = converge(&replica.node, &[&a.node, &b.node]).await;
    assert!(
        !feature.exists(),
        "the deletion is the newest assertion about the ref: {report:?}"
    );
    assert!(
        checkout.join(REPO).join(".git/refs/heads/main").is_file(),
        "main is untouched"
    );

    // Written after the deletion was noticed, so it is newer than the
    // tombstone — and to a new value, since git does not rewrite a ref that
    // already holds the value it is given.
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(repo_b.join("b.txt"), b"b").unwrap();
    git(&repo_b, &["add", "b.txt"]);
    git(&repo_b, &["commit", "-q", "-m", "on b"]);
    git(&repo_b, &["branch", "-f", "feature", "main"]);
    b.node.scan_publish_push().await.unwrap();
    converge(&replica.node, &[&a.node, &b.node]).await;
    assert!(feature.is_file(), "the later write wins the ref back");
    shutdown(&[&a.node, &b.node, &replica.node]).await;
}

/// Concurrent commits on one branch: the checkout carries the newer as the
/// branch and the other under `refs/synch/`, so both are reachable and `git
/// gc` in the checkout loses nothing; the mirror goes when the divergence
/// ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_commits_are_both_reachable_in_a_checkout() {
    if !have_git() {
        return;
    }
    let _blocking = synch_core::BlockingScope::enter();
    let a = spawn("a").await;
    let b = spawn("b").await;
    let replica = spawn("replica").await;
    introduce(&[&a, &b, &replica]);
    let repo_a = init_repo(a.space.path());
    let repo_b = b.space.path().join(REPO);
    copy_dir(&repo_a, &repo_b);
    std::fs::write(repo_a.join("a.txt"), b"a").unwrap();
    git(&repo_a, &["add", "a.txt"]);
    git(&repo_a, &["commit", "-q", "-m", "on a"]);
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(repo_b.join("b.txt"), b"b").unwrap();
    git(&repo_b, &["add", "b.txt"]);
    git(&repo_b, &["commit", "-q", "-m", "on b"]);
    let (commit_a, commit_b) = (
        git(&repo_a, &["rev-parse", "main"]),
        git(&repo_b, &["rev-parse", "main"]),
    );
    for peer in [&a, &b] {
        peer.node
            .add_filesystem_source(SPACE, peer.space.path())
            .unwrap();
        peer.node.scan_publish_push().await.unwrap();
    }
    let checkout = add_checkout(&replica).await;
    let report = converge(&replica.node, &[&a.node, &b.node]).await;
    let mirror = checkout.join(REPO);
    assert_eq!(
        git(&mirror, &["rev-parse", "main"]),
        commit_b,
        "the newer commit is the branch: {report:?}"
    );
    let mirrored = mirror.join(".git").join(synch_core::git::mirror_ref_path(
        &a.node.origin().short(),
        "heads/main",
    ));
    assert!(mirrored.is_file(), "{report:?}");
    assert_eq!(std::fs::read_to_string(&mirrored).unwrap().trim(), commit_a);
    assert!(report.mirrored >= 1, "{report:?}");
    git(&mirror, &["fsck", "--strict"]);
    let all = git(&mirror, &["rev-list", "--all"]);
    assert!(all.contains(&commit_a) && all.contains(&commit_b), "{all}");
    git(&mirror, &["gc", "-q", "--prune=now"]);
    git(&mirror, &["cat-file", "-e", &commit_a]);
    git(&mirror, &["cat-file", "-e", &commit_b]);

    // b takes a's line; the divergence ends and the mirror goes.
    git(&repo_b, &["fetch", "-q", repo_a.to_str().unwrap(), "main"]);
    git(&repo_b, &["reset", "-q", "--hard", "FETCH_HEAD"]);
    b.node.scan_publish_push().await.unwrap();
    converge(&replica.node, &[&a.node, &b.node]).await;
    assert_eq!(git(&mirror, &["rev-parse", "main"]), commit_a);
    assert!(
        !mirrored.exists(),
        "the mirror is swept once the ref agrees"
    );
    shutdown(&[&a.node, &b.node, &replica.node]).await;
}

/// A fresh machine adopting a whole repository gets a clean one, objects
/// before refs; adopting a single ref before the objects is refused; and a
/// repository mid-rebase is not written into until the rebase is over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adoption_writes_a_whole_repository_and_refuses_one_mid_operation() {
    if !have_git() {
        return;
    }
    let _blocking = synch_core::BlockingScope::enter();
    let a = spawn("a").await;
    let b = spawn("b").await;
    introduce(&[&a, &b]);
    let repo_a = init_repo(a.space.path());
    a.node.add_filesystem_source(SPACE, a.space.path()).unwrap();
    a.node.scan_publish_push().await.unwrap();
    b.node.add_filesystem_source(SPACE, b.space.path()).unwrap();
    b.node.sync_with_peer(&a.node.node_id()).await.unwrap();

    let refused = b
        .node
        .adopt_from(a.node.origin(), SPACE, "app/.git/refs/heads/main")
        .await
        .expect_err("a ref before its objects");
    assert!(refused.to_string().contains("adopt tree"), "{refused}");

    let report = adopt(&b.node, &a.node, AdoptTreeOptions::default()).await;
    assert!(report.skipped.is_empty(), "{report:?}");
    let repo_b = b.space.path().join(REPO);
    git(&repo_b, &["fsck", "--strict"]);
    assert_eq!(
        git(&repo_b, &["rev-parse", "main"]),
        git(&repo_a, &["rev-parse", "main"])
    );
    assert_eq!(git(&repo_b, &["status", "--porcelain"]), "");
    // Now the objects are here, the single ref adopts.
    b.node
        .adopt_from(a.node.origin(), SPACE, "app/.git/refs/heads/main")
        .await
        .unwrap();

    // a moves on; b is mid-rebase.
    std::fs::write(repo_a.join("README"), b"second\n").unwrap();
    git(&repo_a, &["commit", "-q", "-am", "second"]);
    a.node.scan_publish_push().await.unwrap();
    b.node.scan_publish_push().await.unwrap();
    std::fs::create_dir(repo_b.join(".git/rebase-merge")).unwrap();
    b.node.sync_with_peer(&a.node.node_id()).await.unwrap();
    let refused = b
        .node
        .adopt_tree(
            SPACE,
            "",
            &VersionPolicy::Newest,
            AdoptTreeOptions {
                replace: true,
                dry_run: false,
            },
        )
        .await
        .expect_err("mid-rebase");
    assert!(refused.to_string().contains("rebase-merge"), "{refused}");
    std::fs::remove_dir(repo_b.join(".git/rebase-merge")).unwrap();
    let before = git(&repo_b, &["rev-parse", "main"]);
    let report = adopt(
        &b.node,
        &a.node,
        AdoptTreeOptions {
            replace: true,
            dry_run: false,
        },
    )
    .await;
    assert!(report.skipped.is_empty(), "{report:?}");
    let after = git(&repo_a, &["rev-parse", "main"]);
    assert_eq!(git(&repo_b, &["rev-parse", "main"]), after);
    assert!(
        report
            .replaced_refs
            .contains(&("app/.git/refs/heads/main".to_string(), before, after)),
        "{:?}",
        report.replaced_refs
    );
    git(&repo_b, &["fsck", "--strict"]);
    assert_eq!(git(&repo_b, &["status", "--porcelain"]), "");
    shutdown(&[&a.node, &b.node]).await;
}

/// A ref the adopted repository has deleted is named, never removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adoption_names_refs_the_publisher_deleted() {
    if !have_git() {
        return;
    }
    let _blocking = synch_core::BlockingScope::enter();
    let a = spawn("a").await;
    let b = spawn("b").await;
    introduce(&[&a, &b]);
    let repo_a = init_repo(a.space.path());
    git(&repo_a, &["branch", "feature"]);
    copy_dir(&repo_a, &b.space.path().join(REPO));
    for peer in [&a, &b] {
        peer.node
            .add_filesystem_source(SPACE, peer.space.path())
            .unwrap();
        peer.node.scan_publish_push().await.unwrap();
    }
    git(&repo_a, &["branch", "-D", "feature"]);
    a.node.scan_publish_push().await.unwrap();
    let report = adopt(&b.node, &a.node, AdoptTreeOptions::default()).await;
    assert!(
        report
            .deleted
            .contains(&"app/.git/refs/heads/feature".to_string()),
        "{report:?}"
    );
    assert!(
        report
            .deleted
            .iter()
            .all(|p| p.starts_with("app/.git/refs/") || p.starts_with("app/.git/logs/")),
        "the reflog of the deleted branch is worktree state, deleted too: {report:?}"
    );
    assert!(
        b.space.path().join("app/.git/refs/heads/feature").is_file(),
        "a tree adoption removes nothing"
    );
    shutdown(&[&a.node, &b.node]).await;
}
