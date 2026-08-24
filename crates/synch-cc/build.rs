//! Builds the tinycc fork that targets eBPF, and links it into this crate.
//!
//! The fork is fetched at build time rather than vendored, and it is fetched
//! with git rather than as an archive: a commit id *is* a content digest, so
//! pinning one needs no second checksum to keep in sync with it, and a fetch
//! that lands on different bytes cannot succeed. `SYNCH_TINYCC_DIR` points the
//! build at a checkout that is already on disk, for an offline or air-gapped
//! build.
//!
//! Compiled with the `cc` crate rather than by driving tinycc's own
//! `./configure` and Makefile. That build system needs a POSIX shell and GNU
//! make, which is a heavier thing to require of everyone who builds this
//! workspace than the nine `.c` files are worth; the flags it would derive are
//! the handful spelled out below.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// The fork, and the commit that has the eBPF backend.
const TINYCC_REPO: &str = "https://github.com/losfair/tinycc.git";
/// Pinned, and the only integrity check this needs: git will not hand back
/// different bytes under this name.
const TINYCC_COMMIT: &str = "ac2dd4a1011674ed3f55eb99bc8fa22bdf635daa";

/// The translation units a BPF-targeting libtcc is made of.
///
/// `tccrun.c` is deliberately absent. It implements `-run`, which needs
/// `mmap`, `dlopen` and a host that can execute what was just compiled — none
/// of which apply when the target is eBPF and the output is always an object
/// file. Everything it defines sits behind `TCC_IS_NATIVE`, which a
/// cross-target build never sets, so leaving it out changes not one byte of
/// the output and removes the crate's only reason to link `dl` and `pthread`.
const SOURCES: &[&str] = &[
    "libtcc.c",
    "tccpp.c",
    "tccgen.c",
    "tccdbg.c",
    "tccelf.c",
    "tccasm.c",
    "bpf-gen.c",
    "bpf-link.c",
];

fn main() {
    println!("cargo:rerun-if-env-changed=SYNCH_TINYCC_DIR");
    println!("cargo:rustc-check-cfg=cfg(tinycc)");

    // MSVC is the one host this has not been built against, and a compiler
    // that fails to build is a workspace that fails to build. The crate still
    // compiles there; `synch_cc::compile` answers `Unsupported`, the same
    // shape `synch-sock` uses for a platform with no eBPF runtime.
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let source_dir = match env::var_os("SYNCH_TINYCC_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => fetch_tinycc(&out_dir),
    };
    if !source_dir.join("bpf-gen.c").is_file() {
        panic!(
            "{} does not look like a tinycc checkout with the eBPF backend",
            source_dir.display()
        );
    }

    write_config_header(&out_dir);
    generate_predefs(&source_dir, &out_dir);
    embed_freestanding_headers(&source_dir, &out_dir);

    let mut build = cc::Build::new();
    build
        .include(&out_dir)
        .include(&source_dir)
        // The generated code targets eBPF; the compiler itself is native.
        .define("TCC_TARGET_BPF", None)
        // Says "this is a multi-file build", which is what turns tinycc's
        // amalgamated single-translation-unit mode off.
        .define("ONE_SOURCE", "0")
        // Nothing here is threaded: one `TCCState` is used by one caller, and
        // `synch_cc::compile` holds a lock over the whole of it anyway.
        .define("CONFIG_TCC_SEMLOCK", "0")
        // Upstream's own build passes -w; the code is older than most of the
        // warnings, and a vendored dependency's warnings are noise a consumer
        // can do nothing about.
        .warnings(false)
        .flag_if_supported("-fno-strict-aliasing");
    for source in SOURCES {
        let path = source_dir.join(source);
        println!("cargo:rerun-if-changed={}", path.display());
        build.file(path);
    }
    build.compile("synch_tinycc_bpf");

    println!("cargo:rustc-cfg=tinycc");
}

/// Fetches the pinned commit into `OUT_DIR`, or reuses one already there.
fn fetch_tinycc(out_dir: &Path) -> PathBuf {
    let dir = out_dir.join(format!("tinycc-{TINYCC_COMMIT}"));
    if dir.join("bpf-gen.c").is_file() {
        return dir;
    }

    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));

    // A depth-1 fetch of one commit id: no history, no other branches, and
    // nothing to resolve — the name being fetched is the answer.
    git(&dir, &["init", "--quiet"]);
    git(&dir, &["remote", "add", "origin", TINYCC_REPO]);
    git(
        &dir,
        &["fetch", "--quiet", "--depth", "1", "origin", TINYCC_COMMIT],
    );
    git(&dir, &["checkout", "--quiet", "FETCH_HEAD"]);
    dir
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(dir)
        .args(args)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "failed to run `git {}` in {}: {e}\n\
                 building synch-cc needs git and network access to {TINYCC_REPO}, or a checkout \
                 of {TINYCC_COMMIT} named by SYNCH_TINYCC_DIR",
                args.join(" "),
                dir.display()
            )
        });
    if !status.success() {
        panic!(
            "`git {}` failed in {}\n\
             building synch-cc needs git and network access to {TINYCC_REPO}, or a checkout of \
             {TINYCC_COMMIT} named by SYNCH_TINYCC_DIR",
            args.join(" "),
            dir.display()
        );
    }
}

/// Writes the `config.h` that tinycc's `./configure` would have written.
///
/// Every value the BPF build actually reads. `CONFIG_TCC_PREDEFS` is the one
/// that matters: with it, the predefined macros are compiled into the binary
/// instead of read from a file beside it at run time, which is what makes this
/// a compiler that can be shipped as one executable.
fn write_config_header(out_dir: &Path) {
    let path = out_dir.join("config.h");
    let body = concat!(
        "/* generated by synch-cc's build.rs */\n",
        "#define TCC_VERSION \"0.9.28rc\"\n",
        "#define CC_NAME CC_gcc\n",
        "#define GCC_MAJOR 0\n",
        "#define GCC_MINOR 0\n",
        "#ifndef CONFIG_TCCDIR\n",
        "#define CONFIG_TCCDIR \"\"\n",
        "#endif\n",
        "#define CONFIG_TCC_PREDEFS 1\n",
    );
    fs::write(&path, body).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

/// Embeds tinycc's freestanding headers as string constants.
///
/// `stddef.h`, `stdbool.h`, `stdarg.h` and the rest are part of the compiler
/// rather than of any C library: they define what the language says exists,
/// not what an operating system provides. A guest has no libc and is compiled
/// `-nostdinc`, so without these `size_t` and `bool` would be unavailable in a
/// freestanding program that is entitled to both.
///
/// `tccdefs.h` is excluded: it is the predefined *macros*, already compiled in
/// by [`generate_predefs`], and is not a header anybody includes.
fn embed_freestanding_headers(source_dir: &Path, out_dir: &Path) {
    let include_dir = source_dir.join("include");
    let mut entries: Vec<PathBuf> = fs::read_dir(&include_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", include_dir.display()))
        .map(|entry| entry.expect("cannot read a directory entry").path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "h")
                && path.file_name().is_some_and(|name| name != "tccdefs.h")
        })
        .collect();
    entries.sort();

    let mut generated = String::from(
        "// Generated by build.rs from the pinned tinycc's include/ directory.\n\
         pub(crate) const FREESTANDING_HEADERS: &[(&str, &str)] = &[\n",
    );
    for path in entries {
        let name = path
            .file_name()
            .expect("a file has a name")
            .to_string_lossy();
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        // A raw string with enough hashes that nothing in C can close it.
        generated.push_str(&format!("    ({name:?}, r####\"{body}\"####),\n"));
    }
    generated.push_str("];\n");

    let path = out_dir.join("freestanding_headers.rs");
    fs::write(&path, generated).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

/// Runs tinycc's `c2str` over `include/tccdefs.h` to produce `tccdefs_.h`.
///
/// Built and run with the *host* compiler: it is a build-time tool, and on a
/// cross build the `cc` crate's target compiler would produce something this
/// machine cannot execute.
fn generate_predefs(source_dir: &Path, out_dir: &Path) {
    let host = env::var("HOST").expect("HOST is set by cargo");
    let compiler = cc::Build::new().host(&host).target(&host).get_compiler();
    let tool = out_dir.join("c2str");

    let mut command = compiler.to_command();
    let status = command
        .arg("-DC2STR")
        .arg(source_dir.join("conftest.c"))
        .arg("-o")
        .arg(&tool)
        .status()
        .unwrap_or_else(|e| panic!("failed to build tinycc's c2str: {e}"));
    assert!(status.success(), "failed to build tinycc's c2str");

    let status = Command::new(&tool)
        .arg(source_dir.join("include/tccdefs.h"))
        .arg(out_dir.join("tccdefs_.h"))
        .status()
        .unwrap_or_else(|e| panic!("failed to run tinycc's c2str: {e}"));
    assert!(status.success(), "failed to generate tccdefs_.h");
}
