use std::{env, path::PathBuf, process::Command};

fn output(command: &mut Command) -> String {
    let out = command.output().unwrap_or_else(|e| {
        panic!("could not run {command:?}: {e}; install the pinned Lean toolchain via elan")
    });
    assert!(
        out.status.success(),
        "{command:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("tool output is UTF-8")
        .trim()
        .to_owned()
}

fn main() {
    println!("cargo:rerun-if-changed=lean/VerifiedCore.lean");
    println!("cargo:rerun-if-changed=lean/lean-toolchain");
    println!("cargo:rerun-if-changed=src/adapter.c");
    if env::var_os("CARGO_FEATURE_NATIVE").is_none() {
        return;
    }
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    assert_eq!(target, host, "the Lean native backend requires a target-native build; never link host Lean archives into a cross-target binary");
    assert!(target.ends_with("-linux-gnu"), "this first Lean native backend supports native Linux GNU builds only; other release targets require validated Lean runtime packaging");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let lean_dir = root.join("lean");
    let lean = |args: &[&str]| {
        let mut cmd = Command::new("lean");
        cmd.current_dir(&lean_dir)
            .env_remove("LEAN_PATH")
            .args(args);
        output(&mut cmd)
    };
    let version = lean(&["--version"]);
    assert!(
        version.starts_with("Lean (version 4.30.0,"),
        "expected the pinned Lean 4.30.0 toolchain, got {version}"
    );
    let sysroot = PathBuf::from(lean(&["--print-prefix"]));
    let triple = output(
        Command::new("leanc")
            .current_dir(&lean_dir)
            .arg("-dumpmachine"),
    );
    assert_eq!(
        triple, target,
        "Lean's runtime target must match Cargo's target"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let generated = out.join("VerifiedCore.c");
    lean(&["-c", generated.to_str().unwrap(), "VerifiedCore.lean"]);
    cc::Build::new()
        .include(sysroot.join("include"))
        .file(&generated)
        .file(root.join("src/adapter.c"))
        .flag_if_supported("-Wno-unused-parameter")
        .compile("synch_verified_core");
    println!(
        "cargo:rustc-link-search=native={}",
        sysroot.join("lib/lean").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        sysroot.join("lib").display()
    );
    for lib in ["Init", "leanrt", "c++", "c++abi", "gmp", "uv"] {
        println!("cargo:rustc-link-lib=static={lib}");
    }
    for lib in ["m", "pthread", "dl"] {
        println!("cargo:rustc-link-lib={lib}");
    }
}
