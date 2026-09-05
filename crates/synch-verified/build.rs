use std::{env, path::PathBuf, process::Command};

fn output(command: &mut Command) -> String {
    let out = command.output().unwrap_or_else(|e| {
        panic!("could not run {command:?}: {e}; install the pinned Lean toolchain via elan")
    });
    assert!(
        out.status.success(),
        "{command:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("tool output is UTF-8")
        .trim()
        .to_owned()
}

fn main() {
    println!("cargo:rerun-if-changed=lean/VerifiedCore.lean");
    let modules = [
        "Host",
        "Cas",
        "Cas/Program",
        "Host/Wire",
        "Entry",
        "Trie/Codec",
        "Trie/Program",
        "Replication/History",
    ];
    for module in modules {
        println!("cargo:rerun-if-changed=lean/VerifiedCore/{module}.lean");
    }
    println!("cargo:rerun-if-changed=lean/lean-toolchain");
    println!("cargo:rerun-if-changed=src/adapter.c");
    let target = env::var("TARGET").unwrap();
    let linux = target.ends_with("-linux-gnu");
    let macos = target.ends_with("-apple-darwin");
    let windows = target == "x86_64-pc-windows-gnullvm";
    assert!(
        target.starts_with("x86_64-") || target.starts_with("aarch64-"),
        "the Lean core supports x86-64 and arm64 only"
    );
    assert!(linux || macos || windows, "supported targets are Linux GNU, macOS, and Windows GNU/LLVM; OpenBSD, Linux musl, and Windows MSVC are not supported");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let lean_dir = root.join("lean");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    std::fs::create_dir_all(out.join("VerifiedCore")).unwrap();
    let lean = |args: &[&str]| {
        let mut cmd = Command::new("lean");
        // Cargo's job count does not limit Lean's own worker pool. Native
        // modules are small and compiled serially; bound each compiler's
        // threads and memory instead of multiplying host-core-sized pools.
        cmd.current_dir(&lean_dir)
            .env("LEAN_PATH", &out)
            .args(["-j1", "-M4096"])
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
    let arch = if target.starts_with("aarch64-") {
        "aarch64"
    } else {
        "x86_64"
    };
    let runtime_arch = if triple.starts_with("arm64-") {
        "aarch64"
    } else {
        triple.split('-').next().unwrap()
    };
    assert_eq!(
        runtime_arch, arch,
        "Lean's runtime architecture must match Cargo's target; use a native runner"
    );
    assert!(
        (linux && triple.ends_with("-linux-gnu"))
            || (macos && triple.contains("-apple-darwin"))
            || (windows && triple.ends_with("-windows-gnu")),
        "Lean runtime {triple} is incompatible with Cargo target {target}"
    );
    // Dependency order above is shared by the native compiler and proof imports.
    // Domain modules remain separate; the ABI adapter does not implement policy.
    let mut compiled_modules = Vec::new();
    for module in modules {
        let object = out.join(format!("VerifiedCore/{module}.olean"));
        std::fs::create_dir_all(object.parent().unwrap()).unwrap();
        let generated = out.join(format!("{}.c", module.replace('/', "_")));
        lean(&[
            "-c",
            generated.to_str().unwrap(),
            "-o",
            object.to_str().unwrap(),
            &format!("VerifiedCore/{module}.lean"),
        ]);
        compiled_modules.push(generated);
    }
    let generated = out.join("VerifiedCore.c");
    lean(&["-c", generated.to_str().unwrap(), "VerifiedCore.lean"]);
    cc::Build::new()
        .include(sysroot.join("include"))
        .file(&generated)
        .files(&compiled_modules)
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
    for lib in ["Std", "Init", "leanrt", "gmp", "uv"] {
        println!("cargo:rustc-link-lib=static={lib}");
    }
    if macos {
        // Apple's libc++ is a system library, not a bundled static archive.
        println!("cargo:rustc-link-lib=c++");
    } else {
        for lib in ["c++", "c++abi"] {
            println!("cargo:rustc-link-lib=static={lib}");
        }
    }
    if windows {
        for lib in ["unwind", "pthread"] {
            println!("cargo:rustc-link-lib=static={lib}");
        }
        for lib in [
            "bcrypt", "ws2_32", "userenv", "iphlpapi", "psapi", "dbghelp", "ole32", "icu",
        ] {
            println!("cargo:rustc-link-lib={lib}");
        }
    } else {
        for lib in ["m", "pthread"] {
            println!("cargo:rustc-link-lib={lib}");
        }
        if linux {
            println!("cargo:rustc-link-lib=dl");
        }
    }
}
