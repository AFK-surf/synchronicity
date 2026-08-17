//! Generates the control service from `proto/control.proto` (§9.3).
//!
//! `protox` parses the schema in-process, so the build needs no `protoc` on the
//! machine and behaves the same on every platform CI covers.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/control.proto");
    let descriptors = protox::compile(["proto/control.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(descriptors)?;
    Ok(())
}
