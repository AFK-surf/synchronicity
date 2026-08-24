//! `synch` — the synchronicity daemon and the CLI that drives it (§9.1).
//!
//! A thin argument-parsing shell over [`synch_cli`]: parse, dispatch, render
//! the failure as an exit status.

use clap::Parser;
use synch_cli::{cli::Cli, commands};

/// The stack the whole program runs on.
///
/// Not the platform's default, because the platforms disagree about it by a
/// factor of eight and the smallest is not enough. clap's derived parser is one
/// builder chain per subcommand, all of it in a single frame with nothing
/// inlined in a debug build, and `synch`'s command surface has grown to the
/// point where parsing an argument list needs the better part of a megabyte.
/// Linux gives the main thread eight; Windows gives it one, and `synch
/// --version` overflowed it before the program had done anything at all.
///
/// So the size is stated rather than inherited. Sixteen megabytes is reserved
/// address space, committed as it is touched, and the cost of being wrong in
/// this direction is nothing.
const STACK: usize = 16 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    let thread = std::thread::Builder::new()
        .name("synch".into())
        .stack_size(STACK)
        .spawn(run)
        .expect("the main thread starts");
    match thread.join() {
        Ok(result) => result,
        // The thread panicked and has already printed why.
        Err(_) => std::process::exit(101),
    }
}

fn run() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(main_thread())
}

async fn main_thread() -> anyhow::Result<()> {
    // Before anything builds a TLS client: reqwest, built without a baked-in
    // provider, refuses to construct a `Client` until one is installed.
    synch_net::tls::install_crypto_provider();
    let args = Cli::parse();
    let default = if args.verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SYNCH_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default)),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = commands::run(args).await {
        // Rust starts processes with SIGPIPE ignored, so a reader that hung
        // up early (`synch ls | head`) surfaces as a broken-pipe write error.
        // That is the reader saying "enough", not a failure to report.
        let reader_hung_up = e.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
        });
        if reader_hung_up {
            std::process::exit(0);
        }
        eprintln!("synch: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}
