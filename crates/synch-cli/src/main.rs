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
    let args = Cli::parse();
    let default = if args.verbose { "debug" } else { "warn" };
    synch_net::process::init(default);

    if let Err(e) = commands::run(args).await {
        if synch_net::process::reader_hung_up(e.as_ref()) {
            std::process::exit(0);
        }
        eprintln!("synch: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}
