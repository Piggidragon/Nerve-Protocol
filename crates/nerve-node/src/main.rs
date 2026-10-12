//! `nerve-node`: the node daemon and its command line.

use clap::Parser;

fn main() {
    // The exec shim is this same binary, started by the daemon for each
    // confined command. It is not a command the owner types, so it is checked
    // before clap (and stays out of `--help`).
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(nerve_sandbox::SHIM_ARG))
    {
        std::process::exit(nerve_sandbox::shim_main());
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();
    let cli = nerve_node::cli::Cli::parse();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("nerve-node: cannot start the runtime: {e}");
            std::process::exit(1);
        }
    };
    let mut out = std::io::stdout();
    if let Err(e) = rt.block_on(nerve_node::cli::execute(cli, &mut out)) {
        eprintln!("nerve-node: {e}");
        std::process::exit(1);
    }
}
