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
    // So is the keyring probe that setup and install start
    // (docs/user/config.md): it answers whether the system keyring of the
    // user it runs as works.
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(nerve_node::keyring_setup::PROBE_ARG))
    {
        std::process::exit(nerve_node::keyring_setup::probe_main());
    }
    // Events go to stderr. The daemon adds the log file in the state folder and
    // takes its level from `node.toml`.
    nerve_transport::log::install(nerve_transport::log::Level::Info, true);
    let cli = nerve_node::cli::Cli::parse();
    // Before the runtime starts threads: root's command on the installed
    // node runs as the node's user.
    if let Err(e) = nerve_node::cli::settle_user(&cli) {
        eprintln!("nerve-node: {e}");
        std::process::exit(1);
    }
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
