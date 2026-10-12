//! `nerve-center`: started by a harness from its MCP configuration. Logs go to
//! stderr and to the log file in the state folder, never to stdout, which
//! carries MCP.

use clap::Parser;

fn main() -> std::process::ExitCode {
    let args = nerve_center::config::Args::parse();
    // The level of the settings replaces this one once the state is opened.
    nerve_transport::log::install(args.log.unwrap_or_default(), true);
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("nerve-center: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match rt.block_on(nerve_center::server::run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
