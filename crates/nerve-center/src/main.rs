//! `nerve-center`: started by a harness from its MCP configuration. Logs go to
//! stderr only, since stdout carries MCP.

use clap::Parser;

fn main() -> std::process::ExitCode {
    let args = nerve_center::config::Args::parse();
    let level: tracing::Level = args.log.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_max_level(level)
        .init();
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
            eprintln!("nerve-center: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
