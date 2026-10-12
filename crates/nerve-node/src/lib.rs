//! The Nerve node: links this machine to its centers and serves them what the
//! owner's policy allows (docs/dev/).
//!
//! The daemon ([`daemon::Daemon`]) keeps one link per paired center, runs the
//! `fs`, `exec`, `settings` and `audit` capabilities, and serves
//! the control socket the CLI ([`cli`]) talks to. Tests start a daemon in
//! process with [`daemon::Daemon::start`] and pair with [`pair::pair`].

pub mod cli;
pub mod daemon;
pub mod descriptor;
pub mod exec;
pub mod fs;
// The job is Windows-only in use; its choices are tested everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
mod job;
mod link;
pub mod pair;
pub mod paths;
mod secrets;
mod sudo;
// The walk is Windows-only in use, tested everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
mod tree;
#[cfg(windows)]
mod win;

pub use daemon::{Daemon, NodeOptions};
pub use paths::NodePaths;

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    nerve_proto::msg::now_ms()
}
